"""
Centralized DNS resolver with DNS-over-HTTPS (DoH) fallback.

Strategy: UDP first (fast), DoH fallback when UDP port 53 is blocked.
This allows the application to work on VPS providers that block outgoing UDP 53.
"""
import logging
import dns.asyncresolver
import dns.asyncquery
import dns.resolver
import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rcode
import dns.name

logger = logging.getLogger(__name__)

# Traditional UDP DNS servers (tried first — fast path)
UDP_DNS_SERVERS = [
    ['8.8.8.8', '8.8.4.4'],      # Google DNS
    ['1.1.1.1', '1.0.0.1'],      # Cloudflare DNS
]

# DoH endpoints (fallback when UDP 53 is blocked)
DOH_URLS = [
    'https://cloudflare-dns.com/dns-query',
    'https://dns.google/dns-query',
]

# Blacklist-specific DNS servers (Spamhaus needs special resolvers)
BLACKLIST_UDP_DNS_SERVERS = [
    ['9.9.9.9', '149.112.112.112'],      # Quad9 (works reliably with Spamhaus)
    ['193.2.1.39', '35.154.147.207'],     # Spamhaus authoritative DNS
    ['1.1.1.1', '1.0.0.1'],              # Cloudflare (fallback)
    ['8.8.8.8', '8.8.4.4'],              # Google DNS (last resort)
]

# Blacklist-specific DoH endpoints (Spamhaus blocks Google/Cloudflare DoH too)
BLACKLIST_DOH_URLS = [
    'https://dns.quad9.net/dns-query',    # Quad9 DoH (works with Spamhaus)
]


async def resolve(query: str, rdtype: str = 'A', timeout: int = 5):
    """
    Resolve a DNS query with UDP-first, DoH-fallback strategy.
    
    Args:
        query: DNS query string (domain name)
        rdtype: DNS record type ('A', 'TXT', 'MX', etc.)
        timeout: Timeout in seconds per attempt
        
    Returns:
        DNS answer object
        
    Raises:
        dns.resolver.NXDOMAIN: Domain does not exist
        dns.resolver.NoAnswer: No records of this type
        Exception: All resolvers failed
    """
    return await _resolve_with_fallback(query, rdtype, timeout, UDP_DNS_SERVERS, DOH_URLS)


async def resolve_for_blacklist(query: str, rdtype: str = 'A', timeout: int = 10):
    """
    Resolve a DNS query for blacklist checks.
    Uses blacklist-specific DNS servers (Quad9, Spamhaus authoritative)
    with Quad9 DoH as final fallback (Spamhaus blocks Google/Cloudflare).
    
    Args:
        query: DNS query string (reversed IP + blacklist zone)
        rdtype: DNS record type (usually 'A')
        timeout: Timeout in seconds per attempt
        
    Returns:
        DNS answer object
        
    Raises:
        dns.resolver.NXDOMAIN: IP not listed (valid response)
        dns.resolver.NoAnswer: IP not listed (valid response)
        Exception: All resolvers failed
    """
    return await _resolve_with_fallback(query, rdtype, timeout, BLACKLIST_UDP_DNS_SERVERS, BLACKLIST_DOH_URLS)


async def _resolve_with_fallback(query: str, rdtype: str, timeout: int, udp_servers: list, doh_urls: list):
    """
    Internal: Try UDP resolvers first, fall back to DoH if all UDP attempts fail.
    
    NXDOMAIN and NoAnswer are valid DNS responses and are re-raised immediately.
    Only transport-level failures (timeout, no nameservers) trigger fallback.
    """
    last_error = None
    
    # Phase 1: Try traditional UDP DNS servers
    for dns_servers in udp_servers:
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.nameservers = dns_servers
            resolver.timeout = timeout
            resolver.lifetime = timeout
            
            return await resolver.resolve(query, rdtype)
            
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            # Valid DNS responses — re-raise immediately, no fallback needed
            raise
        except (dns.resolver.NoNameservers, dns.exception.Timeout) as e:
            last_error = str(e)
            logger.debug(f"DNS UDP failed ({dns_servers[0]}) for {query}: {e}")
            continue
        except Exception as e:
            last_error = str(e)
            logger.debug(f"DNS UDP error ({dns_servers[0]}) for {query}: {e}")
            continue
    
    # Phase 2: All UDP servers failed — try DoH (port 443)
    logger.info(f"All UDP DNS servers failed for {query}, trying DoH fallback...")
    
    for doh_url in doh_urls:
        try:
            q = dns.message.make_query(dns.name.from_text(query), rdtype)
            
            response = await dns.asyncquery.https(q, doh_url, timeout=timeout)
            
            # Check for NXDOMAIN in DoH response
            if response.rcode() == dns.rcode.NXDOMAIN:
                raise dns.resolver.NXDOMAIN()
            
            # Check for no answer
            answer_section = response.answer
            if not answer_section:
                raise dns.resolver.NoAnswer()
            
            logger.info(f"DoH fallback succeeded ({doh_url}) for {query}")
            return dns.resolver.Answer(
                qname=dns.name.from_text(query),
                rdtype=dns.rdatatype.from_text(rdtype),
                rdclass=dns.rdataclass.IN,
                response=response,
            )
            
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            raise
        except Exception as e:
            last_error = str(e)
            logger.debug(f"DoH failed ({doh_url}) for {query}: {e}")
            continue
    
    # All methods exhausted
    error_msg = f"All DNS resolvers failed for {query} (UDP + DoH)"
    if last_error:
        error_msg += f" - last error: {last_error}"
    logger.warning(error_msg)
    raise Exception(error_msg)

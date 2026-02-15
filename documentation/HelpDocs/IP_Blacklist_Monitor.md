# IP Blacklist Monitor - User Guide

## Overview
The IP Blacklist Monitor helps you check if your server's IP address is listed on common DNS-based Blackhole Lists (DNSBL). Being blacklisted can severely impact your email deliverability.

## Why is this important?
If your IP is blacklisted, emails sent from your server may be rejected or marked as spam by receiving servers. Regular monitoring ensures you can take quick action to request delisting.

## Features

### 🔄 Automated Background Monitoring
- **Daily Auto-Check**: The system automatically checks your server IP against all supported blacklists every day at **5:00 AM**.
- **Startup Check**: A quick check is also performed shortly after the application starts.
- **Results Caching**: Results are stored for 24 hours to minimize unnecessary DNS traffic.

### 📧 Email Notifications
If your server is found on a blacklist during an automated check, the system will send an alert to the configured admin email (`BLACKLIST_ALERT_EMAIL` or `ADMIN_EMAIL`).
- **Detailed Report**: The email includes exactly which lists have flagged your IP.
- **Direct Links**: Quick links to the removal pages of the respective blacklists.

> [!NOTE] 
> **Notification Policy:** To prevent alert fatigue, some aggressive or paid-removal-only lists (specifically **UCEPROTECT Level 2** and **Level 3**) will **NOT** trigger an email notification if they are the only ones listing your IP. These lists often block entire subnets or ASNs and are typically not actionable by individual server admins.

### Real-time Manual Check
- You can manually trigger a fresh check at any time by clicking the **"Check Now"** button on the Status page.
- Status indicators:
  - **Green**: Not listed (Clean)
  - **Red**: Listed (Blacklisted)
  - **Gray**: Check failed or timeout

### Supported Blacklists
The monitor checks against ~50 reputable lists including:
- Spamhaus (ZEN/SBL/XBL/PBL)
- Barracuda (b.barracudacentral.org)
- SpamCop (bl.spamcop.net)
- SORBS (various lists)
- And many others...

## Troubleshooting

### What if I am blacklisted?
1. **Identify the List**: Use the Expand details view to see which specific list has flagged your IP.
2. **Visit the List's Website**: Click the provided link to visit their lookup/removal page.
3. **Check the Reason**: They often provide a reason (e.g., spam trap hits, compromised account, high volume).
4. **Request Delisting**: Follow their specific procedure to request removal.
5. **Fix the Root Cause**: Ensure your server is not sending spam, is fully secured, and is not an open relay.

### Common False Positives
- **Dynamic IPs**: Many lists block residential/dynamic IP ranges. Ensure your server has a static IP and proper reverse DNS (rDNS).
- **"Bad Neighborhood"**: Sometimes entire IP blocks are listed because of other bad actors in the same range (common with some VPS providers).

## Best Practices
- **Monitor Regularily**: Let the background job do the work, but check the dashboard occasionally.
- **Maintain Reputation**: Ensure strict SPF, DKIM, and DMARC policies are enforced.
- **Secure Your Server**: Prevent your server from being used as a requested relay by spammers.

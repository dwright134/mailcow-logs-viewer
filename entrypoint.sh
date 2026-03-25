#!/bin/bash
set -e

if [ "$(id -u)" = "0" ]; then
    # Running as root — fix host bind-mount permissions and drop to appuser
    mkdir -p /app/data
    # Ensure container.log exists so chown covers it too
    touch /app/data/container.log
    chown -R 1000:1000 /app/data
    exec gosu appuser uvicorn app.main:app --host 0.0.0.0 --port 8080 --workers 1
else
    # Already running as non-root — just start the app
    exec uvicorn app.main:app --host 0.0.0.0 --port 8080 --workers 1
fi

#!/bin/sh

# Start fail2ban
fail2ban-client -x start

# Run x1-ui
exec /app/x1-ui

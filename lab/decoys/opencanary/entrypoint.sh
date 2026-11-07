#!/bin/sh
set -e
# Clean up any stale pid files from previous unclean shutdowns
rm -f /run/*.pid /run/opencanaryd.pid /var/run/*.pid /tmp/*.pid /twistd.pid ./twistd.pid 2>/dev/null || true
exec opencanaryd --dev


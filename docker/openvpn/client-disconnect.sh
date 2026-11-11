#!/bin/sh
# Accounting failure must not prevent OpenVPN from completing a disconnect.
/usr/local/bin/vpn-stats disconnect || true

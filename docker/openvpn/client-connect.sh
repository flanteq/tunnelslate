#!/bin/sh
/usr/local/bin/vpn-auth connect || exit 1
/usr/local/bin/vpn-network connect "$@" || exit 1
/usr/local/bin/vpn-stats connect || true

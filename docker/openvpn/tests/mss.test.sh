#!/bin/sh
# Run only in an isolated test container with NET_ADMIN.
set -eu
iptables -t mangle -N UNRELATED
iptables -t mangle -A OUTPUT -j UNRELATED
configure-vpn-mss 1320
configure-vpn-mss 1320
[ "$(iptables -t mangle -S PREROUTING | grep -c -- '-j DESK_MSS_IN')" = 1 ]
[ "$(iptables -t mangle -S POSTROUTING | grep -c -- '-j DESK_MSS_OUT')" = 1 ]
iptables -t mangle -S DESK_MSS_IN | grep -q -- '--set-mss 1320'
configure-vpn-mss 1280
iptables -t mangle -S DESK_MSS_OUT | grep -q -- '--set-mss 1280'
for value in 0x500 01 535 1461 '1320;id'; do
  if configure-vpn-mss "$value" >/dev/null 2>&1; then exit 1; fi
  iptables -t mangle -S DESK_MSS_IN | grep -q -- '--set-mss 1280'
done
configure-vpn-mss 0
configure-vpn-mss 0
! iptables -t mangle -S | grep -q 'DESK_MSS_'
iptables -t mangle -S OUTPUT | grep -q -- '-j UNRELATED'
echo 'Kernel MSS rules: apply, replace, validation, cleanup and unrelated rules: PASS'

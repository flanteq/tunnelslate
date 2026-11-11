#!/bin/sh
# Numeric TCP MSS clamping runs in the container's network namespace. Unlike
# OpenVPN's userspace mssfix, these hooks also see DCO and server-local traffic.
set -eu
[ "$#" = 1 ] || { echo 'Usage: configure-vpn-mss MSS (0 to clear)' >&2; exit 1; }
mss=$1
case "$mss" in 0) ;; ''|*[!0-9]*|0*) exit 1;; *) [ "${#mss}" -le 4 ] && [ "$mss" -ge 536 ] && [ "$mss" -le 1460 ] || exit 1;; esac

for hook in PREROUTING POSTROUTING; do
  case "$hook" in PREROUTING) direction=-i; chain=DESK_MSS_IN;; POSTROUTING) direction=-o; chain=DESK_MSS_OUT;; esac
  # Remove hooks before flushing: a failed update must not leave a stale limit.
  while iptables -t mangle -C "$hook" "$direction" tun+ -p tcp --tcp-flags SYN,RST SYN -j "$chain" 2>/dev/null; do
    iptables -t mangle -D "$hook" "$direction" tun+ -p tcp --tcp-flags SYN,RST SYN -j "$chain"
  done
  if iptables -t mangle -S "$chain" >/dev/null 2>&1; then
    iptables -t mangle -F "$chain"
    iptables -t mangle -X "$chain"
  fi
  if [ "$mss" != 0 ]; then
    iptables -t mangle -N "$chain"
    iptables -t mangle -A "$chain" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$mss"
    iptables -t mangle -A "$hook" "$direction" tun+ -p tcp --tcp-flags SYN,RST SYN -j "$chain"
  fi
done

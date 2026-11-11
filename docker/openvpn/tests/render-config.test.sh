#!/bin/sh
set -eu
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
base=$work/base.conf
out=$work/runtime.conf
cat > "$base" <<'EOF'
# Existing user config from the initial scaffold.
server 10.8.0.0 255.255.255.0
port 1194
proto udp
topology net30
dev ovpn-custom
client-to-client
script-security 3
verify-client-cert none
username-as-common-name
auth-user-pass-verify /old/auth via-env
auth-gen-token 86400
management-client-auth
tmp-dir /persistent-passwords
reneg-sec 0
hand-window 30
learn-address /old/script
client-disconnect /old/disconnect
status /old/status.log 120
status-version 2
ifconfig-pool 10.8.0.2 10.8.0.253
client-config-dir /old/ccd
explicit-exit-notify 1
push "dhcp-option DNS 192.0.2.1"
push "route 192.168.7.0 255.255.255.0"
keepalive 10 60
max-clients 250
disable-dco
tun-mtu 1300
mssfix 1200
push "dhcp-option DOMAIN old.example.com"
push "dhcp-option DOMAIN-SEARCH old.example.com"
<ca>
server preserve-inline-content
</ca>
EOF
original=$(sha256sum "$base")

export TUNNELSLATE_VPN_NETWORK=172.27.13.42/23
export TUNNELSLATE_VPN_PORT=1294
export TUNNELSLATE_VPN_PROTOCOL=udp
export TUNNELSLATE_VPN_DNS='172.16.0.1, 172.27.12.53'
export TUNNELSLATE_VPN_ROUTES='192.168.7.0/24,172.20.12.42/23'
network=$(render-vpn-config "$base" "$out")
[ "$network" = 172.27.12.0/23 ]
grep -qx 'verify-client-cert require' "$out"
grep -qx 'auth-user-pass-optional' "$out"
grep -qx 'auth-user-pass-verify /usr/local/bin/vpn-auth via-file' "$out"
grep -qx 'tmp-dir /run/openvpn/auth' "$out"
grep -qx 'reneg-sec 3600' "$out"
grep -qx 'hand-window 330' "$out"
grep -qx 'status /run/openvpn/status.log 5' "$out"
grep -qx 'status-version 3' "$out"
grep -qx 'client-disconnect /usr/local/bin/desk-client-disconnect' "$out"
[ "$(grep -c '^status ' "$out")" = 1 ]
[ "$(grep -c '^status-version ' "$out")" = 1 ]
[ "$(grep -c '^client-disconnect ' "$out")" = 1 ]
[ "$(grep -c '^hand-window ' "$out")" = 1 ]
! grep -Eq '^(verify-client-cert none|username-as-common-name|auth-gen-token|management-client-auth)' "$out"

grep -qx 'server 172.27.12.0 255.255.254.0 nopool' "$out"
grep -qx 'ifconfig-pool 172.27.12.2 172.27.12.255 255.255.254.0' "$out"
grep -qx 'topology subnet' "$out"
grep -qx 'dev tun0' "$out"
! grep -q 'ovpn-custom\|client-to-client\|/old/script\|script-security 3' "$out"
grep -qx 'client-config-dir /etc/openvpn/ccd' "$out"
! grep -q 'topology net30\|/old/ccd\|10.8.0.253' "$out"
grep -qx 'port 1294' "$out"
grep -qx 'proto udp' "$out"
grep -qx 'explicit-exit-notify 1' "$out"
grep -qx 'push "dhcp-option DNS 172.16.0.1"' "$out"
grep -qx 'push "dhcp-option DNS 172.27.12.53"' "$out"
grep -qx 'push "route 172.16.0.1 255.255.255.255"' "$out"
! grep -q 'route 172.27.12.53' "$out"
! grep -q '192.0.2.1\|server 10.8.0.0\|port 1194' "$out"
grep -qx 'push "route 192.168.7.0 255.255.255.0"' "$out"
grep -qx 'push "route 172.20.12.0 255.255.254.0"' "$out"
grep -qx 'server preserve-inline-content' "$out"
[ "$original" = "$(sha256sum "$base")" ]
grep -qx 'max-clients 1024' "$out"
grep -qx 'keepalive 10 60' "$out"
! grep -q '^disable-dco' "$out"

TUNNELSLATE_VPN_DCO=off TUNNELSLATE_VPN_MAX_CLIENTS=25 TUNNELSLATE_VPN_KEEPALIVE_INTERVAL=15 TUNNELSLATE_VPN_KEEPALIVE_TIMEOUT=90 render-vpn-config "$base" "$out" > /dev/null
grep -qx 'disable-dco' "$out"
grep -qx 'max-clients 25' "$out"
grep -qx 'keepalive 15 90' "$out"
[ "$(grep -c '^keepalive ' "$out")" = 1 ]
[ "$(grep -c '^max-clients ' "$out")" = 1 ]

TUNNELSLATE_VPN_DNS_DOMAIN=office.example.com TUNNELSLATE_VPN_DNS_SEARCH=dev.example.com,office.example.com TUNNELSLATE_VPN_TUN_MTU=1400 TUNNELSLATE_VPN_MSS_MODE=custom TUNNELSLATE_VPN_MSS=1320 render-vpn-config "$base" "$out" > /dev/null
grep -qx 'tun-mtu 1400' "$out"
grep -qx 'mssfix 0' "$out"
grep -qx 'push "dhcp-option DOMAIN office.example.com"' "$out"
grep -qx 'push "dhcp-option DOMAIN-SEARCH dev.example.com"' "$out"
[ "$(grep -c '^tun-mtu ' "$out")" = 1 ]
[ "$(grep -c '^mssfix ' "$out")" = 1 ]
! grep -q 'old.example.com' "$out"
TUNNELSLATE_VPN_MSS_MODE=off render-vpn-config "$base" "$out" > /dev/null
grep -qx 'mssfix 0' "$out"
TUNNELSLATE_VPN_PROTOCOL=tcp TUNNELSLATE_VPN_MSS_MODE=custom TUNNELSLATE_VPN_MSS=1320 render-vpn-config "$base" "$out" > /dev/null
! grep -q '^mssfix' "$out"
TUNNELSLATE_VPN_PROTOCOL=tcp render-vpn-config "$base" "$out" > /dev/null
grep -qx 'proto tcp-server' "$out"
! grep -q '^explicit-exit-notify' "$out"
TUNNELSLATE_VPN_REDIRECT_GATEWAY=true render-vpn-config "$base" "$out" > /dev/null
grep -qx 'push "redirect-gateway def1 bypass-dhcp"' "$out"

TUNNELSLATE_VPN_NETWORK=192.0.2.0/29 render-vpn-config "$base" "$out" > /dev/null
grep -qx 'ifconfig-pool 192.0.2.2 192.0.2.3 255.255.255.248' "$out"
TUNNELSLATE_VPN_NETWORK=128.0.0.0/1 render-vpn-config "$base" "$out" > /dev/null
grep -qx 'ifconfig-pool 128.0.0.2 191.255.255.255 128.0.0.0' "$out"

# Validation must fail before overwriting a previously working config.
last=$(sha256sum "$out")
for network in not-cidr 10.1.0.0/30 10.1.0.0/33 '::/64' '10.1.0.0/24;id'; do
  if TUNNELSLATE_VPN_NETWORK="$network" render-vpn-config "$base" "$out" > /dev/null 2>&1; then
    echo "Invalid network accepted: $network" >&2; exit 1
  fi
  [ "$last" = "$(sha256sum "$out")" ]
done
for mode in enabled 'off;id'; do
  if TUNNELSLATE_VPN_DCO="$mode" render-vpn-config "$base" "$out" > /dev/null 2>&1; then
    echo 'Invalid DCO mode accepted.' >&2; exit 1
  fi
  [ "$last" = "$(sha256sum "$out")" ]
done
for value in 0 -1 65536 01 '25;id' 999999999999999999999; do
  if TUNNELSLATE_VPN_MAX_CLIENTS="$value" render-vpn-config "$base" "$out" > /dev/null 2>&1; then
    echo 'Invalid connection limit accepted.' >&2; exit 1
  fi
  [ "$last" = "$(sha256sum "$out")" ]
done
for value in 0 3601 '10;id'; do
  if TUNNELSLATE_VPN_KEEPALIVE_INTERVAL="$value" render-vpn-config "$base" "$out" > /dev/null 2>&1; then
    echo 'Invalid keepalive interval accepted.' >&2; exit 1
  fi
done
for value in 19 86401 '60;id'; do
  if TUNNELSLATE_VPN_KEEPALIVE_TIMEOUT="$value" render-vpn-config "$base" "$out" > /dev/null 2>&1; then
    echo 'Invalid keepalive timeout accepted.' >&2; exit 1
  fi
done
for dns in '172.16.0.999' '1.1.1.1,' '::1' '1.1.1.1;id'; do
  if TUNNELSLATE_VPN_DNS="$dns" render-vpn-config "$base" "$out" > /dev/null 2>&1; then
    echo "Invalid DNS accepted: $dns" >&2; exit 1
  fi
  [ "$last" = "$(sha256sum "$out")" ]
done
for port in 0 65536 '1194;id'; do
  if TUNNELSLATE_VPN_PORT="$port" render-vpn-config "$base" "$out" > /dev/null 2>&1; then
    echo "Invalid port accepted: $port" >&2; exit 1
  fi
done
for routes in '192.168.1.0/33' '192.168.1.0/24,' '192.168.1.0/24;id'; do
  if TUNNELSLATE_VPN_ROUTES="$routes" render-vpn-config "$base" "$out" > /dev/null 2>&1; then
    echo "Invalid route accepted: $routes" >&2; exit 1
  fi
done
for value in ',example.com' 'example.com,' bad..example -bad.example 'a.example;id' 'a.example"' 'a.example
b.example' 'a.example
script-security 2'; do
  if TUNNELSLATE_VPN_DNS_DOMAIN="$value" render-vpn-config "$base" "$out" > /dev/null 2>&1; then exit 1; fi
  if TUNNELSLATE_VPN_DNS_SEARCH="$value" render-vpn-config "$base" "$out" > /dev/null 2>&1; then exit 1; fi
  [ "$last" = "$(sha256sum "$out")" ]
done
for value in 575 1501 01400 '1400;id'; do
  if TUNNELSLATE_VPN_TUN_MTU="$value" render-vpn-config "$base" "$out" > /dev/null 2>&1; then exit 1; fi
  [ "$last" = "$(sha256sum "$out")" ]
done
for value in 0 535 1361 '1320;id'; do
  if TUNNELSLATE_VPN_TUN_MTU=1400 TUNNELSLATE_VPN_MSS_MODE=custom TUNNELSLATE_VPN_MSS="$value" render-vpn-config "$base" "$out" > /dev/null 2>&1; then exit 1; fi
  [ "$last" = "$(sha256sum "$out")" ]
done
echo 'VPN config tests passed: networks, DNS/domains/routes, MTU/MSS, DCO, limits, keepalive, legacy settings and injection rejection.'

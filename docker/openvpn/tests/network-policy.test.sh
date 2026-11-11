#!/bin/sh
# Requires an isolated container with NET_ADMIN. Never use the host network.
set -eu
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cat > "$work/policy.json" <<'JSON'
{"revision":1,"network":"10.8.0.0/24","isolate_clients":true,"site_to_site":true,"site_nat":true,"devices":[{"id":"router","name":"router","client_name":"site","cns":["desk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],"static_ip":"10.8.0.128","site_networks":["192.168.80.0/24"],"access_mode":"restricted","allowed_networks":["192.168.81.0/24"],"dns":["192.0.2.53"]}]}
JSON
iptables -N UNRELATED_FILTER
iptables -A OUTPUT -j UNRELATED_FILTER
vpn-network apply "$work/policy.json" 1 eth0 > "$work/routes"
vpn-network apply "$work/policy.json" 1 eth0 > /dev/null
! grep -q '^route ' "$work/routes"
grep -qx 'client-connect /usr/local/bin/desk-client-connect' "$work/routes"
[ "$(iptables -S FORWARD | grep -c -- '-j DESK_NET_FWD')" = 1 ]
iptables -S DESK_NET_FWD | grep -q -- '-i tun+ -o tun+ -j DROP'
iptables -S DESK_NET_S0 | grep -q -- '-j DROP'
iptables -S DESK_NET_D0 | grep -q -- '-s 192.168.81.0/24 -j RETURN'
iptables -t nat -S DESK_NET_NAT | grep -q -- '-s 192.168.80.0/24 -o eth0 -j MASQUERADE'
iptables-save | sed '/^#/d' > "$work/before"
if vpn-network apply "$work/policy.json" 2 eth0 > /dev/null 2>&1; then exit 1; fi
if vpn-network apply "$work/policy.json" 1 'eth0;id' > /dev/null 2>&1; then exit 1; fi
iptables-save | sed '/^#/d' > "$work/after"
cmp "$work/before" "$work/after"
printf '%s\n' '{"revision":1,"network":"10.8.0.0/24","devices":[]}' > "$work/policy.json"
vpn-network apply "$work/policy.json" 1 eth0 > /dev/null
! iptables -S DESK_NET_FWD | grep -q -- '-j DROP'
! iptables -S DESK_NET_FROM | grep -q -- '^-A '
! iptables -t nat -S DESK_NET_NAT | grep -q MASQUERADE
iptables -S OUTPUT | grep -q -- '-j UNRELATED_FILTER'
echo 'Network policy: routes, isolation, bidirectional ACL, NAT, idempotency, revision and injection rejection, disabled cleanup: PASS'
# Route reconciliation owns only the desk protocol/metric on tun0. OpenVPN/DCO
# peer routes and unrelated routes must survive, including /32 JSON rendering.
ip link add tun0 type dummy
ip link set tun0 up
mkdir -p /run/openvpn
cat > /run/openvpn/network.json <<'JSON'
{"revision":1,"network":"10.8.0.0/24","site_to_site":true,"devices":[{"id":"router","static_ip":"10.8.0.128","site_networks":["192.168.80.0/24","198.51.100.4/32"]}]}
JSON
ip route add 203.0.113.0/24 dev lo proto 186 metric 1
ip route add 192.168.80.0/24 via 10.8.0.128 dev tun0 onlink metric 200
vpn-network routes
vpn-network routes
ip route show proto 186 | grep -q '198.51.100.4 dev tun0.*42760'
printf '%s\n' '{"revision":1,"network":"10.8.0.0/24","devices":[]}' > /run/openvpn/network.json
vpn-network routes
! ip route show proto 186 | grep -q 'dev tun0'
ip route show proto 186 | grep -q '203.0.113.0/24 dev lo'
ip route show | grep -q '192.168.80.0/24 via 10.8.0.128.*200'
echo 'Live route reconciliation: idempotency, /32 removal, DCO peer and unrelated route preservation: PASS'

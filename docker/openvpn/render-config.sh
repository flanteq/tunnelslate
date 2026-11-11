#!/bin/sh
set -eu
set -f
umask 077

if [ "$#" -ne 2 ]; then
  echo 'Usage: render-vpn-config BASE_CONFIG OUTPUT_CONFIG' >&2
  exit 1
fi
base=$1
output=$2
invalid() { echo "$1" >&2; exit 1; }

network=${TUNNELSLATE_VPN_NETWORK:-10.8.0.0/24}
prefix=${network##*/}
case "$network" in *[!0-9./]*|'') invalid 'VPN_NETWORK must be an IPv4 CIDR prefix.';; esac
case "$prefix" in ''|*[!0-9]*|0[0-9]*) invalid 'VPN_NETWORK must have an IPv4 prefix length from 1 to 29.';; esac
if [ "$network" = "$prefix" ] || [ "$prefix" -lt 1 ] || [ "$prefix" -gt 29 ]; then
  invalid 'VPN_NETWORK must have an IPv4 prefix length from 1 to 29.'
fi
network_info=$(ipcalc -n -m "$network") || invalid 'Invalid VPN_NETWORK.'
address=$(printf '%s\n' "$network_info" | sed -n 's/^NETWORK=//p')
netmask=$(printf '%s\n' "$network_info" | sed -n 's/^NETMASK=//p')
[ -n "$address" ] && [ -n "$netmask" ] || invalid 'Cannot calculate VPN network and netmask.'

# Keep dynamically assigned IPs out of the fixed-address CCD range. The Go CCD
# validator uses the same split: lower half dynamic, upper half static.
pool=$(awk -v address="$address" -v prefix="$prefix" 'BEGIN {
  split(address, a, ".")
  base=a[1]*16777216+a[2]*65536+a[3]*256+a[4]
  end=base+2^(32-prefix)/2-1
  start=base+2
  printf "%d.%d.%d.%d %d.%d.%d.%d", int(start/16777216),int(start/65536)%256,int(start/256)%256,start%256,int(end/16777216),int(end/65536)%256,int(end/256)%256,end%256
}')

port=${TUNNELSLATE_VPN_PORT:-1194}
case "$port" in ''|*[!0-9]*) invalid 'VPN_PORT must be between 1 and 65535.';; esac
[ "$port" -ge 1 ] && [ "$port" -le 65535 ] || invalid 'VPN_PORT must be between 1 and 65535.'
protocol=${TUNNELSLATE_VPN_PROTOCOL:-udp}
case "$protocol" in udp) server_protocol=udp;; tcp) server_protocol=tcp-server;; *) invalid 'VPN_PROTOCOL must be udp or tcp.';; esac

dco=${TUNNELSLATE_VPN_DCO:-auto}
case "$dco" in auto|off) ;; *) invalid 'VPN_DCO must be auto or off.';; esac
max_clients=${TUNNELSLATE_VPN_MAX_CLIENTS:-1024}
keepalive_interval=${TUNNELSLATE_VPN_KEEPALIVE_INTERVAL:-10}
keepalive_timeout=${TUNNELSLATE_VPN_KEEPALIVE_TIMEOUT:-60}
validate_number() {
  case "$1" in ''|*[!0-9]*|0*) invalid "$2 must be a positive decimal integer.";; esac
  [ "${#1}" -le 5 ] && [ "$1" -le "$3" ] || invalid "$2 is outside the supported range."
}
validate_number "$max_clients" VPN_MAX_CLIENTS 65535
validate_number "$keepalive_interval" VPN_KEEPALIVE_INTERVAL 3600
validate_number "$keepalive_timeout" VPN_KEEPALIVE_TIMEOUT 86400
[ "$keepalive_timeout" -ge "$((keepalive_interval * 2))" ] || invalid 'VPN_KEEPALIVE_TIMEOUT must be at least twice VPN_KEEPALIVE_INTERVAL.'

# MTU/MSS are data, never config fragments. MSS is the TCP payload size.
tun_mtu=${TUNNELSLATE_VPN_TUN_MTU:-0}
case "$tun_mtu" in 0) effective_mtu=1500;; *) validate_number "$tun_mtu" VPN_TUN_MTU 1500; [ "$tun_mtu" -ge 576 ] || invalid 'VPN_TUN_MTU must be 0 or 576–1500.'; effective_mtu=$tun_mtu;; esac
mss_mode=${TUNNELSLATE_VPN_MSS_MODE:-default}
mss=${TUNNELSLATE_VPN_MSS:-0}
case "$mss_mode" in
  default|off) [ "$mss" = 0 ] || invalid 'VPN_MSS must be 0 outside custom mode.';;
  custom) validate_number "$mss" VPN_MSS 1460; [ "$mss" -ge 536 ] && [ "$mss" -le "$((effective_mtu - 40))" ] || invalid 'VPN_MSS must be 536 to tunnel MTU minus 40.';;
  *) invalid 'VPN_MSS_MODE must be default, custom or off.';;
esac

dns_domain=${TUNNELSLATE_VPN_DNS_DOMAIN:-}
dns_search=${TUNNELSLATE_VPN_DNS_SEARCH:-}
validate_domain() {
  [ -n "$1" ] && [ "${#1}" -le 253 ] || invalid 'DNS domain is too long.'
  printf '%s\n' "$1" | LC_ALL=C awk '
    NR > 1 { exit 1 }
    /[^a-z0-9.-]/ { exit 1 }
    { n=split($0,a,"."); for(i=1;i<=n;i++) if(length(a[i])<1 || length(a[i])>63 || a[i] !~ /^[a-z0-9]/ || a[i] !~ /[a-z0-9]$/) exit 1 }
  ' || invalid 'Invalid DNS domain.'
}
[ -z "$dns_domain" ] || validate_domain "$dns_domain"
remaining=$dns_search
count=0
while [ -n "$remaining" ]; do
  case "$remaining" in *,*) domain=${remaining%%,*}; remaining=${remaining#*,}; [ -n "$remaining" ] || invalid 'Empty DNS search domain.';; *) domain=$remaining; remaining='';; esac
  validate_domain "$domain"
  count=$((count + 1))
  [ "$count" -le 10 ] || invalid 'At most 10 DNS search domains are allowed.'
done

# Validate every DNS address before touching the output config. No shell evaluation.
dns_remaining=${TUNNELSLATE_VPN_DNS:-172.16.0.1}
dns_servers=''
while :; do
  case "$dns_remaining" in
    *,*) dns=${dns_remaining%%,*}; dns_remaining=${dns_remaining#*,}; more=1;;
    *) dns=$dns_remaining; more=0;;
  esac
  dns=$(printf '%s' "$dns" | awk '{$1=$1; print}')
  case "$dns" in ''|*[!0-9.]*) invalid 'VPN_DNS must contain comma-separated IPv4 addresses.';; esac
  dns_info=$(ipcalc -n "$dns/32") || invalid 'Invalid IPv4 address in VPN_DNS.'
  canonical_dns=$(printf '%s\n' "$dns_info" | sed -n 's/^NETWORK=//p')
  [ "$canonical_dns" = "$dns" ] || invalid 'VPN_DNS addresses must use dotted decimal IPv4 notation.'
  dns_servers="$dns_servers $dns"
  [ "$more" = 1 ] || break
done

# Validate full tunnel and extra routes before writing a derived config.
redirect=${TUNNELSLATE_VPN_REDIRECT_GATEWAY:-false}
case "$redirect" in true|false) ;; *) invalid 'VPN_REDIRECT_GATEWAY must be true or false.';; esac
routes=${TUNNELSLATE_VPN_ROUTES:-}
case "$routes" in *[!0-9.,/]*) invalid 'VPN_ROUTES must contain comma-separated IPv4 CIDR prefixes.';; esac
remaining=$routes
while [ -n "$remaining" ]; do
  case "$remaining" in *,*) route=${remaining%%,*}; remaining=${remaining#*,}; [ -n "$remaining" ] || invalid 'Empty route.';; *) route=$remaining; remaining='';; esac
  route_prefix=${route##*/}
  case "$route_prefix" in ''|*[!0-9]*) invalid 'Invalid route prefix.';; esac
  [ "$route" != "$route_prefix" ] && [ "$route_prefix" -le 32 ] || invalid 'Invalid route prefix.'
  ipcalc -n -m "$route" > /dev/null || invalid 'Invalid IPv4 route.'
done

# Keep the persistent custom config intact. Replace managed directives in a derived
# runtime config, including legacy configs written before env settings were wired up.
awk '
  {
    line=$0
    sub(/^[ \t]+/, "", line)
    if (inline) {
      print
      if (line ~ /^<\//) inline=0
      next
    }
    if (line ~ /^<[^\/]/) { if (line !~ /<\/[^>]+>/) inline=1; print; next }
    if (line ~ /^(--)?(server|topology|ifconfig-pool|client-config-dir|port|proto|explicit-exit-notify|management|management-client-user|management-client-group|keepalive|ping|ping-restart|ping-exit|max-clients|disable-dco|tun-mtu|mssfix|client-to-client|learn-address|client-connect|client-disconnect|status|status-version|script-security|route|dev|dev-type|verify-client-cert|username-as-common-name|auth-user-pass-verify|auth-user-pass-optional|auth-gen-token|auth-gen-token-secret|auth-token|management-client-auth|tmp-dir|reneg-sec|hand-window)([ \t]|$)/) next
    if (line ~ /^(--)?push[ \t]+["\047]?dhcp-option[ \t]+(DNS|DOMAIN|DOMAIN-SEARCH)([ \t]|$)/) next
    if (line ~ /^(--)?push[ \t]+["\047]?(route|redirect-gateway)([ \t]|$)/) next
    if (line ~ /^(--)?push[ \t]+["\047]?(ping|ping-restart|ping-exit|tun-mtu|mssfix)([ \t]|$)/) next
    print
  }
' "$base" > "$output"
{
  printf '\n# Managed by TunnelSlate settings.\n'
  printf 'dev tun0\ntopology subnet\nserver %s %s nopool\n' "$address" "$netmask"
  printf 'ifconfig-pool %s %s\n' "$pool" "$netmask"
  printf 'client-config-dir /etc/openvpn/ccd\nport %s\nproto %s\n' "$port" "$server_protocol"
  printf 'management /run/tunnelslate/management.sock unix\nmanagement-client-user desk\nmanagement-client-group desk\n'
  printf 'verify-client-cert require\nauth-user-pass-optional\nauth-user-pass-verify /usr/local/bin/vpn-auth via-file\ntmp-dir /run/openvpn/auth\nreneg-sec 3600\nhand-window 330\n'
  printf 'status /run/openvpn/status.log 5\nstatus-version 3\nclient-disconnect /usr/local/bin/desk-client-disconnect\n'
  printf 'max-clients %s\nkeepalive %s %s\n' "$max_clients" "$keepalive_interval" "$keepalive_timeout"
  if [ "$tun_mtu" != 0 ]; then printf 'tun-mtu %s\n' "$tun_mtu"; fi
  if [ "$protocol" = udp ]; then
    case "$mss_mode" in custom|off) printf 'mssfix 0\n';; esac
  fi
  if [ -n "$dns_domain" ]; then printf 'push "dhcp-option DOMAIN %s"\n' "$dns_domain"; fi
  remaining=$dns_search
  while [ -n "$remaining" ]; do
    case "$remaining" in *,*) domain=${remaining%%,*}; remaining=${remaining#*,};; *) domain=$remaining; remaining='';; esac
    printf 'push "dhcp-option DOMAIN-SEARCH %s"\n' "$domain"
  done
  if [ "$dco" = off ]; then printf 'disable-dco\n'; fi
  if [ "$protocol" = udp ]; then printf 'explicit-exit-notify 1\n'; fi
  if [ "$redirect" = true ]; then printf 'push "redirect-gateway def1 bypass-dhcp"\n'; fi
  remaining=$routes
  while [ -n "$remaining" ]; do
    case "$remaining" in *,*) route=${remaining%%,*}; remaining=${remaining#*,};; *) route=$remaining; remaining='';; esac
    route_info=$(ipcalc -n -m "$route")
    route_address=$(printf '%s\n' "$route_info" | sed -n 's/^NETWORK=//p')
    route_mask=$(printf '%s\n' "$route_info" | sed -n 's/^NETMASK=//p')
    printf 'push "route %s %s"\n' "$route_address" "$route_mask"
  done
  for dns in $dns_servers; do
    printf 'push "dhcp-option DNS %s"\n' "$dns"
    # Route external DNS through the tunnel even in split-tunnel mode.
    dns_network=$(ipcalc -n "$dns/$prefix" | sed -n 's/^NETWORK=//p')
    if [ "$dns_network" != "$address" ]; then
      printf 'push "route %s 255.255.255.255"\n' "$dns"
    fi
  done
} >> "$output"

# The entrypoint uses exactly this normalized CIDR in its NAT rule.
printf '%s/%s\n' "$address" "$prefix"

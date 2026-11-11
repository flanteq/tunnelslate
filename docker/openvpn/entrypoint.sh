#!/bin/sh
set -eu
umask 077
ready() {
  for file in .desk-ready settings.env network.json server.conf ca.crt server.crt server.key crl.pem tls-crypt.key; do
    [ -s "/etc/openvpn/runtime/$file" ] || return 1
  done
}
trap 'exit 0' TERM INT
if ! ready; then
  echo 'Waiting for PKI. Open the admin panel to initialize a new installation.'
  while ! ready; do
    sleep 2 &
    wait $!
  done
fi
trap - TERM INT

mkdir -p /run/openvpn
chown 10001:10001 /run/openvpn
mkdir -p /run/openvpn/auth
chown 10001:10001 /run/openvpn/auth
chmod 700 /run/openvpn/auth
mkdir -p /run/tunnelslate
chown 10001:10001 /run/tunnelslate
chmod 700 /run/tunnelslate
if [ -S /run/tunnelslate/management.sock ]; then
  rm /run/tunnelslate/management.sock
fi

egress_interface=$(ip -4 route show default | awk '/^default / { for (i=1; i<NF; i++) if ($i=="dev") { print $(i+1); exit } }')
if [ -z "$egress_interface" ]; then
  echo 'Cannot determine the outgoing interface: no IPv4 default route.' >&2
  exit 1
fi

vpn_pid=''
publish_dco_host_status() {
  module_loaded=false
  [ ! -d /sys/module/ovpn ] || module_loaded=true
  probe=$(printf 'revision=%s\nkernel_release=%s\nmodule_loaded=%s\n' "$DESK_REVISION" "$(uname -r)" "$module_loaded")
  previous_probe=$(cat /run/tunnelslate/dco-host-status 2>/dev/null || true)
  if [ "$probe" != "$previous_probe" ]; then
    temporary=$(mktemp /run/tunnelslate/.dco-host-XXXXXX)
    printf '%s\n' "$probe" > "$temporary"
    chown 10001:10001 "$temporary"
    chmod 600 "$temporary"
    mv -f "$temporary" /run/tunnelslate/dco-host-status
  fi
}
publish_network_error() {
  cp /run/openvpn/network-error /run/tunnelslate/.network-error
  chown 10001:10001 /run/tunnelslate/.network-error
  mv -f /run/tunnelslate/.network-error /run/tunnelslate/network-error
}
acknowledge_network() {
  temporary=$(mktemp /run/tunnelslate/.network-XXXXXX)
  printf '%s\n' "$policy_signature" > "$temporary"
  chown 10001:10001 "$temporary"
  chmod 600 "$temporary"
  mv -f "$temporary" /run/tunnelslate/applied-network
  rm -f /run/tunnelslate/network-error
}
stop() {
  trap '' TERM INT
  if [ -n "$vpn_pid" ]; then
    kill -TERM "$vpn_pid" 2>/dev/null || true
    wait "$vpn_pid" 2>/dev/null || true
  fi
  vpn-stats stop || true
  configure-vpn-mss 0
  exit 0
}
trap stop TERM INT

# A root supervisor can recreate TUN/NAT after the OpenVPN child drops its UID.
# Settings are read as data, never sourced or evaluated as shell commands.
while :; do
  rm -f /run/tunnelslate/applied-settings /run/tunnelslate/applied-network /run/tunnelslate/dco-host-status /run/tunnelslate/management.sock
  cp /etc/openvpn/runtime/settings.env /run/openvpn/settings.env
  cp /etc/openvpn/runtime/network.json /run/openvpn/network.json
  chown 10001:10001 /run/openvpn/network.json
  signature=$(sha256sum /run/openvpn/settings.env | awk '{print $1}')
  policy_signature=$(sha256sum /run/openvpn/network.json | awk '{print $1}')
  DESK_REVISION=0
  while IFS='=' read -r key value; do
    case "$key" in
      TUNNELSLATE_VPN_NETWORK|TUNNELSLATE_VPN_PORT|TUNNELSLATE_VPN_PROTOCOL|TUNNELSLATE_VPN_DNS|TUNNELSLATE_VPN_REDIRECT_GATEWAY|TUNNELSLATE_VPN_ROUTES|TUNNELSLATE_VPN_DCO|TUNNELSLATE_VPN_MAX_CLIENTS|TUNNELSLATE_VPN_KEEPALIVE_INTERVAL|TUNNELSLATE_VPN_KEEPALIVE_TIMEOUT|TUNNELSLATE_VPN_DNS_DOMAIN|TUNNELSLATE_VPN_DNS_SEARCH|TUNNELSLATE_VPN_TUN_MTU|TUNNELSLATE_VPN_MSS_MODE|TUNNELSLATE_VPN_MSS) export "$key=$value";;
      DESK_REVISION) case "$value" in ''|*[!0-9]*) echo 'Invalid settings revision.' >&2; exit 1;; esac; DESK_REVISION=$value;;
      *) echo 'Unknown settings key.' >&2; exit 1;;
    esac
  done < /run/openvpn/settings.env
  vpn_network=$(render-vpn-config /etc/openvpn/runtime/server.conf /run/openvpn/server.conf)
  # A new global revision publishes its CCD/policy before settings.env. Wait for
  # a complete snapshot; never start with a policy belonging to another revision.
  if ! vpn-network apply /run/openvpn/network.json "$DESK_REVISION" "$egress_interface" > /run/openvpn/network.conf 2> /run/openvpn/network-error; then
    cat /run/openvpn/network-error >&2
    publish_network_error
    echo 'Network policy not applied; waiting for a valid matching configuration.' >&2
    sleep 2 &
    wait $!
    continue
  fi
  rm -f /run/tunnelslate/network-error
  cat /run/openvpn/network.conf >> /run/openvpn/server.conf
  if [ "${TUNNELSLATE_VPN_PROTOCOL:-udp}" = udp ] && [ "${TUNNELSLATE_VPN_MSS_MODE:-default}" = custom ]; then
    configure-vpn-mss "$TUNNELSLATE_VPN_MSS"
  else
    configure-vpn-mss 0
  fi
  chown 10001:10001 /run/openvpn/server.conf
  iptables -t nat -C POSTROUTING -s "$vpn_network" -o "$egress_interface" -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -s "$vpn_network" -o "$egress_interface" -j MASQUERADE
  rm -f /run/tunnelslate/management.sock /run/tunnelslate/applied-settings /run/tunnelslate/dco-host-status
  rm -f /run/openvpn/status.log
  : > /run/openvpn/status.log
  chown 10001:10001 /run/openvpn/status.log
  vpn-stats start || true
  openvpn --config /run/openvpn/server.conf &
  vpn_pid=$!
  acknowledged=0
  changed=0
  while kill -0 "$vpn_pid" 2>/dev/null; do
    vpn-stats sample || true
    publish_dco_host_status
    if [ "$acknowledged" = 0 ] && [ -S /run/tunnelslate/management.sock ]; then
      if vpn-network routes 2> /run/openvpn/network-error; then
        temporary=$(mktemp /run/tunnelslate/.applied-XXXXXX)
        printf '%s\n' "$DESK_REVISION" > "$temporary"
        chown 10001:10001 "$temporary"
        chmod 600 "$temporary"
        mv -f "$temporary" /run/tunnelslate/applied-settings
        acknowledge_network
        acknowledged=1
      else
        publish_network_error
      fi
    fi
    latest=$(sha256sum /etc/openvpn/runtime/settings.env | awk '{print $1}')
    latest_policy=$(sha256sum /etc/openvpn/runtime/network.json | awk '{print $1}')
    if [ "$latest" != "$signature" ]; then
      echo 'Applying updated VPN settings; restarting the OpenVPN process.'
      changed=1
      kill -TERM "$vpn_pid" 2>/dev/null || true
      break
    fi
    if [ "$latest_policy" != "$policy_signature" ]; then
      cp /etc/openvpn/runtime/network.json /run/openvpn/network-next.json
      if vpn-network update /run/openvpn/network-next.json "$DESK_REVISION" "$egress_interface" 2> /run/openvpn/network-error; then
        policy_signature=$(sha256sum /run/openvpn/network.json | awk '{print $1}')
        acknowledge_network
        echo 'Individual VPN network policy applied without restarting OpenVPN.'
      else
        publish_network_error
      fi
    elif [ "$acknowledged" = 1 ]; then
      # Restoring the already active policy also clears an earlier failed update.
      rm -f /run/tunnelslate/network-error
    fi
    sleep 2 &
    wait $!
  done
  code=0
  wait "$vpn_pid" || code=$?
  vpn_pid=''
  vpn-stats stop || true
  configure-vpn-mss 0
  iptables -t nat -D POSTROUTING -s "$vpn_network" -o "$egress_interface" -j MASQUERADE
  if [ "$changed" = 0 ]; then
    echo "OpenVPN stopped unexpectedly (exit $code)." >&2
    exit 1
  fi
done

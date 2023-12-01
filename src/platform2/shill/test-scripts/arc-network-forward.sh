#!/bin/bash
# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

set -euo pipefail

ANDROID_ADDR=100.115.92.2
SSH_PORT=22

function run_iptables {
  local action="${1}"

  for iface in /sys/class/net/*; do
    iface=$(basename ${iface})
    case ${iface} in
      "lo" )
      # No forwarding for localhost.
      ;;

      "arcbr0" | "veth_android" )
      # No forwarding from the Android interfaces.
      ;;

      tun* )
      # No forwarding for VPN interfaces.
      ;;

      * )
      # Mark packets coming from ${iface} so that they are masqueraded on their
      # way back and correctly forwarded. See platform2/patchpanel/manager.cc
      # for more details.
      iptables -t mangle ${action} PREROUTING -i ${iface} \
        -p tcp ! --dport ${SSH_PORT} -j MARK --set-mark 1 -w || return 1
      iptables -t nat ${action} PREROUTING -i ${iface} \
        -p tcp ! --dport ${SSH_PORT} -j DNAT \
        --to-destination ${ANDROID_ADDR} -w || return 1
      ;;
    esac
  done
}

mode="${1:-}"
if [ "${mode}" != "enable" -a "${mode}" != "disable" ]; then
  echo "Forwards inbound TCP connections on LAN interfaces (wlan0, eth0, etc.)"
  echo "to the Android container. Normally only ADB connections are allowed"
  echo "into the container, and all other ports are owned by Chrome OS."
  echo "This script prevents Chrome OS and Chrome apps from accepting inbound"
  echo "TCP connections. It keeps port 22 unforwarded to SSH can still be"
  echo "accessible."
  echo ""
  echo "usage: ${0} { enable | disable }"
  exit 1
fi

# Both versions first check if the rules exist to avoid adding duplicate rules /
# removing non-existent rules.
if [ "${mode}" = "enable" ]; then
  run_iptables "-C" 2>/dev/null || run_iptables "-A"
else
  run_iptables "-C" 2>/dev/null && run_iptables "-D"
fi

#!/bin/bash
# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

set -euo pipefail

function set_route {
  local mode="${1}"
  local ip="${2}"
  local host="${3}"
  local gw="${4}"

  if [ "${mode}" = "ethernet" ]; then
    ${ip} route del "${host}" via "${gw}"
  else
    # FIXME: This *should* work for IPv6, but it returns EINVAL.
    ${ip} route add "${host}" via "${gw}"
    dbus-send --system --dest=org.chromium.flimflam --print-reply / \
      org.chromium.flimflam.Manager.SetServiceOrder \
      string:"vpn,wifi,ethernet,cellular"
  fi
}

function find_route {
  local mode="${1}"
  local host="${2}"
  local ip="ip -4"

  if [[ "${host}" = *:* ]]; then
    ip="ip -6"
  fi

  route=($(${ip} route get "${host}"))
  if [ "${route[0]}" = "${host}" -a "${route[1]}" = "via" ]; then
    set_route "${mode}" "${ip}" "${host}" "${route[2]}"
    exit 0
  else
    echo "Could not find gateway for ${host}"
    exit 1
  fi
}

function parse_netstat {
  local mode="${1}"

  while read -r proto recv_q send_q local foreign state; do
    if [[ "${proto}" = tcp* && "${local}" = *:22 && \
          "${state}" == ESTABLISHED ]]; then
      find_route "${mode}" "${foreign%:*}"
      exit 0
    fi
  done

  echo "Could not find ssh connection in netstat"
  exit 1
}

mode="${1:-}"
if [ "${mode}" != "wifi" -a "${mode}" != "ethernet" ]; then
  echo "Tells shill to prioritize ethernet or wifi, and adds a route"
  echo "back to the ssh/adb host so that the device can still be controlled"
  echo "remotely."
  echo ""
  echo "usage: ${0} { ethernet | wifi }"
  exit 1
fi

if [ "${mode}" = "ethernet" ]; then
  # Switch the service order first, because the IP lookup might fail.
  dbus-send --system --dest=org.chromium.flimflam --print-reply / \
    org.chromium.flimflam.Manager.SetServiceOrder \
    string:"vpn,ethernet,wifi,cellular"
fi

# Find the first connection to our local port 22 (ssh), then use it to
# set a static route via eth0.
# This should ideally use $SSH_CLIENT instead, but that will require enabling
# transparent mode in sslh because $SSH_CLIENT currently points to
# 127.0.0.1.
netstat --tcp --numeric --wide | parse_netstat "${mode}"
exit 0

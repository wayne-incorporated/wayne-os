#!/bin/sh
# shellcheck disable=SC2039

# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Workaround for b:35648315 where Cyan devices lose touch with the wifi NIC
# in the field. The workaround is to unbind the driver, rescan the PCI bus
# and bind the driver again. Logs from the field show that the device is
# possibly disappearing off the bus for a short while, and when it comes
# back, the pci config space is intact, but memory-mapped registers are
# not OK (reading all Fs).
# Rescanning the bus implies a memory window is allocated again.

readonly PID=$$
readonly TAG="pci-rescan"

###### Helpers

# $*: String to log.
log() {
  logger -t "${TAG}" --id "${PID}" "$*"
}

# $1: function that evaluates a condition to check for.
wait_for_true_or_time_out() {
  local count
  for count in $(seq 0 1 60); do
    if "$@"; then
      return 0
    fi
    sleep 1
  done
  return 1
}

wifi_nic_in_lspci() {
  # Check for the Intel wifi PCI ID
  # 8086:095a/095b = StonePeak2
  # 8086:08b1/08b2 = WilkinsPeak2
  local sp2_1="$(lspci -nD -d 8086:095a)"
  local sp2_2="$(lspci -nD -d 8086:095b)"
  local wp2_1="$(lspci -nD -d 8086:08b1)"
  local wp2_2="$(lspci -nD -d 8086:08b2)"
  local wifi_dev="${sp2_1}${sp2_2}${wp2_1}${wp2_2}"
  wifi_dev="${wifi_dev%% *}"

  if [ -n "${wifi_dev}" ]; then

    # Disable ClkPM, Enable L1, CommClk via link control register
    # It is at offset 0x50 for both SP2 and WP2
    setpci -s "${wifi_dev}" 0x50.w=0x42

    # The WP2 does not have L1 PM substate capabilities
    if [ -z "${wp2_1}${wp2_2}" ]; then
      # Disable L1 substates.
      log "Disabling L1 PM substates"
      setpci -s "${wifi_dev}" 0x15c.l=0x0
    fi

    log "Successfully found PCI wifi device in lspci: ${wifi_dev}"
    lspci -vvv -s "${wifi_dev}" | log
    return 0
  else
    log "No known PCI wifi device in lspci, retrying scan..."
    # A rescan does not delete any devices already discovered. It only checks
    # for new devices, so we are still good. A retry also covers the cases where
    # the wifi device may take some time to come back up rather than
    # immediately. Note that wait_for_true_or_time_out tries 60 times, so in
    # the worst case, we may end up rescanning all of those 60 times.
    echo 1 > /sys/bus/pci/rescan
    return 1
  fi
}

wlan0_present() {
  if [ -e "/sys/class/net/wlan0" ]; then
    log "Successfully found /sys/class/net/wlan0"
    return 0
  else
    log "Can't find /sys/class/net/wlan0"
    return 1
  fi
}

shill_has_wlan0() {
  local count
  count=$(dbus-send --system --print-reply --dest=org.chromium.flimflam \
          /device/wlan0 \
          org.chromium.flimflam.Device.GetProperties | grep -c wlan0)
  if [ "${count}" -ge 0 ]; then
     log "Shill brought up wlan0, interface is functional"
    return 0
  else
     log "Shill can't bringup wlan0, interface not functional"
    return 1
  fi
}

###### main

main() {
  # Add an UMA metric that shows the state of wifi after the rescan
  # with the following enum:
  # 0 : NIC not detected in lspci
  # 1 : NIC shows in lspci but wlan0 doesnt exist / shill doesn't know.
  # 2 : NIC shows in lspci, /sys/class/net/wlan0 exists, shill doesn't know.
  # 3 : all of (2) and shill knows about wlan0 interface.
  # Note that what the users see in the UI is based on the UI asking shill
  # for wlan0 over dbus, so 3 is the only "happy" case for users here.
  local wifi_status=0
  local buf
  local port
  local bc

  log "$1 was removed. Trying to revive"

  # Get rid of wifi module to restart cleanly.
  modprobe -r iwlmvm iwlwifi
  # Find the WiFi PCIe root port.
  port="$(basename "$(dirname "$1")")"
  # Get the current bridge control.
  bc=$(setpci -s "${port}" BRIDGE_CONTROL)
  # Turn on bit 6 - secondary bus reset.
  setpci -s "${port}" BRIDGE_CONTROL="$(printf "%04x" $((0x${bc} | 0x40)))"
  sleep 0.01
  # Turn secondary bus reset off.
  setpci -s "${port}" BRIDGE_CONTROL="${bc}"
  sleep 1
  log "Starting pci bus rescan"
  echo 1 > "/sys/bus/pci/devices/${port}/rescan"
  # Delay b/w rescanning pci bus and wlan0 appearining is 100-300 ms. Hence
  # sleep here to make the checks below easier.
  sleep 1

  ###### Check, log and record metric.
  if wait_for_true_or_time_out wifi_nic_in_lspci; then
    wifi_status=1
    if wait_for_true_or_time_out wlan0_present; then
      wifi_status=2
      # wlan0 has reappeared, now restart wpasupplicant
      # and shill so that they know about the new interface.
      restart wpasupplicant
      restart shill
      if wait_for_true_or_time_out shill_has_wlan0; then
        wifi_status=3
      fi
    fi
  else
    log "Wifi NIC did not show up in lspci"
    buf="$(lspci -vvv)"
    echo "${buf}" | log
  fi

  log "Sending : Platform.WiFiStatusAfterForcedPCIRescan: ${wifi_status}"
  metrics_client -e Platform.WiFiStatusAfterForcedPCIRescan ${wifi_status} 3
}

main "$@"

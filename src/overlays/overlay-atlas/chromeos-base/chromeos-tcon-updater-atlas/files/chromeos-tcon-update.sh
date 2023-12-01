#!/bin/sh -e
#
# Copyright 2020 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

. /opt/google/tcon/scripts/chromeos-nvt-tcon-firmware-update.sh

hook_pre_display_reset() {
  # Disable Panel Self-Refresh (PSR).  This takes effect upon panel reset.
  loginfo "disabling PSR in preparation for TCON firmware update"
  echo 0 > /sys/module/i915/parameters/enable_psr
}

hook_post_display_reset() {
  # Verify that Panel Self-Refresh (PSR) is disabled.
  if ! grep -q '^Enabled: no$' /sys/kernel/debug/dri/0/i915_edp_psr_status; then
    logerror "failed to disable PSR, will not attempt TCON firmware update"
    return 1
  fi
  loginfo "successfully disabled PSR"
}

# Args:
#   vendor: PCI vendor ID
#   device: PCI device ID
#   class: PCI class ID
#   callback: Upon success, this is invoked as:
#     "$callback" "$sys_path" "$dp_aux_device" "$i2c_device"
#
# Sample callback invocation:
#   "$callback" /sys/class/drm/card0-eDP-1 /dev/drm_dp_aux0 /dev/i2c-3
find_i2c_edp() {
  [ "$#" -eq 4 ] || return
  local vendor="$1"
  local device="$2"
  local class="$3"
  local callback="$4"

  local pci_path=
  local sys_path=
  local dp_aux_device=
  local i2c_device=

  # Each of these assignments is expected to match only one path or device.
  pci_path="$(lspci -vmm -D -n -d "${vendor}:${device}:${class}" \
      | awk '/^Slot:/ {print $2; exit} ENDFILE {exit 1}')"
  sys_path="$(find "/sys/class/pci_bus/${pci_path%:*}/device/${pci_path}/drm" \
      -maxdepth 2 -regex '^.*/card[0-9]+/card[0-9]+-eDP-[0-9]+$')"
  dp_aux_device="/dev/$(find "${sys_path}" -maxdepth 1 \
      -regex '^.*/drm_dp_aux[0-9]+$' -printf '%f\n')"
  i2c_device="/dev/$(find "${sys_path}" -maxdepth 1 -regex '^.*/i2c-[0-9]+$' \
      -printf '%f\n')"

  "${callback}" "${sys_path}" "${dp_aux_device}" "${i2c_device}"
}

# Args:
#   sys_path: path to an eDP device in sysfs, e.g. /sys/class/drm/card0-eDP-1
#   dp_aux_device: path to a drm_dp_aux device, e.g. /dev/drm_dp_aux0
#   i2c_device: path to an i2c-dev device, e.g. /dev/i2c-3
nvt_tcon_callback() {
  [ "$#" -eq 3 ] || return
  local sys_path="$1"
  local dp_aux_device="$2"
  local i2c_device="$3"

  local res=
  res="$(get_display_res "${sys_path}/modes")"

  local config_file=
  local firmware_file=

  if [ "${res}" = "1920x1080" ]; then
    config_file="/opt/google/tcon/configs/NT71851_flash.ini"
    firmware_file="/lib/firmware/nvt_tcon_firmware_fhd.bin"
  elif [ "${res}" = "3840x2160" ]; then
    config_file="/opt/google/tcon/configs/NT71871_flash.ini"
    firmware_file="/lib/firmware/nvt_tcon_firmware_uhd.bin"
  else
    if [ -n "${res}" ]; then
      logerror "unrecognized internal display resolution: ${res}"
    else
      logerror "no internal display resolution found"
    fi
    return 1
  fi

  update_tcon_fw "${dp_aux_device}" "${i2c_device}" "${config_file}" \
      "${firmware_file}"
}

nvt_tcon_update() {
  find_i2c_edp "8086" "591c" "0300" nvt_tcon_callback
}

main() {
  if [ "$#" -gt 0 ]; then
    logerror "unexpected args: $*"
    return 1
  fi

  nvt_tcon_update
}

main "$@"

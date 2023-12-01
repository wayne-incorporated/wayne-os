#!/bin/sh -e
#
# Copyright 2020 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# This library is compatible with set -e, and its use is recommended.
#
# Expected usage of this library: Create a device-specific or display-specific
# script which looks up the necessary args for update_tcon_fw() and calls that
# function.  get_display_res() may be useful for identifying different display
# models which need different firmware.
#
# It is *not* recommended to source this library from any script responsible for
# more than just using this updater.  Instead create a higher level script with
# the broader responsibility, and have it execute in a subprocess the script
# which sources this library.
#
# If using this library for multiple displays on one device, it is recommended
# to use each from a separate script or invocation, and append a unique suffix
# to $LOG_TAG so that the source of log messages can be identified.

LOG_TAG="chromeos-nvt-tcon-firmware-update"
INHIBIT_SUSPEND_FILE="/run/lock/power_override/${LOG_TAG}.lock"

# Require a minimum battery percentage to mitigate
# https://issuetracker.google.com/144947174 as best we can.
# This should NOT be necessary for most firmware update processes in the
# Chromium OS ecosystem.
MIN_BATTERY_PERCENT=15

loginfo() {
  echo "$*"
  logger --tag="${LOG_TAG}" -- "$*"
}

logerror() {
  logger --stderr --tag="${LOG_TAG}" -- "$*"
}

# Pipe a non-negative integer to this.
#
# If the version is a non-negative integer, this will write the input unmodified
# to stdout and return zero.
#
# If the input is not a non-negative integer, this will write nothing to stdout,
# and will return non-zero.
verify_integer() {
  grep -o -E '^(0|[1-9][0-9]*)$'
}

# Pipe a TCON firmware version to this.
#
# If the version matches the expected format, this will write the input
# unmodified to stdout and return zero.
#
# If the input is not formatted properly, this will write nothing to stdout, and
# will return non-zero.
verify_fw_ver() {
  grep -o -E '^0x[0-9A-F]{2}-0x[0-9A-F]{2}$'
}

# Block suspend while running a command.
#
# Args:
#   $@ The command to run while suspend is blocked.
block_suspend_and_run_cmd() {
  local ret=0

  trap 'rm -f -- "${INHIBIT_SUSPEND_FILE}"' EXIT
  echo "$$" > "${INHIBIT_SUSPEND_FILE}"

  "$@"
  # Preserve the exit status in case we're running without set -e.
  ret="$?"

  rm -f "${INHIBIT_SUSPEND_FILE}"
  trap - EXIT
  return "${ret}"
}

# Prints display resolution string to stdout as one line, with trailing newline.
#
# Args:
#   dp_modes_path: path to DP modes sysfs file, e.g.
#       /sys/class/drm/card0-eDP-1/modes
#
# Sample display resolutions:
#   1920x1080
#   3840x2160
get_display_res() {
  [ "$#" -eq 1 ] || return
  local dp_modes_path="$1"

  if [ ! -e "${dp_modes_path}" ]; then
    logerror "expected sysfs path is missing: ${dp_modes_path}"
    return 1
  fi
  head -n 1 "${dp_modes_path}"
}

# Prints battery percentage as non-negative integer to stdout as one line, with
# trailing newline.
#
# Sample percentages:
#   8
#   98
#   100
#
# IMPORTANT:
# Battery charge state is checked to help mitigate
# https://issuetracker.google.com/144947174 as best we can.
# Most firmware update processes in the Chromium OS ecosystem should NOT need
# to care about battery charge state.
get_battery_percent() {
  # Use of battery_display_percent based on:
  # https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/HEAD/chromeos-base/infineon-firmware-updater/files/tpm-firmware-updater
  # (latest revision 1f9212ce3222e59aa221cccb97b2ce709c5614da)
  dump_power_status \
      | grep -E '^battery_display_percent [1-9][0-9]*(\.[0-9]+)?$' \
      | awk '{print $2}' | cut -d. -f1 | verify_integer
}

# Prints firmware file version string to stdout as one line, with trailing
# newline.
#
# Args:
#   firmware_file: path to TCON firmware binary file
#
# Sample versions:
#   0x00-0x00
#   0x01-0x02
#   0x01-0x04
#
# The current implementation resolves any symlinks in firmware_file and then
# uses the real path to determine the firmware version.  This is subject to
# change.
get_fw_file_ver() {
  [ "$#" -eq 1 ] || return
  local firmware_file="$1"

  # The use of grep ensures empty output if ${firmware_file} does not match the
  # expected format.
  realpath -e -- "${firmware_file}" | head -n 1 \
      | grep -o -E '_0x[0-9A-F]{2}_0x[0-9A-F]{2}\.bin$' \
      | sed 's/^_//; s/\.bin$//; s/_/-/g' | verify_fw_ver
}

# Prints installed firmware version to stdout as one line, with trailing
# newline.
#
# Args:
#   dp_aux_device: path to DP aux device, e.g. /dev/drm_dp_aux0
#
# Sample versions:
#   0x00-0x00
#   0x01-0x02
#   0x01-0x04
get_installed_fw_ver() {
  [ "$#" -eq 1 ] || return
  local dp_aux_device="$1"

  if [ ! -e "${dp_aux_device}" ]; then
    logerror "expected device file is missing: ${dp_aux_device}"
    return 1
  fi
  hexdump -s 0x40A -n 2 -e '1/1 "0x%02X-" 1/1 "0x%02X\n"' "${dp_aux_device}" \
      | verify_fw_ver
}

# Override this to perform actions immediately prior to display reset.
#
# This is only invoked when a TCON FW update is about to be attempted.
#
# A typical action might be to disable Panel Self-Refresh (PSR), which requires
# a driver-specific implementation.
#
# This MUST be overridden by the script using this library.  If no actions are
# needed, override with an empty no-op function.
hook_pre_display_reset() {
  logerror "hook_pre_display_reset() is not implemented.  THIS IS A BUG."
  exit 1
}

# "chromeos-boot-alert" uses "display_boot_message show_message" which
# conveniently performs the panel reset necessary for PSR disable to take
# effect.
show_message_and_reset_panel() {
  display_boot_message action restore_frecon
  chromeos-boot-alert update_tcon_firmware
}

# Override this to perform actions immediately after display reset.
#
# This is only invoked when a TCON FW update is about to be attempted.
#
# A typical action might be to verify that Panel Self-Refresh (PSR) is disabled,
# which requires a driver-specific implementation.
#
# This MUST be overridden by the script using this library.  If no actions are
# needed, override with an empty no-op function.
hook_post_display_reset() {
  logerror "hook_post_display_reset() is not implemented.  THIS IS A BUG."
  exit 1
}

# Args:
#   num_attempts: number of times to check for PSR being disabled
#   sleep_seconds: number of seconds to sleep between checking PSR status
#   dp_aux_device: path to DP aux device, e.g. /dev/drm_dp_aux0
#   i2c_device: path to I2C device, e.g. /dev/i2c-3
#   config_file: path to TCON firmware updater config file
#   firmware_file: path to TCON firmware binary file
invoke_updater_binary_loop() {
  [ "$#" -eq 6 ] || return
  local num_attempts="$1"
  local sleep_seconds="$2"
  local dp_aux_device="$3"
  local i2c_device="$4"
  local config_file="$5"
  local firmware_file="$6"

  local ret=1
  local i
  for i in $(seq -- "${num_attempts}"); do
    if [ "${i}" -gt 1 ]; then
      sleep -- "${sleep_seconds}"
    fi
    loginfo "invoking TCON firmware updater attempt ${i} of ${num_attempts}"
    ret=0
    # Executing this from a cwd that will not exist in the pivot_root results in
    # failure, so chdir to / to ensure success.  The initial deployment of this
    # script executes from / already, but safest not to rely on that.
    (cd / && exec minijail0 --profile=minimalistic-mountns -n -p \
        --uts=localhost -b /sys -b "${dp_aux_device}" -b "${i2c_device}" \
        -u fwupdate-drm_dp_aux-i2c -g fwupdate-drm_dp_aux-i2c -G \
        -S /opt/google/tcon/policies/nvt-tcon-fw-updater.update.policy -- \
        /usr/sbin/nvt-tcon-fw-updater -p:"${firmware_file}" "${config_file}") \
        || ret="$?"
    if [ "${ret}" -eq 0 ]; then
      loginfo "TCON firmware updater attempt ${i} of ${num_attempts} succeeded"
      return
    fi
    logerror "TCON firmware updater attempt ${i} of ${num_attempts} failed" \
        "with exit status ${ret}"
  done
  return "${ret}"
}

request_reboot_after_update() {
  touch /tmp/force_reboot_after_fw_update
}

# Args:
#   dp_aux_device: path to DP aux device, e.g. /dev/drm_dp_aux0
#   i2c_device: path to I2C device, e.g. /dev/i2c-3
#   config_file: path to TCON firmware updater config file
#   firmware_file: path to TCON firmware binary file
update_tcon_fw() {
  [ "$#" -eq 4 ] || return
  local dp_aux_device="$1"
  local i2c_device="$2"
  local config_file="$3"
  local firmware_file="$4"

  local target_fw_ver
  target_fw_ver="$(get_fw_file_ver "${firmware_file}")"
  local installed_fw_ver
  installed_fw_ver="$(get_installed_fw_ver "${dp_aux_device}")"

  if [ "${installed_fw_ver}" = "${target_fw_ver}" ]; then
    loginfo "no TCON firmware update needed, installed version" \
        "${installed_fw_ver} matches target version"
    return
  fi

  loginfo "TCON firmware update needed, installed version is" \
      "${installed_fw_ver} target version is ${target_fw_ver}"

  # Require a minimum battery percentage to mitigate
  # https://issuetracker.google.com/144947174 as best we can.
  # This check should NOT be necessary for most firmware update processes in the
  # Chromium OS ecosystem.
  local battery_percent
  battery_percent="$(get_battery_percent)"
  if [ "${battery_percent}" -lt "${MIN_BATTERY_PERCENT}" ]; then
    loginfo "skipping TCON firmware update due to low battery charge"
    return
  fi

  block_suspend_and_run_cmd do_tcon_fw_update
}

# Only update_tcon_fw() should invoke this.
#
# Preconditions:
# - Suspend must be inhibited.
# - Battery state of charge must be sufficient to complete the update.
do_tcon_fw_update() {
  hook_pre_display_reset || return
  show_message_and_reset_panel || return
  hook_post_display_reset || return

  # Without this sleep, encountered updater failures resulting in permanently
  # broken sleeps.  From initial testing 1 second sleep is enough, going with
  # 2 seconds just in case.  This extra time is trivial compared to updater
  # wall time.
  sleep 2
  invoke_updater_binary_loop 4 2 "${dp_aux_device}" "${i2c_device}" \
      "${config_file}" "${firmware_file}" || return

  # This sleep is just in case, have not yet tested whether we can do without
  # this reliably.
  sleep 2
  # Reset the display so get_installed_fw_ver can detect the new version.
  show_message_and_reset_panel

  # This sleep is just in case, initial testing without this was successful.
  sleep 2
  local post_update_fw_ver
  post_update_fw_ver="$(get_installed_fw_ver "${dp_aux_device}")"

  if [ "${post_update_fw_ver}" != "${target_fw_ver}" ]; then
    logerror "attempted and failed to update TCON firmware, expected" \
        "installed version to become ${target_fw_ver} instead it is " \
        "${post_update_fw_ver}"
    return 1
  fi

  # Only request a reboot after successful update to reduce risk of this updater
  # causing a boot loop.
  request_reboot_after_update
  loginfo "successfully updated TCON firmware to ${post_update_fw_ver}"
}

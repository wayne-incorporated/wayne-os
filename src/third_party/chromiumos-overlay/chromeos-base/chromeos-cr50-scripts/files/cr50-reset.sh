#!/bin/bash
# Copyright 2017 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# This script is a wrapper around gsctool. It creates and displays a
# qrcode from the challenge string returned by gsctool. The cr50
# is reset when a valid authorization code is entered.

# RMA Reset Authorization parameters.
# - URL of Reset Authorization Server.
RMA_SERVER="https://www.google.com/chromeos/partner/console/cr50reset"
# - Number of retries before giving up.
MAX_RETRIES=3
# - Time in seconds to delay before generating another qrcode.
RETRY_DELAY=10

. "/usr/share/cros/gsc-constants.sh"

gbb_force_dev_mode() {
  # Set GBB_FLAG_FORCE_DEV_SWITCH_ON (0x8) to force boot in
  # developer mode after RMA reset.
  /usr/bin/futility gbb --flash --set --flags="+0x8" > /dev/null 2>&1
}

cr50_reset() {
  # Make sure frecon is running.
  local frecon_pid;
  frecon_pid="$(cat /run/frecon/pid)"

  # This is the path to the pre-chroot filesystem. Since frecon is started
  # before the chroot, all files that frecon accesses must be copied to
  # this path.
  local chg_str_path="/proc/${frecon_pid}/root"

  if [ ! -d "${chg_str_path}" ]; then
    echo "frecon not running. Can't display qrcode."
    return 1
  fi

  # Make sure qrencode is installed.
  if ! command -v qrencode > /dev/null; then
    echo "qrencode is not installed."
    return 1
  fi

  # Make sure gsctool is installed.
  if ! command -v gsctool > /dev/null; then
    echo "gsctool is not installed."
    return 1
  fi

  # Get HWID and replace whitespace with underscore.
  local hwid;
  hwid="$(crossystem hwid 2>/dev/null | sed -e 's/ /_/g')"

  # Get challenge string and remove "Challenge:".
  local ch;
  ch="$(gsctool_cmd -t -r | sed -e 's/.*://g')"

  # Test if we have a challenge.
  if [ -z "${ch}" ]; then
    echo "Challenge wasn't generated. CR50 might need updating."
    return 1
  fi

  # Preseve enough space to prevent terminal scrolling.
  clear

  # Display the challenge.
  echo "Challenge:"
  echo "${ch}"

  # Remove whitespace and newline from challenge.
  ch="$(echo "${ch}" | tr -d '[:space:]')"

  # Calculate challenge URL and display it.
  local chstr="${RMA_SERVER}?challenge=${ch}&hwid=${hwid}"
  echo
  echo "URL: ${chstr}"

  # Create qrcode and display it.
  qrencode -s 5 -o "${chg_str_path}/chg.png" "${chstr}"
  printf "\033]image:file=/chg.png\033\\" > /run/frecon/vt0

  local n=0
  local ac
  while [ "${n}" -lt "${MAX_RETRIES}" ]; do
    # Read authorization code. Show input in uppercase letters.
    echo
    printf "Enter authorization code: "
    stty olcuc
    read -r -e ac
    stty -olcuc

    # The input string is still lowercase. Convert to uppercase.
    ac_uppercase="$(echo "${ac}" | tr '[:lower:]' '[:upper:]')"

    # Test authorization code.
    if gsctool_cmd -t -r "${ac_uppercase}"; then
      # Force the next boot to be in developer mode so that we can boot to
      # RMA shim again.
      echo "The system will reboot shortly."
      # Wait for cr50 to enter RMA mode.
      sleep 2
      gbb_force_dev_mode
      reboot
      # Sleep indefinitely to avoid continue.
      sleep 1d
    fi

    echo "Invalid authorization code. Please try again."
    echo

    : $(( n += 1 ))
    if [ "${n}" -eq "${MAX_RETRIES}" ]; then
      echo "Number of retries exceeded. Another qrcode will generate in 10s."
      local m=0
      while [ "${m}" -lt "${RETRY_DELAY}" ]; do
        printf "."
        sleep 1
        : $(( m += 1 ))
      done
      echo
    fi
  done
}

main() {
  if ! cr50_reset; then
    echo "Cr50 Reset Error."
  fi
}

main "$@"

#!/bin/sh
# Copyright 2017 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Checks for a device specific configuration and if present, starts
# bluetoothd with that config file; otherwise, starts bluetoothd with
# the legacy board-specific configuration (main.conf) if the config file
# is present.

bluetooth_dir="/etc/bluetooth"
conf_file="${bluetooth_dir}/main.conf"
experimental="d4992530-b9ec-469f-ab01-6c481c47da1c,671b10b5-42c0-4696-9227-eb28d1b049d6"

bt_offload="$(cros_config /bluetooth/flags enable-bluetooth-offload)"
if [ "$bt_offload" = "true" ]; then
    experimental="${experimental},a6695ace-ee7f-4fb9-881a-5fac66c629af"
fi

ll_privacy_file="/var/lib/bluetooth/bluetooth-llprivacy.experimental"
if grep -q "enable" "${ll_privacy_file}"; then
    experimental="${experimental},15c0a148-c273-11ea-b3de-0242ac130004"
fi

# "1" in quality_conf_file means to enable BQR while "0" means to disable BQR.
quality_conf_file="/var/lib/bluetooth/quality.conf"
if grep -q "^1$" "${quality_conf_file}"; then
    # To enable BQR globally by default in the future, remove the if-condition
    # above and fi below.
    experimental="${experimental},330859bc-7506-492d-9370-9a6f0614037f"
fi

# Make a copy of main.conf to /var to make it editable
var_conf_file="/var/lib/bluetooth/main.conf"
cp "${conf_file}" "${var_conf_file}"
# For security, limit the file permissions to only user "bluetooth".
chown bluetooth: "${var_conf_file}"
chmod 0600 "${var_conf_file}"
# Set the DeviceID based on Chrome OS version.
os_version="$(awk -F= '$1=="VERSION" { print $2 ;}' /etc/os-release)"
hex_os_version="$(printf '%04x' "${os_version}")"
sed -i -E "s/(bluetooth:00e0:c405:)0000/\1${hex_os_version}/" "${var_conf_file}"

config_file_param="--configfile=${var_conf_file}"

exec /sbin/minijail0 -u bluetooth -g bluetooth -G \
  -c 3500 -n -- \
  /usr/libexec/bluetooth/bluetoothd "${BLUETOOTH_DAEMON_OPTION}" --nodetach \
  "${config_file_param}" -E "${experimental}"

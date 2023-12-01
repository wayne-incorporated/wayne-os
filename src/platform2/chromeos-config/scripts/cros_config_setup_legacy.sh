#!/bin/bash
# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Set up /run/chromeos-config during boot (assumes pre-unibuild).
# Note: This is written to target busybox ash and bash, as it needs to
# run in recovery initramfs, where we only have busybox.

# TODO(jrosenth): Delete this script once we're 100% unibuild.

set -e

: "${MOUNTPOINT:=/run/chromeos-config}"
CONFIG_OUT="${MOUNTPOINT}/private"

# Magic environment variable that lets us get access to hidden mosys
# commands accessible only to cros-config now.
export I_AM_CROS_CONFIG=1

# Set a config to a value.
#   $1: path
#   $2: property
#   $3: value
setconfig() {
    local path="$1"
    local property="$2"
    local value="$3"

    if [ -n "${value}" ]; then
        mkdir -p "${CONFIG_OUT}${path}"
        echo -n "${value}" > "${CONFIG_OUT}${path}/${property}"
    fi
}

model="$(mosys platform model)"
brand_code="$(mosys platform brand)"
customization_id="$(mosys platform customization || true)"
platform_name="$(mosys platform name)"

setconfig / brand-code "${brand_code}"
setconfig / name "${model}"
setconfig /firmware image-name "${model}"
setconfig /hardware-properties form-factor CHROMEBOOK
setconfig /hardware-properties has-backlight true
setconfig /hardware-properties psu-type battery
setconfig /identity platform-name "${platform_name}"
setconfig /ui help-content-id "${customization_id}"

mkdir -p "${MOUNTPOINT}/v1"
mount -n -obind,ro,nodev,noexec,nosuid "${CONFIG_OUT}" "${MOUNTPOINT}/v1"

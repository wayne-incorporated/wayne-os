#!/bin/bash
# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

set -e

# Ensure we run from this script's directory.
cd -- "$(dirname -- "$0")"

die() {
    echo "$@" >&2
    exit 1
}

(
    # Mocked commands
    crosid() {
        echo -n 8
    }

    MOUNT_CALLS=()
    mount() {
        MOUNT_CALLS+=("$*")
    }

    # shellcheck disable=SC2030
    MOUNTPOINT="$(mktemp -d)"
    source cros_config_setup.sh
    rm -rf "${MOUNTPOINT}"

    # Assertions
    [ "${#MOUNT_CALLS[@]}" = 2 ] \
        || die "mount should have been called exactly twice (got ${#MOUNT_CALLS[@]} calls)"
    [ "${MOUNT_CALLS[0]}" = "-n -oro,nodev,noexec,nosuid /usr/share/chromeos-config/configfs.img ${MOUNTPOINT}/private" ] \
        || die "First call to mount does not look right (${MOUNT_CALLS[0]})"
    [ "${MOUNT_CALLS[1]}" = "-n -obind,ro,nodev,noexec,nosuid ${MOUNTPOINT}/private/v1/chromeos/configs/8 ${MOUNTPOINT}/v1" ] \
        || die "Second call to mount does not look right (${MOUNT_CALLS[1]})"
)

(
    # Mock crosid this time so we don't match a config
    crosid() {
        echo -n unknown
    }

    if ( source cros_config_setup.sh ) 2>/dev/null; then
        die "Should exit with failure status"
    fi
)

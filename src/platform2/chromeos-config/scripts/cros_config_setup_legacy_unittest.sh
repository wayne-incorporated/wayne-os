#!/bin/bash
# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

set -e

# Ensure we run from this script's directory.
cd -- "$(dirname -- "$0")"

(
    # Mocked commands
    mosys() {
        if [ "${I_AM_CROS_CONFIG}" != 1 ]; then
            return 1
        fi

        case "$*" in
            "platform model" )
                echo somemodel
                ;;
            "platform brand" )
                echo ZZCR
                ;;
            "platform customization" )
                echo SOMEOEM-SOMEMODEL
                ;;
            "platform name" )
                echo Some
                ;;
            * )
                return 1
                ;;
        esac
    }

    MOUNTPOINT="$(mktemp -d)"

    mount() {
        [ "$1" == "-n" ] || return 1
        [ "$2" == "-obind,ro,nodev,noexec,nosuid" ] || return 1
        [ "$3" == "${MOUNTPOINT}/private" ] || return 1
        [ -d "$3" ] || return 1
        [ "$4" == "${MOUNTPOINT}/v1" ] || return 1
        [ -d "$4" ] || return 1

        # Simulate sorta what the bind mount would do
        rmdir "$4"
        cp -r "$3" "$4"
    }

    source cros_config_setup_legacy.sh

    # Assertions
    assert_config_equals() {
        local path="$1"
        local property="$2"
        local value="$3"
        local expected_output_file

        # We use diff to show the difference and also so that we
        # compare the value exactly (including newlines, etc).
        expected_output_file="$(mktemp)"
        echo -n "${value}" >"${expected_output_file}"
        diff "${MOUNTPOINT}/v1${path}/${property}" "${expected_output_file}"
        rm "${expected_output_file}"
    }

    assert_config_equals / name somemodel
    assert_config_equals / brand-code ZZCR
    assert_config_equals /identity platform-name Some
    assert_config_equals /ui help-content-id SOMEOEM-SOMEMODEL
    assert_config_equals /hardware-properties psu-type battery
    assert_config_equals /hardware-properties has-backlight true
    assert_config_equals /hardware-properties form-factor CHROMEBOOK
    assert_config_equals /firmware image-name somemodel
    rm -rf "${MOUNTPOINT}"
)

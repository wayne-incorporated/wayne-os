#!/usr/bin/env python3
# Copyright 2017 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""The example code for getting touchpad info for factory with hammerd API."""

from __future__ import print_function

import argparse
import collections
import ctypes
import os.path
import shlex
import subprocess
import sys

import hammerd_api


# The mask of the hardware write protection.
# TODO(akahuang): Move to hammerd_api.py
EC_FLASH_PROTECT_RO_AT_BOOT = 1 << 0
EC_FLASH_PROTECT_RO_NOW = 1 << 1
EC_FLASH_PROTECT_ALL_NOW = 1 << 2
EC_FLASH_PROTECT_GPIO_ASSERTED = 1 << 3
EC_FLASH_PROTECT_ERROR_STUCK = 1 << 4
EC_FLASH_PROTECT_ERROR_INCONSISTENT = 1 << 5
EC_FLASH_PROTECT_ALL_AT_BOOT = 1 << 6
EC_FLASH_PROTECT_RW_AT_BOOT = 1 << 7
EC_FLASH_PROTECT_RW_NOW = 1 << 8
EC_FLASH_PROTECT_ROLLBACK_AT_BOOT = 1 << 9
EC_FLASH_PROTECT_ROLLBACK_NOW = 1 << 10

FLASH_PROTECT_ALL = (
    EC_FLASH_PROTECT_RO_AT_BOOT
    | EC_FLASH_PROTECT_RO_NOW
    | EC_FLASH_PROTECT_RW_AT_BOOT
    | EC_FLASH_PROTECT_RW_NOW
    | EC_FLASH_PROTECT_ROLLBACK_AT_BOOT
    | EC_FLASH_PROTECT_ROLLBACK_NOW
    | EC_FLASH_PROTECT_ALL_AT_BOOT
    | EC_FLASH_PROTECT_ALL_NOW
    | EC_FLASH_PROTECT_GPIO_ASSERTED
)

# list of pre-defined exit codes
ERROR_GET_FIRST_PDU = 3


def DetachableBaseConfig(key):
    cmd = ["cros_config", "/detachable-base", key]
    return subprocess.check_output(cmd, encoding="utf-8")


def GetHammerdArguments():
    """Parses the hammerd.override and retrieves the arguments.

    The format of the file is:
      env FOO=1234  # comment of FOO
      env BAR="string value"  # comment of BAR

    Returns:
      a dict containing the arguments of hammerd process. The type of the key and
      value are string. e.g.
      {
        'FOO': '1234',
        'BAR': 'string value'
      }
    """
    ARGUMENT_FILE_PATH = "/etc/init/hammerd.override"
    REQUIRED_ARGUMENTS = [
        "EC_IMAGE_PATH",
        "TOUCHPAD_IMAGE_PATH",
        "VENDOR_ID",
        "PRODUCT_ID",
        "USB_PATH",
    ]
    IMAGE_DIR = "/lib/firmware"

    ret = {}
    if os.path.exists(ARGUMENT_FILE_PATH):
        with open(ARGUMENT_FILE_PATH, "r") as f:
            for line in f:
                tokens = shlex.split(line)
                if len(tokens) >= 2 and tokens[0] == "env":
                    key, _unused_sel, value = tokens[1].partition("=")
                    ret[key] = value
    else:
        ec_image_filename = DetachableBaseConfig("ec-image-name")
        touchpad_image_filename = DetachableBaseConfig("touch-image-name")

        ret["EC_IMAGE_PATH"] = os.path.join(IMAGE_DIR, ec_image_filename)
        ret["TOUCHPAD_IMAGE_PATH"] = os.path.join(
            IMAGE_DIR, touchpad_image_filename
        )
        ret["VENDOR_ID"] = DetachableBaseConfig("vendor-id")
        ret["PRODUCT_ID"] = DetachableBaseConfig("product-id")
        ret["USB_PATH"] = DetachableBaseConfig("usb-path")

    missing_args = set(REQUIRED_ARGUMENTS) - set(ret.keys())
    if missing_args:
        raise ValueError("Missing arguments: %s" % (",".join(missing_args)))
    return ret


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("field", type=str, nargs="?", help="information field")
    args = parser.parse_args()

    hammerd_args = GetHammerdArguments()
    updater = hammerd_api.FirmwareUpdater(
        int(hammerd_args["VENDOR_ID"]),
        int(hammerd_args["PRODUCT_ID"]),
        hammerd_args["USB_PATH"],
    )
    with open(hammerd_args["EC_IMAGE_PATH"], "rb") as f:
        ec_image = f.read()
    updater.LoadEcImage(ec_image)
    updater.TryConnectUsb()
    if not updater.SendFirstPdu():
        sys.exit(ERROR_GET_FIRST_PDU)
    updater.SendDone()

    pdu_resp = updater.GetFirstResponsePdu().contents
    wp_status = (pdu_resp.flash_protection & EC_FLASH_PROTECT_GPIO_ASSERTED) > 0
    wp_all = pdu_resp.flash_protection == FLASH_PROTECT_ALL
    touchpad_info = hammerd_api.TouchpadInfo()
    updater.SendSubcommandReceiveResponse(
        hammerd_api.UpdateExtraCommand.TouchpadInfo,
        b"",
        ctypes.pointer(touchpad_info),
        ctypes.sizeof(touchpad_info),
    )

    # Do a pairing challenge, which will check that entropy has been injected
    pair_manager = hammerd_api.PairManager()
    challenge_status = pair_manager.PairChallenge(updater.object, None)

    # Print the base information.
    info = collections.OrderedDict()
    info["ro_version"] = updater.GetSectionVersion(hammerd_api.SectionName.RO)
    info["rw_version"] = updater.GetSectionVersion(hammerd_api.SectionName.RW)
    info["key_version"] = pdu_resp.key_version
    info["wp_screw"] = str(wp_status)
    info["wp_all"] = str(wp_all)
    info["challenge_status"] = hammerd_api.ChallengeStatus.ToStr(
        challenge_status
    )
    info["touchpad_id"] = "%d.0" % touchpad_info.id
    info["touchpad_pid"] = hex(touchpad_info.vendor)
    info["touchpad_fw_version"] = "%d.0" % touchpad_info.fw_version
    info["touchpad_fw_checksum"] = hex(touchpad_info.fw_checksum)

    if args.field is None:
        print(" ".join('%s="%s"' % (key, val) for key, val in info.items()))
    elif args.field in info:
        print(info[args.field])
    else:
        print(
            'Invalid args.field: "%s", should be one of %s'
            % (args.field, ", ".join(info.keys()))
        )
        sys.exit(1)


if __name__ == "__main__":
    main()

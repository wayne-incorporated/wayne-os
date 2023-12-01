#!/usr/bin/env python3
# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Verify RO only boots valid RW and not corrupt/ dev signed RW"""

from __future__ import print_function

import sys
import time

import common
import hammerd_api  # pylint: disable=import-error


# Before this test, please flash MP-signed locked image (staff.bin)
def main(argv):
    if argv:
        sys.exit("Test takes no args!")
    updater = hammerd_api.FirmwareUpdater(
        common.BASE_VENDOR_ID, common.BASE_PRODUCT_ID, common.BASE_USB_PATH
    )
    # Load EC image.
    with open(common.RW_VALID, "rb") as f:
        ec_image = f.read()
    updater.LoadEcImage(ec_image)

    common.disable_hammerd()
    # Update to invalid RW with corrupt bytes at begining of image
    image_desc = "Update to invalid RW with corrupt bytes at begining of image"
    update_invalid_rw(updater, common.RW_CORRUPT_FIRST_BYTE, image_desc)

    # Restore to valid RW
    restore_valid_rw(updater, common.RW_VALID)

    # Update to invalid RW with corrupt bytes at end of image
    image_desc = "Update to invalid RW with corrupt bytes at end of image"
    update_invalid_rw(updater, common.RW_CORRUPT_LAST_BYTE, image_desc)

    # Restore to valid RW
    restore_valid_rw(updater, common.RW_VALID)


def init_before_updaterw(updater):
    common.connect_usb(updater)
    print("EC information:")
    pdu_resp = updater.GetFirstResponsePdu().contents
    print("PDU Response: %s" % pdu_resp)
    print("Current section before updating RW: %s" % updater.CurrentSection())
    assert updater.CurrentSection() == 1, "Running section should be 1 (RW)"


def transfer_rw(updater, image):
    with open(image, "rb") as f:
        ec_image = f.read()
    updater.LoadEcImage(ec_image)
    print("Transferring RW")
    updater.TransferImage(1)
    updater.SendSubcommand(hammerd_api.UpdateExtraCommand.ImmediateReset)
    updater.CloseUsb()
    time.sleep(0.5)
    common.connect_usb(updater)


def update_invalid_rw(updater, image, image_desc):
    init_before_updaterw(updater)
    common.reset_stay_ro(updater)
    unlock_rw(updater)
    print(image_desc)
    transfer_rw(updater, image)
    updater.SendSubcommand(hammerd_api.UpdateExtraCommand.JumpToRW)
    updater.CloseUsb()
    # If successful (it should not be), jump to RW resets the base.
    common.connect_usb(updater)
    updater.SendFirstPdu()
    updater.SendDone()
    print("Current section-invalid RW update: %s" % updater.CurrentSection())
    assert updater.CurrentSection() == 0, "Running section should be 0 (RO)"


def restore_valid_rw(updater, image):
    print("Restoring to valid RW")
    transfer_rw(updater, image)
    updater.SendSubcommand(hammerd_api.UpdateExtraCommand.JumpToRW)
    time.sleep(2)
    updater.CloseUsb()
    time.sleep(0.5)
    # Jump to RW resets the base. Need to reconnect
    common.connect_usb(updater)
    updater.SendFirstPdu()
    updater.SendDone()
    print(
        "Current section after valid RW update: %s" % updater.CurrentSection()
    )
    assert updater.CurrentSection() == 1, "Running section should be 1 (RW)"
    common.sim_disconnect_connect(updater)


def get_wp_status(updater):
    wp_rw = (get_flash_protection(updater) & common.EC_FLASH_PROTECT_RW_NOW) > 0
    return wp_rw


def get_flash_protection(updater):
    pdu_resp = updater.GetFirstResponsePdu().contents
    return pdu_resp.flash_protection


def unlock_rw(updater):
    # Check if RW is locked and unlock if needed
    wp_rw = (get_flash_protection(updater) & common.EC_FLASH_PROTECT_RW_NOW) > 0
    print("WP status:  %s" % str(wp_rw))
    if wp_rw:
        print("Need to unlock RW")
        unlocked = updater.UnlockRW()
        assert unlocked == 1, "Failed to unlock RW"
        common.reset_stay_ro(updater)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

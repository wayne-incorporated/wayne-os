#!/usr/bin/env python3
# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Verify that RW can't update RO on locked fw"""

from __future__ import print_function

import sys
import time

import common
import hammerd_api  # pylint: disable=import-error


# Before this test, please flash staff.bin using servo
# Negative test: Flash staff image from ToT (unlocked)


def main(argv):
    if argv:
        sys.exit("Test takes no args!")
    updater = hammerd_api.FirmwareUpdater(
        common.BASE_VENDOR_ID, common.BASE_PRODUCT_ID, common.BASE_USB_PATH
    )
    # Load EC image.
    with open(common.IMAGE, "rb") as f:
        ec_image = f.read()
    updater.LoadEcImage(ec_image)

    common.disable_hammerd()
    common.connect_usb(updater)
    print("PDU Response: %s" % updater.GetFirstResponsePdu().contents)
    print("Current section before ro update: %s" % updater.CurrentSection())
    transfer_ro(updater, common.IMAGE)
    common.sim_disconnect_connect(updater)


def transfer_ro(updater, image):
    with open(image, "rb") as f:
        ec_image = f.read()
    updater.LoadEcImage(ec_image)
    print("Transferring RO")
    transfer_result = updater.TransferImage(0)
    assert transfer_result == 0, "RW should not be able to update locked RO!"
    updater.SendSubcommand(hammerd_api.UpdateExtraCommand.ImmediateReset)
    updater.CloseUsb()
    time.sleep(0.5)
    common.connect_usb(updater)
    print("PDU Response: %s" % updater.GetFirstResponsePdu().contents)
    print("Current running section: %s" % updater.CurrentSection())


def get_wp_status(updater):
    wp_rw = (get_flash_protection(updater) & common.EC_FLASH_PROTECT_RW_NOW) > 0
    return wp_rw


def unlock_rw(updater):
    # Check if RW is locked and unlock if needed
    wp_rw = get_wp_status(updater)
    print("WP status:  %s" % str(wp_rw))
    if wp_rw:
        print("Need to unlock RW")
        unlocked = updater.UnlockRW()
        assert unlocked == 1, "Failed to unlock RW"
        common.reset_stay_ro(updater)


def get_flash_protection(updater):
    pdu_resp = updater.GetFirstResponsePdu().contents
    return pdu_resp.flash_protection


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

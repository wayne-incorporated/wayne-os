#!/usr/bin/env python3
# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Verify rollback update possible & flashing with lower rb version fails"""

from __future__ import print_function

import sys
import time

import common
import hammerd_api  # pylint: disable=import-error

# Before this test, please flash staff.dev.rb1 using servo
# This test can only be run once, then the image needs to be reflashed using
# servo again.


def main(argv):
    if argv:
        sys.exit("Test takes no args!")
    updater = hammerd_api.FirmwareUpdater(
        common.BASE_VENDOR_ID, common.BASE_PRODUCT_ID, common.BASE_USB_PATH
    )
    # Load EC image.
    with open(common.RB_INITIAL, "rb") as f:
        ec_image = f.read()
    updater.LoadEcImage(ec_image)

    common.disable_hammerd()

    # Make sure rollback is updated to current RW image (rb1)
    common.connect_usb(updater)
    inc_rollback(updater, 1)

    # Update to invalid RW with RB < current RB
    image_desc = "Update to invalid RW with RB < current RB"
    update_invalid_rb(updater, common.RB_LOWER, image_desc)

    # Restore to valid RB
    image_desc = "Restoring to valid RB_1 from RO"
    restore_valid_rb(updater, common.RB_INITIAL, image_desc)

    # Update to valid RW with RB > current RB
    image_desc = "Update to valid RW with RB > current RB"
    init_before_updaterw(updater)
    common.reset_stay_ro(updater)
    unlock_rw(updater)
    restore_valid_rb(updater, common.RB_HIGHER, image_desc)

    # RB should now = RB_HIGHER
    common.connect_usb(updater)
    inc_rollback(updater, 9)


def init_before_updaterw(updater):
    print("Calling init_before_updaterw")
    common.connect_usb(updater)
    print("EC information:")
    pdu_resp = updater.GetFirstResponsePdu().contents
    print("PDU Response: %s" % pdu_resp)
    print("RO: %s" % updater.GetSectionVersion(hammerd_api.SectionName.RO))
    print("RW: %s" % updater.GetSectionVersion(hammerd_api.SectionName.RW))
    updater.SendFirstPdu()
    updater.SendDone()
    print("Current running section before RW: %s" % updater.CurrentSection())


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
    updater.SendSubcommand(hammerd_api.UpdateExtraCommand.JumpToRW)
    time.sleep(2)
    updater.CloseUsb()
    time.sleep(0.5)
    # Jump to RW resets the base. Need to reconnect
    common.connect_usb(updater)
    print("PDU Response: %s" % updater.GetFirstResponsePdu().contents)
    print("RO: %s" % updater.GetSectionVersion(hammerd_api.SectionName.RO))
    print("RW: %s" % updater.GetSectionVersion(hammerd_api.SectionName.RW))
    # Check that transferred RW is running if it's not corrupted version
    updater.SendFirstPdu()
    updater.SendDone()
    print("Current running section after RW: %s" % updater.CurrentSection())


def update_invalid_rb(updater, image, image_desc):
    init_before_updaterw(updater)
    common.reset_stay_ro(updater)
    unlock_rw(updater)
    print(image_desc)
    transfer_rw(updater, image)
    assert updater.CurrentSection() == 0, "RW has lower RB version!"


def restore_valid_rb(updater, image, image_desc):
    print(image_desc)
    transfer_rw(updater, image)
    common.sim_disconnect_connect(updater)


def get_wp_status(updater):
    pdu_resp = updater.GetFirstResponsePdu().contents
    wp_status = (
        pdu_resp.flash_protection & common.EC_FLASH_PROTECT_GPIO_ASSERTED
    ) > 0
    return wp_status


def unlock_rw(updater):
    # Check if RW is locked and unlock if needed
    wp = get_wp_status(updater)
    print("WP status:  %s" % str(wp))
    if wp:
        print("Need to unlock RW")
        updater.UnlockRW()
        common.reset_stay_ro(updater)


def inc_rollback(updater, expected_rb):
    current_rb = updater.GetFirstResponsePdu().contents.min_rollback
    print("Current RB: %s" % current_rb)
    updater.SendSubcommand(hammerd_api.UpdateExtraCommand.UnlockRollback)
    common.sim_disconnect_connect(updater)
    common.connect_usb(updater)
    pdu_resp = updater.GetFirstResponsePdu().contents
    print("PDU Response: %s" % pdu_resp)
    print("Current running section: %s" % updater.CurrentSection())
    new_rb = updater.GetFirstResponsePdu().contents.min_rollback
    print("New RB version: %s" % new_rb)
    assert new_rb == expected_rb, "Error: Failed to increment RB version!"


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

#!/usr/bin/env python3
# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Verify RO can update RW

Uses two different fw images with the same rollback version
"""

from __future__ import print_function

import sys
import time

import common
import hammerd_api  # pylint: disable=import-error


def main(argv):
    if argv:
        sys.exit("Test takes no args!")
    updater = hammerd_api.FirmwareUpdater(
        common.BASE_VENDOR_ID, common.BASE_PRODUCT_ID, common.BASE_USB_PATH
    )
    # Load EC image.
    with open(common.OLDER_IMAGE, "rb") as f:
        ec_image = f.read()
    updater.LoadEcImage(ec_image)

    common.disable_hammerd()
    init_before_updaterw(updater)
    common.reset_stay_ro(updater)
    unlock_rw(updater)
    print("Updating to OLDER_IMAGE fw from RO")
    transfer_rw(updater, common.OLDER_IMAGE)
    common.sim_disconnect_connect(updater)

    common.disable_hammerd()
    init_before_updaterw(updater)
    common.reset_stay_ro(updater)
    unlock_rw(updater)
    print("Updating to NEWER_IMAGE from RO")
    transfer_rw(updater, common.NEWER_IMAGE)
    common.sim_disconnect_connect(updater)


def init_before_updaterw(updater):
    common.connect_usb(updater)
    print("EC information:")
    pdu_resp = updater.GetFirstResponsePdu().contents
    print("PDU Response: %s" % pdu_resp)
    print("RO: %s" % updater.GetSectionVersion(hammerd_api.SectionName.RO))
    print("RW: %s" % updater.GetSectionVersion(hammerd_api.SectionName.RW))
    print(
        "Current running section before RW jump: %s" % updater.CurrentSection()
    )


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
    # Check that transferred RW is running
    print("PDU Response: %s" % updater.GetFirstResponsePdu().contents)
    print("RO: %s" % updater.GetSectionVersion(hammerd_api.SectionName.RO))
    print("RW: %s" % updater.GetSectionVersion(hammerd_api.SectionName.RW))
    updater.SendFirstPdu()
    updater.SendDone()
    print(
        "Current running section after RW jump: %s" % updater.CurrentSection()
    )


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


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

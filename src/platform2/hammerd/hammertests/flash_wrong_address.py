#!/usr/bin/env python3
# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Verify that RO cannot flash to wrong address."""

from __future__ import print_function

import sys
import time

import common
import hammerd_api  # pylint: disable=import-error

# These will fail in RO because hammer prevents current image from being
# updated. It'll fail in RW as RO is protected.
WRONG_ADDR_RO_OFFSET = "0x00000000"
WRONG_ADDR_KEY_RO = "0x0000ac00"
WRONG_ADDR_RO_FRID = "0x000000c4"
WRONG_ADDR_RW_FWID = "0x0000c0c4"
WRONG_ADDR_SIG_RW = "0x0001fc00"
# This will fail because hammer never allows rollback to be updated
WRONG_ADDR_RW_RBVER = "0x0000c0e8"
# These will fail in RW because hammer prevents current image from being
# updated. It'll fail in RO as RW must be write protected.
WRONG_ADDR_RW_OFFSET = "0x0000c000"

WRONG_ADDR_LIST = [
    WRONG_ADDR_RO_OFFSET,
    WRONG_ADDR_KEY_RO,
    WRONG_ADDR_RO_FRID,
    WRONG_ADDR_RW_FWID,
    WRONG_ADDR_SIG_RW,
    WRONG_ADDR_RW_RBVER,
    WRONG_ADDR_RW_OFFSET,
]


def main(argv):
    if argv:
        sys.exit("Test takes no args!")
    updater = hammerd_api.FirmwareUpdater(
        common.BASE_VENDOR_ID, common.BASE_PRODUCT_ID, common.BASE_USB_PATH
    )
    with open(common.IMAGE, "rb") as f:
        ec_image = f.read()
    updater.LoadEcImage(ec_image)

    common.disable_hammerd()
    common.connect_usb(updater)
    print("EC information:")
    pdu_resp = updater.GetFirstResponsePdu().contents
    print("PDU Response: %s" % pdu_resp)
    print("RO: %s" % updater.GetSectionVersion(hammerd_api.SectionName.RO))
    print("RW: %s" % updater.GetSectionVersion(hammerd_api.SectionName.RW))
    print("Is RW locked?:  %s" % updater.IsSectionLocked(1))
    assert updater.IsSectionLocked(1), "RW should be locked"

    updater.SendSubcommand(hammerd_api.UpdateExtraCommand.ImmediateReset)
    updater.CloseUsb()
    time.sleep(0.5)
    updater.TryConnectUsb()
    updater.SendSubcommand(hammerd_api.UpdateExtraCommand.StayInRO)
    time.sleep(1)
    assert updater.SendFirstPdu() is True, "Error sending first PDU"
    updater.SendDone()

    print("Current section after StayInRO cmd: %s" % updater.CurrentSection())
    assert updater.CurrentSection() == 0, "Running section should be 0 (RO)"

    init_transfer(updater)
    # First test that RW can't update anything
    flash_invalid_address(updater, True)

    # Uncommenting these line will make the test fail (RO will be able to write to
    # WRONG_ADDR_RW_OFFSET)
    # common.connect_usb(updater)
    # unlock_rw(updater)
    # updater.CloseUsb()

    # Then test that RO can't update anything
    flash_invalid_address(updater, False)


def get_wp_status(updater):
    wp_rw = (get_flash_protection(updater) & common.EC_FLASH_PROTECT_RW_NOW) > 0
    return wp_rw


def flash_invalid_address(updater, rw):
    # Using TransferTouchpadFirmware method for now as API lacks equivalent.
    for address in WRONG_ADDR_LIST:
        common.connect_usb(updater)
        if rw:
            updater.SendSubcommand(hammerd_api.UpdateExtraCommand.JumpToRW)
            updater.CloseUsb()
            time.sleep(0.5)
            updater.TryConnectUsb()
            assert updater.SendFirstPdu(), "Error sending first PDU"
            updater.SendDone()

            print("Current section: %s" % updater.CurrentSection())
            if rw:
                assert (
                    updater.CurrentSection() == 1
                ), "Running section should be 1 (RW)"
            else:
                assert (
                    updater.CurrentSection() == 0
                ), "Running section should be 0 (RO)"

            wr = updater.TransferTouchpadFirmware(int(address, 0), 4096)
            assert wr == 0, "Should not be able to write to wrong address!"
            updater.SendSubcommand(
                hammerd_api.UpdateExtraCommand.ImmediateReset
            )
            updater.CloseUsb()
            time.sleep(0.5)


def init_transfer(updater):
    with open(common.TP, "rb") as f:
        ec_image = f.read()
    updater.LoadTouchpadImage(ec_image)
    assert updater.SendFirstPdu() is True, "Error sending first PDU"
    updater.SendDone()
    unlock_rw(updater)
    common.sim_disconnect_connect(updater)


def unlock_rw(updater):
    # Check if RW is locked and unlock if needed.
    wp_rw = get_wp_status(updater)
    print("WP status:  %s" % str(wp_rw))
    if wp_rw:
        print("Need to unlock RW")
        unlocked = updater.UnlockRW()
        assert unlocked == 1, "Failed to unlock RW"


def get_flash_protection(updater):
    pdu_resp = updater.GetFirstResponsePdu().contents
    return pdu_resp.flash_protection


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

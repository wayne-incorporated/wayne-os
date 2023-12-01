#!/usr/bin/env python3
# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Verify that RO cannot flash to wrong address. Test needs unlocked image"""

from __future__ import print_function

import sys
import time

import common
import hammerd_api  # pylint: disable=import-error


WRONG_ADDRR_KEY_RO = "0x0000ac00"
WRONG_ADDRR_RO_FRID = "0x000000c4"
WRONG_ADDRR_RW_FWID = "0x0000c0c4"
WRONG_ADDRR_SIG_RW = "0x0001fc00"
WRONG_ADDRR_RW_RBVER = "0x0000c0e8"
RIGHT_ADDRR_RW_OFFSET = "0x0000c000"

WRONG_ADDR_LIST = [
    WRONG_ADDRR_RW_FWID,
    WRONG_ADDRR_SIG_RW,
    WRONG_ADDRR_RW_RBVER,
]
# WRONG_ADDR_LIST = [WRONG_ADDRR_KEY_RO, WRONG_ADDRR_RO_FRID]


def main(argv):
    if argv:
        sys.exit("Test takes no args!")
    updater = hammerd_api.FirmwareUpdater(
        common.BASE_VENDOR_ID, common.BASE_PRODUCT_ID, common.BASE_USB_PATH
    )

    # Use unlocked image on dut to verify that TransferTouchpadFirmware call works
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

    init_tp_transfer(updater)
    # Try to flash to invalid addresses. Since image is unlocked this should flash
    flash_invalid_image(updater)
    # Restore valid RW
    restore_valid_rw(updater, common.IMAGE)


def flash_invalid_image(updater):
    # Check that TransferTouchpadFirmware can write to RW in unlocked image
    for address in WRONG_ADDR_LIST:
        common.connect_usb(updater)
        unlock_rw(updater)
        wr = updater.TransferTouchpadFirmware(int(address, 0), 1)
        assert wr == 1, "Cannot write to flash: Is DUT image unlocked?"
        assert updater.SendFirstPdu() is True, "Error sending first PDU"
        updater.SendDone()
        print("Current section: %s" % updater.CurrentSection())
        assert updater.CurrentSection() == 0, "Running section should be 0 (RO)"
        updater.SendSubcommand(hammerd_api.UpdateExtraCommand.ImmediateReset)
        updater.CloseUsb()
        time.sleep(0.5)


def restore_valid_rw(updater, image):
    print("Restoring to valid RW")
    common.connect_usb(updater)
    updater.SendSubcommand(hammerd_api.UpdateExtraCommand.StayInRO)
    transfer_rw(updater, image)
    updater.SendSubcommand(hammerd_api.UpdateExtraCommand.JumpToRW)
    time.sleep(2)
    updater.CloseUsb()
    time.sleep(0.5)
    # Jump to RW resets the base. Need to reconnect
    common.connect_usb(updater)
    assert updater.SendFirstPdu() is True, "Error sending first PDU"
    updater.SendDone()
    print("Current section after valid RW: %s" % updater.CurrentSection())
    assert updater.CurrentSection() == 1, "Running section should be 1 (RW)"
    common.sim_disconnect_connect(updater)


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


def init_tp_transfer(updater):
    updater.LoadTouchpadImage(b"\x00")
    assert updater.SendFirstPdu() is True, "Error sending first PDU"
    updater.SendDone()
    unlock_rw(updater)


def get_flash_protection(updater):
    pdu_resp = updater.GetFirstResponsePdu().contents
    return pdu_resp.flash_protection


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


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

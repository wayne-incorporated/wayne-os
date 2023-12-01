#!/usr/bin/env python3
# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Verify RO can remain in RO"""

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
    print("Current section before StayInRO cmd: %s" % updater.CurrentSection())
    assert updater.CurrentSection() == 1, "Running section should be 1 (RW)"

    # Jump to RO by resetting base
    updater.SendSubcommand(hammerd_api.UpdateExtraCommand.ImmediateReset)
    updater.CloseUsb()
    time.sleep(0.5)
    updater.TryConnectUsb()
    updater.SendSubcommand(hammerd_api.UpdateExtraCommand.StayInRO)
    # Keep DUT in RO for 10 sec to check that it stays in RO
    time.sleep(10)

    # Reconnect, in case RO still decided to jump
    updater.CloseUsb()
    updater.TryConnectUsb()

    # Need to SendFirstPdu again after sendig cmd because
    # CurrentSection reads from results of SendFirstPdu by checking the
    # writable offset. Non Zero writable offset means RO is running
    assert updater.SendFirstPdu() is True, "Error sending first PDU"
    updater.SendDone()
    print("Current section after StayInRO cmd: %s" % updater.CurrentSection())
    assert updater.CurrentSection() == 0, "Running section should be 0 (RO)"
    # Reset dut
    common.sim_disconnect_connect(updater)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

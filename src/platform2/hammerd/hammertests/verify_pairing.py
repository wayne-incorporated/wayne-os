#!/usr/bin/env python3
# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Verify pairing between base and lid

   During pairing, the base computes it's public key from base_private key
   and authenticator is derived from shared secret. For the lid to verify the
   challenge, it needs to check whether base_public corresponds to one of
   the previously seen bases, and that the returned authenticator matches.
"""

from __future__ import print_function


import ctypes
import sys
import time

import common
import hammerd_api  # pylint: disable=import-error

PAIRING_RUNS = 10
INJECTION_RUNS = 10
PUBLIC_KEY_SIZE = 32

# Before this test, please flash staff.bin using servo


def main(argv):
    if argv:
        sys.exit("Test takes no args!")
    updater = hammerd_api.FirmwareUpdater(
        common.BASE_VENDOR_ID, common.BASE_PRODUCT_ID, common.BASE_USB_PATH
    )
    public_key_first = (ctypes.c_ubyte * PUBLIC_KEY_SIZE)()
    # Load EC image.
    with open(common.IMAGE, "rb") as f:
        ec_image = f.read()
    updater.LoadEcImage(ec_image)

    common.disable_hammerd()

    print("Connect to base EC.")
    common.connect_usb(updater)
    print("EC information:")
    print("PDU Response: %s" % updater.GetFirstResponsePdu().contents)
    print("RO: %s" % updater.GetSectionVersion(hammerd_api.SectionName.RO))
    print("RW: %s" % updater.GetSectionVersion(hammerd_api.SectionName.RW))
    print("Current section : %s" % updater.CurrentSection())
    assert updater.CurrentSection() == 1, "Running section should be 1 (RW)"

    # Sends 'Need to inject entropy' message if base is new
    pair_manager = hammerd_api.PairManager()
    challenge_status = pair_manager.PairChallenge(
        updater.object, public_key_first
    )
    print("Challenge status: %d" % challenge_status)
    # assert challenge_status == 9, 'Need to inject the entropy'

    for iteratn in range(INJECTION_RUNS):
        print(
            "Jumping back to RO to inject entropy. Iteratn: %d" % (iteratn + 1)
        )
        updater.SendSubcommand(hammerd_api.UpdateExtraCommand.UnlockRollback)
        updater.SendSubcommand(hammerd_api.UpdateExtraCommand.ImmediateReset)
        updater.CloseUsb()
        time.sleep(0.5)
        updater.TryConnectUsb()
        updater.SendSubcommand(hammerd_api.UpdateExtraCommand.StayInRO)
        # Wait for RO to run, else SendFirstPdu() picks up RW
        time.sleep(1)
        # Verify that we're in RO
        assert updater.SendFirstPdu() is True, "Error sending first PDU"
        updater.SendDone()
        assert updater.CurrentSection() == 0, "Not in RO: Cannot inject entropy"

        print("Inject entropy and sys jump to RW")
        updater.InjectEntropyWithPayload(b"\x87" * hammerd_api.ENTROPY_SIZE)
        updater.SendSubcommand(hammerd_api.UpdateExtraCommand.ImmediateReset)
        updater.CloseUsb()
        time.sleep(0.5)
        common.connect_usb(updater)
        updater.SendSubcommand(hammerd_api.UpdateExtraCommand.JumpToRW)
        # Wait for RW to run
        time.sleep(1)
        updater.CloseUsb()
        time.sleep(0.5)
        # Jump to RW resets the base. Need to reconnect
        common.connect_usb(updater)
        print("PDU Response: %s" % updater.GetFirstResponsePdu().contents)

        # Check that RW is running
        assert updater.SendFirstPdu() is True, "Error sending first PDU"
        updater.SendDone()
        print(
            "Current running section after jumping to RW: %s"
            % updater.CurrentSection()
        )
        assert updater.CurrentSection() == 1, "Running section should be 1 (RW)"
        # Autheticator should match for each pairing run
        for i in range(PAIRING_RUNS):
            public_key = (ctypes.c_ubyte * PUBLIC_KEY_SIZE)()
            pair_manager = hammerd_api.PairManager()
            challenge_status = pair_manager.PairChallenge(
                updater.object, public_key
            )
            print("Challenge status: %d" % challenge_status)
            assert challenge_status == 0, "Pairing challenge failed!"
            if i == 0:
                same = True
                for j in range(0, PUBLIC_KEY_SIZE - 1):
                    if public_key_first[j] != public_key[j]:
                        same = False
                        assert (
                            not same
                        ), "The key did not change after entropy injection!"
                        public_key_first = public_key
            else:
                for j in range(0, PUBLIC_KEY_SIZE - 1):
                    assert public_key_first[j] == public_key[j], "Key changed!"

    # Reset the base
    common.sim_disconnect_connect(updater)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

st_flash
========

This is a tool for updating STM32-based touchpads using the STM IAP protocol.

Installation
------------

Build:

    emerge-${BOARD} st_flash

Install:

    cros deploy ${DUT_IP} st_flash


Usage
-----

To check the active firmware version, run

    st_flash --board=BOARD --fw_version

To update the firmware, run:

    st_flash --board=BOARD firmware.bin


Currently only the 'eve' board is supported.

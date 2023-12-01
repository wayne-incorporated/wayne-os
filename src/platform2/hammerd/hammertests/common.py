# -*- coding: utf-8 -*-
# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Common constant and device related information."""

from __future__ import print_function

import atexit
import os
import time
import subprocess

import hammerd_api  # pylint: disable=import-error


def cros_config(path, key):
    cmd = ["cros_config", path, key]
    return subprocess.check_output(cmd, encoding="utf-8")


# The root path of the hammertests.
ROOT_DIR = os.path.dirname(os.path.realpath(__file__))
IMAGE_DIR = os.path.join(ROOT_DIR, "images")

UDEV_RULES_PATH = "/lib/udev/rules.d/99-hammerd.rules"

BASE_TABLE = {
    "coachz": "zed",
    "poppy": "hammer",
    "soraka": "staff",
    "nocturne": "whiskers",
    "kodama": "magnemite",
    "krane": "masterball",
    "kakadu": "moonball",
    "katsu": "don",
    "homestar": "star",
    "wormdingler": "eel",
    "quackingstick": "duck",
}

BOARD_NAME = cros_config("/", "name")
BASE_NAME = BASE_TABLE[BOARD_NAME.rstrip()]

# Device-dependent information.
# Deprecated, new devices should use cros_config instead.
# (b/188625010)
if BASE_NAME == "staff":
    BASE_VENDOR_ID = 0x18D1
    BASE_PRODUCT_ID = 0x502B
    BASE_USB_PATH = "1-2"
    BASE_CONN_GPIO = "PP3300_DX_BASE"
    TP = "/lib/firmware/%s-touchpad.fw" % BASE_NAME
elif BASE_NAME == "whiskers":
    BASE_VENDOR_ID = 0x18D1
    BASE_PRODUCT_ID = 0x5030
    BASE_USB_PATH = "1-7"
    BASE_CONN_GPIO = "BASE_PWR_EN"
    TP = "/lib/firmware/%s-touchpad.fw" % BASE_NAME
elif BASE_NAME == "hammer":
    BASE_VENDOR_ID = 0x18D1
    BASE_PRODUCT_ID = 0x5022
    BASE_USB_PATH = "1-3"
    BASE_CONN_GPIO = "PP3300_DX_BASE"
    TP = "/lib/firmware/%s-touchpad.fw" % BASE_NAME
elif BASE_NAME == "magnemite":
    BASE_VENDOR_ID = 0x18D1
    BASE_PRODUCT_ID = 0x503D
    BASE_USB_PATH = "1-1.1"
    BASE_CONN_GPIO = "EN_PP3300_POGO"
    TP = "/lib/firmware/%s-touch.fw" % BASE_NAME
elif BASE_NAME == "masterball":
    BASE_VENDOR_ID = 0x18D1
    BASE_PRODUCT_ID = 0x503C
    BASE_USB_PATH = "1-1.1"
    BASE_CONN_GPIO = "EN_PP3300_POGO"
    TP = "/lib/firmware/%s-touch.fw" % BASE_NAME
elif BASE_NAME == "moonball":
    BASE_VENDOR_ID = 0x18D1
    BASE_PRODUCT_ID = 0x5044
    BASE_USB_PATH = "1-1.1"
    BASE_CONN_GPIO = "EN_PP3300_POGO"
    TP = "/lib/firmware/%s-touch.fw" % BASE_NAME
elif BASE_NAME == "zed":
    BASE_VENDOR_ID = 0x18D1
    BASE_PRODUCT_ID = 0x504C
    BASE_USB_PATH = "1-1.4"
    BASE_CONN_GPIO = "EN_BASE"
    TP = "/lib/firmware/%s-touch.fw" % BASE_NAME
elif BASE_NAME == "don":
    BASE_VENDOR_ID = 0x18D1
    BASE_PRODUCT_ID = 0x5050
    BASE_USB_PATH = "1-1.1"
    BASE_CONN_GPIO = "EN_PP3300_POGO"
    TP = "/lib/firmware/%s-touch.fw" % BASE_NAME
else:
    BASE_VENDOR_ID = int(cros_config("/detachable-base", "vendor-id"))
    BASE_PRODUCT_ID = int(cros_config("/detachable-base", "product-id"))
    BASE_USB_PATH = cros_config("/detachable-base", "usb-path")
    BASE_CONN_GPIO = None
    TP = os.path.join(
        "/lib/firmware/", cros_config("/detachable-base", "touch-image-name")
    )

# Status of flash protect.
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

# Path of testing image files.
IMAGE = os.path.join(IMAGE_DIR, "%s.bin" % BASE_NAME)
RW_DEV = os.path.join(IMAGE_DIR, "%s.dev" % BASE_NAME)
RW_CORRUPT_FIRST_BYTE = os.path.join(
    IMAGE_DIR, "%s_corrupt_first_byte.bin" % BASE_NAME
)
RW_CORRUPT_LAST_BYTE = os.path.join(
    IMAGE_DIR, "%s_corrupt_last_byte.bin" % BASE_NAME
)
RW_VALID = os.path.join(IMAGE_DIR, "%s.bin" % BASE_NAME)
OLDER_IMAGE = os.path.join(IMAGE_DIR, "%s_older.bin" % BASE_NAME)
NEWER_IMAGE = os.path.join(IMAGE_DIR, "%s.bin" % BASE_NAME)
# Image should not update RW
RB_LOWER = os.path.join(IMAGE_DIR, "%s.dev.rb0" % BASE_NAME)
# Initial DUT image
RB_INITIAL = os.path.join(IMAGE_DIR, "%s.dev.rb1" % BASE_NAME)
# Image should update RW and RB regions region
RB_HIGHER = os.path.join(IMAGE_DIR, "%s.dev.rb9" % BASE_NAME)


# Common function.
def connect_usb(updater):
    updater.TryConnectUsb()
    assert updater.SendFirstPdu() is True, "Error sending first PDU"
    updater.SendDone()


def sim_disconnect_connect(updater):
    print("Simulate hammer disconnect/ reconnect to reset base")
    if BASE_CONN_GPIO:
        subprocess.call(["ectool", "gpioset", BASE_CONN_GPIO, "0"])
        subprocess.call(["ectool", "gpioset", BASE_CONN_GPIO, "1"])
    else:
        subprocess.call(["ectool", "basestate", "detach"])
        subprocess.call(["ectool", "basestate", "attach"])
    updater.CloseUsb()
    # Need to give base time to be visible to lid
    time.sleep(3)


def disable_hammerd():
    print("Disabling hammerd")
    if os.path.ismount(UDEV_RULES_PATH):
        return
    subprocess.call(["mount", "--bind", "/dev/null", UDEV_RULES_PATH])
    subprocess.call(["initctl", "restart", "udev"])
    atexit.register(enable_hammerd)


def enable_hammerd():
    print("Enabling hammerd")
    subprocess.call(["umount", UDEV_RULES_PATH])
    subprocess.call(["initctl", "restart", "udev"])


def reset_stay_ro(updater):
    # Send immediate reset
    updater.SendSubcommand(hammerd_api.UpdateExtraCommand.ImmediateReset)
    updater.CloseUsb()
    # Wait for base to reappear and send StayInRO
    time.sleep(0.5)
    updater.TryConnectUsb()
    updater.SendSubcommand(hammerd_api.UpdateExtraCommand.StayInRO)
    updater.SendFirstPdu()
    updater.SendDone()
    # Wait to stay in RO
    time.sleep(5)
    print("Current section after StayInRO cmd: %s" % updater.CurrentSection())
    assert updater.CurrentSection() == 0, "Running section should be 0 (RO)"

#!/bin/sh -u
# Copyright 2020 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Load kernel modules.
modprobe wilco-ec wilco-charge-schedule wilco-charger

# Wait until udev rules will be applied to boot_on_ac and usb_charge files in
# /sys/bus/platform/devices/GOOG000C:00/ folder.
udevadm trigger --settle --subsystem-match=platform --attr-match=driver=wilco-ec

# Wait until udev rules will be applied to advanced_charging/* and peak_shift/*
# files in /sys/bus/platform/devices/GOOG000C:00/wilco-charge-schedule/ folder.
udevadm trigger --settle --subsystem-match=platform \
    --attr-match=driver=wilco-charge-schedule

# Wait until udev rules will be applied to charge_control_start_threshold,
# charge_control_end_threshold and charge_type files in
# /sys/class/power_supply/wilco-charger/ folder.
udevadm trigger --settle --subsystem-match=power_supply

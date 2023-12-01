#!/bin/bash
# Copyright 2021 The Chromium Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

LOCK_FILE=/run/lock/power_override/xhci_reset.lock

echo $$ > "${LOCK_FILE}"

readarray -t CONTROLLERS < <(find /sys/bus/pci/drivers/xhci_hcd/ -maxdepth 1 -type l -printf "%f\n")

for hcd in "${CONTROLLERS[@]}"; do
    echo "${hcd}" > /sys/bus/pci/drivers/xhci_hcd/unbind
done
for hcd in "${CONTROLLERS[@]}"; do
    echo "${hcd}" > /sys/bus/pci/drivers/xhci_hcd/bind
done

rm -f "${LOCK_FILE}"

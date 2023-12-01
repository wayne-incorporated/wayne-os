#!/bin/sh

# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

logger -t pci-rescan "wifi NIC disappeared from PCI"
metrics_client -e Platform.WiFiDisapppearedFromPCI 1 2

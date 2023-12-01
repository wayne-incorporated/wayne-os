// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/check.h>
#include <base/strings/stringprintf.h>

#include "diagnostics/cros_healthd/system/fake_pci_util.h"

namespace diagnostics {

std::string FakePciUtil::GetVendorName(uint16_t vendor_id) {
  return base::StringPrintf("Vendor:%04X", vendor_id);
}

std::string FakePciUtil::GetDeviceName(uint16_t vendor_id, uint16_t device_id) {
  return base::StringPrintf("Device:%04X", device_id);
}

}  // namespace diagnostics

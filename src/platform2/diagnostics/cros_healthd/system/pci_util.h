// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_SYSTEM_PCI_UTIL_H_
#define DIAGNOSTICS_CROS_HEALTHD_SYSTEM_PCI_UTIL_H_

#include <string>

namespace diagnostics {

// Interface for accessing the pci_util library.
class PciUtil {
 public:
  virtual ~PciUtil() = default;

  // Returns the vendor name according to |vendor_id|.
  virtual std::string GetVendorName(uint16_t vendor_id) = 0;
  // Returns the device name according to |vendor_id| and |device_id|.
  virtual std::string GetDeviceName(uint16_t vendor_id, uint16_t device_id) = 0;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_SYSTEM_PCI_UTIL_H_

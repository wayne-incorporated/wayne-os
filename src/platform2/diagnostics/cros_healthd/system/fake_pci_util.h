// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_SYSTEM_FAKE_PCI_UTIL_H_
#define DIAGNOSTICS_CROS_HEALTHD_SYSTEM_FAKE_PCI_UTIL_H_

#include <string>

#include "diagnostics/cros_healthd/system/pci_util.h"

namespace diagnostics {

class FakePciUtil : public PciUtil {
 public:
  FakePciUtil() = default;
  FakePciUtil(const FakePciUtil& oth) = default;
  FakePciUtil(FakePciUtil&& oth) = default;
  ~FakePciUtil() override = default;

  std::string GetVendorName(uint16_t vendor_id) override;
  std::string GetDeviceName(uint16_t vendor_id, uint16_t device_id) override;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_SYSTEM_FAKE_PCI_UTIL_H_

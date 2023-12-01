// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_SYSTEM_PCI_UTIL_IMPL_H_
#define DIAGNOSTICS_CROS_HEALTHD_SYSTEM_PCI_UTIL_IMPL_H_

#include <string>

#include "diagnostics/cros_healthd/system/pci_util.h"

extern "C" {
struct pci_access;
}

namespace diagnostics {

class PciUtilImpl : public PciUtil {
 public:
  PciUtilImpl();
  PciUtilImpl(const PciUtilImpl& oth) = delete;
  PciUtilImpl(PciUtilImpl&& oth) = delete;
  ~PciUtilImpl() override;

  std::string GetVendorName(uint16_t vendor_id) override;
  std::string GetDeviceName(uint16_t vendor_id, uint16_t device_id) override;

 private:
  struct pci_access* pacc_ = nullptr;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_SYSTEM_PCI_UTIL_IMPL_H_

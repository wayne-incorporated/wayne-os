// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TYPECD_CROS_CONFIG_UTIL_H_
#define TYPECD_CROS_CONFIG_UTIL_H_

#include <memory>

#include <chromeos-config/libcros_config/cros_config.h>

namespace typecd {

// CrosConfig wrapper which gets SKU related Type C information.
class CrosConfigUtil {
 public:
  CrosConfigUtil();
  CrosConfigUtil(const CrosConfigUtil&) = delete;
  CrosConfigUtil& operator=(const CrosConfigUtil&) = delete;

  // Returns whether the device only supports DP alternate mode, while still
  // requiring AP driven mode entry. This is hepful in situations where a
  // partner supports USB4 but the system itself doesn't, so we shouldn't enter
  // USB4 mode in such a case.
  bool APModeEntryDPOnly();

 private:
  std::unique_ptr<brillo::CrosConfig> config_;
};

}  // namespace typecd

#endif  // TYPECD_CROS_CONFIG_UTIL_H_

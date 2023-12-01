// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_CROS_EC_HELPER_STUB_H_
#define POWER_MANAGER_POWERD_SYSTEM_CROS_EC_HELPER_STUB_H_

#include <map>
#include <string>

#include "power_manager/powerd/system/cros_ec_helper_interface.h"

namespace power_manager::system {

class CrosEcHelperStub : public CrosEcHelperInterface {
 public:
  CrosEcHelperStub() = default;
  CrosEcHelperStub(const CrosEcHelperStub&) = delete;
  CrosEcHelperStub& operator=(const CrosEcHelperStub&) = delete;

  ~CrosEcHelperStub() override = default;

  // Implementation of EcHelperInterface.
  bool IsWakeAngleSupported() override;
  bool AllowWakeupAsTablet(bool enabled) override;

  bool IsWakeupAsTabletAllowed();

 private:
  bool wakeup_as_tablet_allowed_ = false;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_CROS_EC_HELPER_STUB_H_

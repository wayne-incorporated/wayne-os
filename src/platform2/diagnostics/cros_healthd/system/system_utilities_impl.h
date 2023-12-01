// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_SYSTEM_SYSTEM_UTILITIES_IMPL_H_
#define DIAGNOSTICS_CROS_HEALTHD_SYSTEM_SYSTEM_UTILITIES_IMPL_H_

#include <sys/utsname.h>

#include "diagnostics/cros_healthd/system/system_utilities.h"

namespace diagnostics {

// Production implementation of the SystemUtilities interface.
class SystemUtilitiesImpl final : public SystemUtilities {
 public:
  SystemUtilitiesImpl();
  SystemUtilitiesImpl(const SystemUtilitiesImpl&) = delete;
  SystemUtilitiesImpl& operator=(const SystemUtilitiesImpl&) = delete;
  ~SystemUtilitiesImpl() override;

  // SystemUtilities overrides:
  int Uname(struct utsname* buf) override;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_SYSTEM_SYSTEM_UTILITIES_IMPL_H_

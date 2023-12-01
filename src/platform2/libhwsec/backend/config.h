// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_CONFIG_H_
#define LIBHWSEC_BACKEND_CONFIG_H_

#include <string>

#include <brillo/secure_blob.h>

#include "libhwsec/status.h"
#include "libhwsec/structures/key.h"
#include "libhwsec/structures/operation_policy.h"

namespace hwsec {

// Config provide the functions to change settings and policies.
class Config {
 public:
  // Converts the operation |policy| setting to operation policy.
  virtual StatusOr<OperationPolicy> ToOperationPolicy(
      const OperationPolicySetting& policy) = 0;

  // Sets the |current_user| config.
  virtual Status SetCurrentUser(const std::string& current_user) = 0;

  // Is the current user had been set or not.
  virtual StatusOr<bool> IsCurrentUserSet() = 0;

  // Returns current boot mode if it is valid.
  // Some older boards are affected by a bug in AP firmware where PCR0 (boot
  // mode PCR) is extended on resume from S3 (rather than just on initial
  // boot), causing PCR0 to have an invalid/unexpected value (different from
  // the expected value immediately after a normal boot). So, this function is
  // also used for verifying that the boot mode of device is valid.
  virtual StatusOr<DeviceConfigSettings::BootModeSetting::Mode>
  GetCurrentBootMode() = 0;

 protected:
  Config() = default;
  ~Config() = default;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_CONFIG_H_

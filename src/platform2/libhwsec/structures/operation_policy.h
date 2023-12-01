// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_STRUCTURES_OPERATION_POLICY_H_
#define LIBHWSEC_STRUCTURES_OPERATION_POLICY_H_

#include "libhwsec/structures/device_config.h"
#include "libhwsec/structures/permission.h"

namespace hwsec {

// An operation will use this policy to verify the access.
struct OperationPolicy {
  DeviceConfigs device_configs;
  Permission permission;
};

// The relation between device config setting and permission is "AND".
// An operation needs to satisfy both conditions.
struct OperationPolicySetting {
  DeviceConfigSettings device_config_settings;
  Permission permission;
};

}  // namespace hwsec

#endif  // LIBHWSEC_STRUCTURES_OPERATION_POLICY_H_

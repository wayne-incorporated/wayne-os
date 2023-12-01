// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "permission_broker/deny_uninitialized_device_rule.h"

#include <libudev.h>

namespace permission_broker {

DenyUninitializedDeviceRule::DenyUninitializedDeviceRule()
    : Rule("DenyUninitializedDeviceRule") {}

Rule::Result DenyUninitializedDeviceRule::ProcessDevice(
    struct udev_device* device) {
  if (!udev_device_get_is_initialized(device))
    return DENY;
  return IGNORE;
}

}  // namespace permission_broker

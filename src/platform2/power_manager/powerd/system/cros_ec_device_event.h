// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_CROS_EC_DEVICE_EVENT_H_
#define POWER_MANAGER_POWERD_SYSTEM_CROS_EC_DEVICE_EVENT_H_

#include <chromeos/ec/ec_commands.h>

namespace power_manager::system {

// Enable device event in CrOS EC.
//
// event: Device event ID. See enum ec_device_event in ec_command.h.
// enable: true for enabling, false for disabling.
void EnableCrosEcDeviceEvent(enum ec_device_event event, bool enable);

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_CROS_EC_DEVICE_EVENT_H_

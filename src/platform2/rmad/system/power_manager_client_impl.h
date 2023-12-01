// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_SYSTEM_POWER_MANAGER_CLIENT_IMPL_H_
#define RMAD_SYSTEM_POWER_MANAGER_CLIENT_IMPL_H_

#include "rmad/system/power_manager_client.h"

#include <base/memory/scoped_refptr.h>
#include <dbus/bus.h>

namespace rmad {

class PowerManagerClientImpl : public PowerManagerClient {
 public:
  explicit PowerManagerClientImpl(const scoped_refptr<dbus::Bus>& bus);
  PowerManagerClientImpl(const PowerManagerClientImpl&) = delete;
  PowerManagerClientImpl& operator=(const PowerManagerClientImpl&) = delete;

  ~PowerManagerClientImpl() override = default;

  bool Restart() override;
  bool Shutdown() override;

 private:
  // Owned by external D-Bus bus.
  dbus::ObjectProxy* proxy_;
};

}  // namespace rmad

#endif  // RMAD_SYSTEM_POWER_MANAGER_CLIENT_IMPL_H_

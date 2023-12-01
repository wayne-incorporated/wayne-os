// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_SYSTEMD_UNIT_STARTER_H_
#define LOGIN_MANAGER_SYSTEMD_UNIT_STARTER_H_

#include <memory>
#include <string>
#include <vector>

#include "login_manager/init_daemon_controller.h"

namespace base {
class TimeDelta;
}
namespace dbus {
class ObjectProxy;
class ScopedDBusError;
}

namespace login_manager {

class SystemdUnitStarter : public InitDaemonController {
 public:
  static const char kServiceName[];
  static const char kPath[];

  explicit SystemdUnitStarter(dbus::ObjectProxy* proxy);
  SystemdUnitStarter(const SystemdUnitStarter&) = delete;
  SystemdUnitStarter& operator=(const SystemdUnitStarter&) = delete;

  ~SystemdUnitStarter() override;

  // InitDaemonController:
  std::unique_ptr<dbus::Response> TriggerImpulse(
      const std::string& unit_name,
      const std::vector<std::string>& args_keyvals,
      TriggerMode mode) override;

  std::unique_ptr<dbus::Response> TriggerImpulseWithTimeoutAndError(
      const std::string& unit_name,
      const std::vector<std::string>& args_keyvals,
      TriggerMode mode,
      base::TimeDelta timeout,
      dbus::ScopedDBusError* error) override;

 private:
  dbus::ObjectProxy* systemd_dbus_proxy_;  // Weak, owned by caller.
};

}  // namespace login_manager

#endif  // LOGIN_MANAGER_SYSTEMD_UNIT_STARTER_H_

// Copyright 2010 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_UPSTART_SIGNAL_EMITTER_H_
#define LOGIN_MANAGER_UPSTART_SIGNAL_EMITTER_H_

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

// Simple mockable class for emitting Upstart signals.
class UpstartSignalEmitter : public InitDaemonController {
 public:
  static const char kServiceName[];
  static const char kPath[];

  explicit UpstartSignalEmitter(dbus::ObjectProxy* proxy);
  UpstartSignalEmitter(const UpstartSignalEmitter&) = delete;
  UpstartSignalEmitter& operator=(const UpstartSignalEmitter&) = delete;

  ~UpstartSignalEmitter() override;

  // InitDaemonController:

  // Emits an upstart signal.  |args_keyvals| will be provided as
  // environment variables to any upstart jobs kicked off as a result
  // of the signal. Each element of |args_keyvals| is a string of the format
  // "key=value".
  //
  // Returns null if emitting the signal fails or if |mode| is ASYNC.
  std::unique_ptr<dbus::Response> TriggerImpulse(
      const std::string& name,
      const std::vector<std::string>& args_keyvals,
      TriggerMode mode) override;

  // Emits an upstart signal with a |timeout|.  |args_keyvals| will be
  // provided as environment variables to any upstart jobs kicked off as a
  // result of the signal. Each element of |args_keyvals| is a string of the
  // format "key=value".
  //
  // Returns null if emitting the signal fails or if |mode| is ASYNC.
  // Also returns an error code in case of error.
  std::unique_ptr<dbus::Response> TriggerImpulseWithTimeoutAndError(
      const std::string& name,
      const std::vector<std::string>& args_keyvals,
      TriggerMode mode,
      base::TimeDelta timeout,
      dbus::ScopedDBusError* error) override;

 private:
  dbus::ObjectProxy* upstart_dbus_proxy_;  // Weak, owned by caller.
};

}  // namespace login_manager

#endif  // LOGIN_MANAGER_UPSTART_SIGNAL_EMITTER_H_

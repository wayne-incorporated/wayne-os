// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_INIT_DAEMON_CONTROLLER_H_
#define LOGIN_MANAGER_INIT_DAEMON_CONTROLLER_H_

#include <memory>
#include <string>
#include <vector>

namespace dbus {
class Response;
class ScopedDBusError;
}

namespace base {
class TimeDelta;
}

namespace login_manager {

class InitDaemonController {
 public:
  // Different triggering modes.
  enum class TriggerMode {
    // Wait for the impulse to be fully processed before returning. Triggering
    // a SYNC impulse may block on dependent init jobs. Always prefer ASYNC over
    // SYNC unless your code actually needs the synchronous behavior.
    // TODO(yusukes): Get rid of SYNC once ARC stops using it.
    SYNC,
    // Asynchronously trigger the impulse.
    ASYNC,
  };

  virtual ~InitDaemonController() = default;

  // Asks the init daemon to emit a signal (Upstart) or start a unit (systemd).
  // The response is null if the request failed or |mode| is ASYNC.
  virtual std::unique_ptr<dbus::Response> TriggerImpulse(
      const std::string& name,
      const std::vector<std::string>& args_keyvals,
      TriggerMode mode) = 0;

  // Asks the init daemon to emit a signal (Upstart) or start a unit (systemd)
  // with a |timeout| and |error|. The response is null if the request failed
  // or |mode| is ASYNC.
  virtual std::unique_ptr<dbus::Response> TriggerImpulseWithTimeoutAndError(
      const std::string& name,
      const std::vector<std::string>& args_keyvals,
      TriggerMode mode,
      base::TimeDelta timeout,
      dbus::ScopedDBusError* error) = 0;
};

}  // namespace login_manager

#endif  // LOGIN_MANAGER_INIT_DAEMON_CONTROLLER_H_

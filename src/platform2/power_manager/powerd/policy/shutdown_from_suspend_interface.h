// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_POLICY_SHUTDOWN_FROM_SUSPEND_INTERFACE_H_
#define POWER_MANAGER_POWERD_POLICY_SHUTDOWN_FROM_SUSPEND_INTERFACE_H_

namespace power_manager::policy {

// Holds the logic to shut down or hibernate the device after prolonged non
// use.
//
// Responsible for setting an alarm for |kLowerPowerFromSuspendSecPref| before
// every suspend if one is not already running.
// On dark resume this code will shut down or hibernate the device instead
// of re-suspending if all of the following conditions hold true:
//   1. Device has spent |kLowerPowerFromSuspendSecPref| in suspend or in
//      dark resume without a full resume, OR the battery is below
//      |kLowBatteryShutdownPercentPref|.
//   2. Device is not connected to line power.
// On full resume, the alarm is stopped and the state is reset.
class ShutdownFromSuspendInterface {
 public:
  enum class Action {
    // Suspend the system.
    SUSPEND = 0,
    // Hibernate the system.
    HIBERNATE,
    // Shut the system down immediately.
    SHUT_DOWN,
  };
  ShutdownFromSuspendInterface() = default;
  virtual ~ShutdownFromSuspendInterface() = default;

  // Updates state in anticipation of the system suspending, returning the
  // action that should be performed.
  virtual Action PrepareForSuspendAttempt() = 0;
  // Called when device does a dark resume.
  virtual void HandleDarkResume() = 0;
  // Called when device does a full resume or on transitions from dark resume to
  // full resume.
  virtual void HandleFullResume() = 0;
};

}  // namespace power_manager::policy

#endif  // POWER_MANAGER_POWERD_POLICY_SHUTDOWN_FROM_SUSPEND_INTERFACE_H_

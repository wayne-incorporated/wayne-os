// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_POLICY_SHUTDOWN_FROM_SUSPEND_H_
#define POWER_MANAGER_POWERD_POLICY_SHUTDOWN_FROM_SUSPEND_H_

#include "power_manager/powerd/policy/shutdown_from_suspend_interface.h"
#include "power_manager/powerd/system/suspend_configurator.h"
#include "power_manager/powerd/system/wakeup_timer.h"

#include <memory>

#include <base/time/time.h>
#include <brillo/timers/alarm_timer.h>

namespace power_manager {

class PrefsInterface;

namespace system {

class PowerSupplyInterface;

}  // namespace system

namespace policy {

class ShutdownFromSuspend : public ShutdownFromSuspendInterface {
 public:
  ShutdownFromSuspend();
  ShutdownFromSuspend(const ShutdownFromSuspend&) = delete;
  ShutdownFromSuspend& operator=(const ShutdownFromSuspend&) = delete;
  ~ShutdownFromSuspend() override;

  void Init(PrefsInterface* prefs,
            system::PowerSupplyInterface* power_supply,
            system::SuspendConfiguratorInterface* suspend_configurator);

  bool enabled_for_testing() const { return global_enabled_; }
  bool hibernate_enabled_for_testing() const { return hibernate_enabled_; }

  // ShutdownFromSuspendInterface implementation.
  Action PrepareForSuspendAttempt() override;
  void HandleDarkResume() override;
  void HandleFullResume() override;

 private:
  explicit ShutdownFromSuspend(
      std::unique_ptr<power_manager::system::WakeupTimer> alarm_timer);

  friend class ShutdownFromSuspendTest;

  // Invoked by |alarm_timer_| after spending |shutdown_delay_| in suspend.
  void OnTimerWake();

  // Helper function to determine if the battery is below a certain threshold.
  bool IsBatteryLow();
  // Called to decide whether or not we should hibernate right now.
  bool ShouldHibernate();
  // Called to decide whether or not to shut down right now.
  bool ShouldShutdown();

  // Is shutdown or hibernate after x enabled ?
  bool global_enabled_ = false;
  // Is hibernate after x enabled ?
  bool hibernate_enabled_ = false;
  // Time in suspend after which the device wakes up to shut down.
  base::TimeDelta shutdown_delay_;
  // Is the device in dark resume currently ?
  bool in_dark_resume_ = false;
  // Has |alarm_timer_| fired since last full resume.
  bool timer_fired_ = false;
  // Timer to wake the system from suspend after |shutdown_delay_|.
  std::unique_ptr<power_manager::system::WakeupTimer> alarm_timer_;

  system::PowerSupplyInterface* power_supply_ = nullptr;  // weak

  double low_battery_shutdown_percent_ = 0.0;
};

}  // namespace policy
}  // namespace power_manager

#endif  // POWER_MANAGER_POWERD_POLICY_SHUTDOWN_FROM_SUSPEND_H_

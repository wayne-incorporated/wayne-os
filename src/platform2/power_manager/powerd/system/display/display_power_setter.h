// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_DISPLAY_DISPLAY_POWER_SETTER_H_
#define POWER_MANAGER_POWERD_SYSTEM_DISPLAY_DISPLAY_POWER_SETTER_H_

#include <base/compiler_specific.h>
#include <base/time/time.h>
#include <base/timer/timer.h>
#include <chromeos/dbus/service_constants.h>

namespace dbus {
class ObjectProxy;
}  // namespace dbus

namespace power_manager::system {

class DBusWrapperInterface;

// Interface for turning displays on and off.
class DisplayPowerSetterInterface {
 public:
  DisplayPowerSetterInterface() = default;
  DisplayPowerSetterInterface(const DisplayPowerSetterInterface&) = delete;
  DisplayPowerSetterInterface& operator=(const DisplayPowerSetterInterface&) =
      delete;

  virtual ~DisplayPowerSetterInterface() = default;

  // Configures displays to use |state| after |delay|. If another change has
  // already been scheduled, it will be aborted. If |delay| is zero, the change
  // will be applied synchronously.
  virtual void SetDisplayPower(chromeos::DisplayPowerState state,
                               base::TimeDelta delay) = 0;

  // Tells DisplayService to simulate the display being dimmed or undimmed in
  // software.  This is used as a substitute for actually changing the
  // display's brightness in some cases, e.g. for external displays.
  virtual void SetDisplaySoftwareDimming(bool dimmed) = 0;
};

// Real DisplayPowerSetterInterface implementation that makes D-Bus method
// calls to DisplayService.
class DisplayPowerSetter : public DisplayPowerSetterInterface {
 public:
  DisplayPowerSetter() = default;
  DisplayPowerSetter(const DisplayPowerSetter&) = delete;
  DisplayPowerSetter& operator=(const DisplayPowerSetter&) = delete;

  ~DisplayPowerSetter() override = default;

  // Ownership of |dbus_wrapper| remains with the caller.
  void Init(DBusWrapperInterface* dbus_wrapper);

  // DisplayPowerSetterInterface implementation:
  void SetDisplayPower(chromeos::DisplayPowerState state,
                       base::TimeDelta delay) override;
  void SetDisplaySoftwareDimming(bool dimmed) override;

  void FireTimerForTesting();

 private:
  // Makes an asynchronous D-Bus method call to DisplayService to apply |state|.
  void SendStateToDisplayService(chromeos::DisplayPowerState state);

  // Runs SendStateToDisplayService().
  base::OneShotTimer timer_;

  DBusWrapperInterface* dbus_wrapper_ = nullptr;        // weak
  dbus::ObjectProxy* display_service_proxy_ = nullptr;  // non-owned
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_DISPLAY_DISPLAY_POWER_SETTER_H_

// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_USER_PROXIMITY_OBSERVER_H_
#define POWER_MANAGER_POWERD_SYSTEM_USER_PROXIMITY_OBSERVER_H_

#include <base/observer_list_types.h>

#include "power_manager/common/power_constants.h"

namespace power_manager::system {

// Interface for classes interested in observing events announced by any
// kind of user proximity sensor (i.e. any piece of hardware, software or mix
// thereof that is capable of providing a signal as to whether a human user
// is physically in close proximity to the device).
class UserProximityObserver : public base::CheckedObserver {
 public:
  // Defines which subsystem(s) a sensor can provide proximity data for.
  enum SensorRole {
    SENSOR_ROLE_NONE = 0,
    SENSOR_ROLE_WIFI = 1u << 0,
    SENSOR_ROLE_LTE = 1u << 1,
  };

  UserProximityObserver() = default;
  ~UserProximityObserver() override = default;

  // Called when a new proximity sensor is detected. |id| is a unique key
  // that will be used to identify this sensor in all future events; |roles|
  // represents a bitwise combination of SensorRole values.
  virtual void OnNewSensor(int id, uint32_t roles) = 0;

  // Called when a proximity sensor has new information to provide.
  virtual void OnProximityEvent(int id, UserProximity value) = 0;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_USER_PROXIMITY_OBSERVER_H_

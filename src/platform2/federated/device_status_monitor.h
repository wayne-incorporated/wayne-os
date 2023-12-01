// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FEDERATED_DEVICE_STATUS_MONITOR_H_
#define FEDERATED_DEVICE_STATUS_MONITOR_H_

#include <base/sequence_checker.h>
#include <memory>
#include <vector>

#include "federated/training_condition.h"

namespace dbus {
class Bus;
}  // namespace dbus

namespace federated {

// Monitors the device status and answers whether a federated computation task
// should start or early stop.
class DeviceStatusMonitor {
 public:
  explicit DeviceStatusMonitor(
      std::vector<std::unique_ptr<TrainingCondition>> training_conditions);
  DeviceStatusMonitor(const DeviceStatusMonitor&) = delete;
  DeviceStatusMonitor& operator=(const DeviceStatusMonitor&) = delete;
  ~DeviceStatusMonitor() = default;

  // A builder functions that construct DeviceStatusMonitor from dbus
  static std::unique_ptr<DeviceStatusMonitor> CreateFromDBus(dbus::Bus* bus);

  // Called before training to see if the device is in a good condition, and
  // during the training to see if the training should be aborted.
  bool TrainingConditionsSatisfied() const;

 private:
  const std::vector<std::unique_ptr<TrainingCondition>> training_conditions_;
  SEQUENCE_CHECKER(sequence_checker_);
};

}  // namespace federated

#endif  // FEDERATED_DEVICE_STATUS_MONITOR_H_

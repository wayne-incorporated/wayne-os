// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FEDERATED_POWER_SUPPLY_TRAINING_CONDITION_H_
#define FEDERATED_POWER_SUPPLY_TRAINING_CONDITION_H_

#include <base/memory/weak_ptr.h>
#include <base/sequence_checker.h>

#include "federated/training_condition.h"

namespace dbus {
class ObjectProxy;
class Signal;
class Bus;
}  // namespace dbus

namespace federated {

// Monitors the dpower supply status and answers whether there the conditions
// are satisfied. Currently, we check that the battery level is above 90% or
// the device is not discharging.
class PowerSupplyTrainingCondition : public TrainingCondition {
 public:
  explicit PowerSupplyTrainingCondition(dbus::Bus* bus);
  PowerSupplyTrainingCondition(const PowerSupplyTrainingCondition&) = delete;
  PowerSupplyTrainingCondition& operator=(const PowerSupplyTrainingCondition&) =
      delete;
  ~PowerSupplyTrainingCondition() override = default;

  // TrainingCondition:
  [[nodiscard]] bool IsTrainingConditionSatisfied() const override;

 private:
  // Called before training to see if the device is in a good condition, and
  // during the training to see if the training should be aborted.
  void OnPowerSupplyReceived(dbus::Signal* signal);

  // Obtained from dbus, should never delete it.
  dbus::ObjectProxy* const powerd_dbus_proxy_;

  // Whether the device has enough battery for a federated computation task.
  // Updated in `OnPowerSupplyReceived` and used in
  // `TrainingConditionsSatisfied`.
  bool enough_battery_;

  const base::WeakPtrFactory<PowerSupplyTrainingCondition> weak_ptr_factory_;

  SEQUENCE_CHECKER(sequence_checker_);
};

}  // namespace federated

#endif  // FEDERATED_POWER_SUPPLY_TRAINING_CONDITION_H_

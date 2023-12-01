// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HERMES_MANAGER_H_
#define HERMES_MANAGER_H_

#include <map>
#include <memory>
#include <optional>

#include "hermes/context.h"
#include "hermes/dbus_bindings/org.chromium.Hermes.Manager.h"
#include "hermes/euicc.h"
#include "hermes/euicc_manager_interface.h"

namespace hermes {

class Manager final : public EuiccManagerInterface {
 public:
  Manager();
  Manager(const Manager&) = delete;
  Manager& operator=(const Manager&) = delete;

  // EuiccManagerInterface overrides.
  void OnEuiccUpdated(uint8_t physical_slot, EuiccSlotInfo slot_info) override;
  void OnEuiccRemoved(uint8_t physical_slot) override;
  void OnLogicalSlotUpdated(uint8_t physical_slot,
                            std::optional<uint8_t> logical_slot) override;

 private:
  void UpdateAvailableEuiccsProperty();

  Context* context_;
  std::unique_ptr<ManagerAdaptorInterface> dbus_adaptor_;

  // Map of physical SIM slot -> Euicc.
  std::map<uint8_t, std::unique_ptr<Euicc>> available_euiccs_;
};

}  // namespace hermes

#endif  // HERMES_MANAGER_H_

// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HERMES_FAKE_EUICC_MANAGER_H_
#define HERMES_FAKE_EUICC_MANAGER_H_

#include <map>
#include <optional>
#include <utility>

#include <base/logging.h>
#include <gmock/gmock.h>

#include "hermes/euicc_manager_interface.h"

namespace hermes {

class FakeEuiccManager : public EuiccManagerInterface {
 public:
  using SlotMap = std::map<uint8_t, EuiccSlotInfo>;

  const SlotMap& valid_slots() const { return valid_slots_; }

  // EuiccManagerInterface overrides.
  MOCK_METHOD(void,
              OnEuiccUpdated,
              (uint8_t physical_slot, EuiccSlotInfo slot_info),
              (override));
  void OnEuiccRemoved(uint8_t physical_slot) override {
    valid_slots_.erase(physical_slot);
  }
  void OnLogicalSlotUpdated(uint8_t physical_slot,
                            std::optional<uint8_t> logical_slot) override {
    auto iter = valid_slots_.find(physical_slot);
    if (iter == valid_slots_.end()) {
      VLOG(2) << "Ignoring logical slot change for non-eUICC physical slot:"
              << physical_slot;
      return;
    }

    iter->second.SetLogicalSlot(std::move(logical_slot));
  };
  FakeEuiccManager() {
    ON_CALL(*this, OnEuiccUpdated)
        .WillByDefault(
            testing::Invoke(this, &FakeEuiccManager::FakeOnEuiccUpdated));
  }

 private:
  void FakeOnEuiccUpdated(uint8_t physical_slot, EuiccSlotInfo slot_info) {
    valid_slots_.insert(std::make_pair(physical_slot, std::move(slot_info)));
  }

  // Map of physical slot number -> eUICC slot info.
  SlotMap valid_slots_;
};

}  // namespace hermes

#endif  // HERMES_FAKE_EUICC_MANAGER_H_

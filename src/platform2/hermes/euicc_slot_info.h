// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HERMES_EUICC_SLOT_INFO_H_
#define HERMES_EUICC_SLOT_INFO_H_

#include <optional>
#include <string>
#include <utility>

#include <base/check.h>

#include "hermes/hermes_common.h"

namespace hermes {

// Information used to inform an EuiccManagerInterface about an eUICC slot, and
// to create & update Euicc instances.
class EuiccSlotInfo {
 public:
  explicit EuiccSlotInfo(std::string eid)
      : eid_(std::move(eid)), logical_slot_(std::nullopt) {}
  explicit EuiccSlotInfo(uint8_t logical_slot, std::string eid)
      : eid_(std::move(eid)), logical_slot_(logical_slot) {}

  void SetLogicalSlot(std::optional<uint8_t> logical_slot) {
    logical_slot_ = std::move(logical_slot);
  }
  bool IsActive() const { return logical_slot_.has_value(); }
  const std::string& eid() const { return eid_; }
  const std::optional<uint8_t>& logical_slot() const { return logical_slot_; }
  bool operator==(const EuiccSlotInfo& rhs) const {
    return logical_slot_ == rhs.logical_slot_ && eid_ == rhs.eid_;
  }

  std::string eid_;

 private:
  std::optional<uint8_t> logical_slot_;
};

}  // namespace hermes

#endif  // HERMES_EUICC_SLOT_INFO_H_

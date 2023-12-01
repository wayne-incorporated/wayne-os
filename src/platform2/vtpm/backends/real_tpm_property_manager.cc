// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vtpm/backends/real_tpm_property_manager.h"

#include <algorithm>
#include <vector>

#include <base/check_op.h>
#include <trunks/tpm_generated.h>

namespace vtpm {

namespace {

constexpr trunks::TPMS_TAGGED_PROPERTY kTpmTaggeProperties[] = {
    {trunks::TPM_PT_FAMILY_INDICATOR, 0},
    {trunks::TPM_PT_LEVEL, 0},
    {trunks::TPM_PT_REVISION, 99},
    {trunks::TPM_PT_DAY_OF_YEAR, 273},
    {trunks::TPM_PT_YEAR, 2013},
    // 0x43524f53 is `CROS`.
    {trunks::TPM_PT_MANUFACTURER, 0x43524f53},
    {trunks::TPM_PT_VENDOR_STRING_1, 0},
    {trunks::TPM_PT_VENDOR_STRING_2, 0},
    {trunks::TPM_PT_VENDOR_STRING_3, 0},
    {trunks::TPM_PT_VENDOR_STRING_4, 0},
    {trunks::TPM_PT_VENDOR_TPM_TYPE, 0},
    {trunks::TPM_PT_FIRMWARE_VERSION_1, 0},
    {trunks::TPM_PT_FIRMWARE_VERSION_2, 0},
    {trunks::TPM_PT_INPUT_BUFFER, 1024},
    {trunks::TPM_PT_HR_TRANSIENT_MIN, 3},
    {trunks::TPM_PT_HR_PERSISTENT_MIN, 2},
    {trunks::TPM_PT_HR_LOADED_MIN, 3},
    {trunks::TPM_PT_ACTIVE_SESSIONS_MAX, 64},
    {trunks::TPM_PT_PCR_COUNT, 0},
    {trunks::TPM_PT_PCR_SELECT_MIN, 0},
    {trunks::TPM_PT_CONTEXT_GAP_MAX, 65535},
    {trunks::TPM_PT_NV_COUNTERS_MAX, 0},
    {trunks::TPM_PT_NV_INDEX_MAX, 2048},
    {trunks::TPM_PT_MEMORY, 6},
    {trunks::TPM_PT_CLOCK_UPDATE, 4096},
    {trunks::TPM_PT_CONTEXT_HASH, 11},
    {trunks::TPM_PT_CONTEXT_SYM, 6},
    {trunks::TPM_PT_CONTEXT_SYM_SIZE, 256},
    {trunks::TPM_PT_ORDERLY_COUNT, 255},
    {trunks::TPM_PT_MAX_COMMAND_SIZE, 32768},
    {trunks::TPM_PT_MAX_RESPONSE_SIZE, 32768},
    {trunks::TPM_PT_MAX_DIGEST, 64},
    {trunks::TPM_PT_MAX_OBJECT_CONTEXT, 1600},
    {trunks::TPM_PT_MAX_SESSION_CONTEXT, 372},
    {trunks::TPM_PT_PS_FAMILY_INDICATOR, 0},
    {trunks::TPM_PT_PS_LEVEL, 0},
    {trunks::TPM_PT_PS_REVISION, 0},
    {trunks::TPM_PT_PS_DAY_OF_YEAR, 0},
    {trunks::TPM_PT_PS_YEAR, 0},
    {trunks::TPM_PT_SPLIT_MAX, 128},
    {trunks::TPM_PT_TOTAL_COMMANDS, 0},
    {trunks::TPM_PT_LIBRARY_COMMANDS, 0},
    {trunks::TPM_PT_VENDOR_COMMANDS, 0},
    {trunks::TPM_PT_NV_BUFFER_MAX, MAX_NV_BUFFER_SIZE},
    {trunks::TPM_PT_PERMANENT, 0x111},
    {trunks::TPM_PT_STARTUP_CLEAR, 2147483662},
    {trunks::TPM_PT_HR_NV_INDEX, 1},
    {trunks::TPM_PT_NV_COUNTERS, 0},
    {trunks::TPM_PT_NV_COUNTERS_AVAIL, 32},
    {trunks::TPM_PT_LOCKOUT_COUNTER, 0},
    {trunks::TPM_PT_MAX_AUTH_FAIL, 200},
    {trunks::TPM_PT_LOCKOUT_INTERVAL, 0},
    {trunks::TPM_PT_LOCKOUT_RECOVERY, 0},
    {trunks::TPM_PT_NV_WRITE_RECOVERY, 0},
    {trunks::TPM_PT_AUDIT_COUNTER_0, 0},
    {trunks::TPM_PT_AUDIT_COUNTER_1, 0},
};

constexpr bool IsPropertyListSorted() {
  trunks::TPM_PT prev = 0;
  for (const auto& p : kTpmTaggeProperties) {
    if (p.property < prev) {
      return false;
    }
    prev = p.property;
  }
  return true;
}

static_assert(IsPropertyListSorted(), "propery list is not sorted.");

}  // namespace

RealTpmPropertyManager::RealTpmPropertyManager()
    : capability_properties_(std::begin(kTpmTaggeProperties),
                             std::end(kTpmTaggeProperties)) {}

void RealTpmPropertyManager::AddCommand(trunks::TPM_CC cc) {
  commands_.emplace_back(cc);
  commands_is_sorted_ = false;
  is_total_commands_updated_ = false;
}

const std::vector<trunks::TPM_CC>& RealTpmPropertyManager::GetCommandList() {
  if (!commands_is_sorted_) {
    std::sort(commands_.begin(), commands_.end());
    commands_.erase(std::unique(commands_.begin(), commands_.end()),
                    commands_.end());
    commands_is_sorted_ = true;
  }
  return commands_;
}

const std::vector<trunks::TPMS_TAGGED_PROPERTY>&
RealTpmPropertyManager::GetCapabilityPropertyList() {
  if (!is_total_commands_updated_) {
    auto iter = std::lower_bound(
        capability_properties_.begin(), capability_properties_.end(),
        trunks::TPM_PT_TOTAL_COMMANDS,
        [](const trunks::TPMS_TAGGED_PROPERTY& a, trunks::TPM_PT b) -> bool {
          return a.property < b;
        });
    CHECK_NE(std::distance(capability_properties_.begin(), iter),
             std::distance(capability_properties_.begin(),
                           capability_properties_.end()));
    iter->value = commands_.size();
    is_total_commands_updated_ = true;
  }
  return capability_properties_;
}

}  // namespace vtpm

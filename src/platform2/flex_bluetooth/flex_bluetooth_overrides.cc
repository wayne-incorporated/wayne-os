// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "flex_bluetooth/flex_bluetooth_overrides.h"

#include <limits>

#include <base/logging.h>
#include <base/strings/string_number_conversions.h>

namespace flex_bluetooth {

FlexBluetoothOverrides::FlexBluetoothOverrides(
    const base::FilePath& sysprop_override_path,
    const std::map<BluetoothAdapter, std::unordered_set<SyspropOverride>>&
        adapter_sysprop_overrides)
    : sysprop_override_path_(sysprop_override_path),
      adapter_sysprop_overrides_(adapter_sysprop_overrides) {}

void FlexBluetoothOverrides::ProcessOverridesForVidPid(
    const uint16_t idVendor, const uint16_t idProduct) const {
  const auto sysprop_overrides =
      GetAdapterSyspropOverridesForVidPid(idVendor, idProduct);

  base::WriteFile(sysprop_override_path_, kSyspropsLine);
  for (const SyspropOverride& ov : sysprop_overrides) {
    if (kSyspropOverrideToString.count(ov) == 0) {
      LOG(WARNING) << "Did not find an override string for override "
                   << static_cast<int>(ov);
    } else {
      base::AppendToFile(sysprop_override_path_,
                         kSyspropOverrideToString.at(ov));
    }
  }
}

void FlexBluetoothOverrides::RemoveOverrides() const {
  // Remove any existing overrides by overwriting the file
  base::WriteFile(sysprop_override_path_, "");
}

std::unordered_set<SyspropOverride>
FlexBluetoothOverrides::GetAdapterSyspropOverridesForVidPid(
    const uint16_t id_vendor, const uint16_t id_product) const {
  BluetoothAdapter adapter{.id_vendor_ = id_vendor, .id_product_ = id_product};
  const auto overrides_entry = adapter_sysprop_overrides_.find(adapter);
  return overrides_entry != adapter_sysprop_overrides_.end()
             ? overrides_entry->second
             : std::unordered_set<SyspropOverride>();
}

bool HexStringToUInt16(const std::string& str, uint16_t* out) {
  uint32_t converted_value;
  if (!base::HexStringToUInt(str, &converted_value)) {
    return false;
  }

  if (converted_value > std::numeric_limits<uint16_t>::max()) {
    return false;
  }

  *out = converted_value;
  return true;
}

}  // namespace flex_bluetooth

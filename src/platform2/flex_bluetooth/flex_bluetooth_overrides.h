// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FLEX_BLUETOOTH_FLEX_BLUETOOTH_OVERRIDES_H_
#define FLEX_BLUETOOTH_FLEX_BLUETOOTH_OVERRIDES_H_

#include <map>
#include <string>
#include <unordered_set>

#include <base/files/file_util.h>

namespace flex_bluetooth {

enum class SyspropOverride {
  kDisableLEGetVendorCapabilities = 0,
};

const char kSyspropsLine[] = "[Sysprops]\n";

const std::map<SyspropOverride, std::string> kSyspropOverrideToString = {
    {SyspropOverride::kDisableLEGetVendorCapabilities,
     "bluetooth.core.le.vendor_capabilities.enabled=false\n"}};

class BluetoothAdapter {
 public:
  bool operator<(const BluetoothAdapter& rhs) const {
    return id_vendor_ < rhs.id_vendor_ ||
           (id_vendor_ == rhs.id_vendor_ && id_product_ < rhs.id_product_);
  }
  const uint16_t id_vendor_;
  const uint16_t id_product_;
};

class FlexBluetoothOverrides {
 public:
  explicit FlexBluetoothOverrides(
      const base::FilePath& sysprop_override_path,
      const std::map<BluetoothAdapter, std::unordered_set<SyspropOverride>>&
          adapter_sysprop_overrides);

  std::unordered_set<SyspropOverride> GetAdapterSyspropOverridesForVidPid(
      const uint16_t id_vendor, const uint16_t id_product) const;

  void ProcessOverridesForVidPid(const uint16_t id_vendor,
                                 const uint16_t id_product) const;
  void RemoveOverrides() const;

 private:
  const base::FilePath sysprop_override_path_;
  const std::map<BluetoothAdapter, std::unordered_set<SyspropOverride>>
      adapter_sysprop_overrides_;
};

bool HexStringToUInt16(const std::string& str, uint16_t* out);

}  // namespace flex_bluetooth

#endif  // FLEX_BLUETOOTH_FLEX_BLUETOOTH_OVERRIDES_H_

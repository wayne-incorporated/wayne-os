// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "modemfwd/firmware_directory.h"

#include <memory>
#include <utility>

#include <base/files/file_path.h>
#include <base/logging.h>
#include <cros_config/cros_config.h>

#include "modemfwd/firmware_manifest.h"
#include "modemfwd/logging.h"

namespace modemfwd {

const char FirmwareDirectory::kGenericCarrierId[] = "generic";

class FirmwareDirectoryImpl : public FirmwareDirectory {
 public:
  FirmwareDirectoryImpl(std::unique_ptr<FirmwareIndex> index,
                        const base::FilePath& fw_manifest_directory,
                        std::string variant)
      : index_(std::move(index)),
        fw_manifest_directory_(fw_manifest_directory),
        variant_(variant) {}
  FirmwareDirectoryImpl(const FirmwareDirectoryImpl&) = delete;
  FirmwareDirectoryImpl& operator=(const FirmwareDirectoryImpl&) = delete;

  // modemfwd::FirmwareDirectory overrides.
  FirmwareDirectory::Files FindFirmware(const std::string& device_id,
                                        std::string* carrier_id) override {
    FirmwareDirectory::Files result;

    DeviceType type{device_id, variant_};
    auto device_it = index_->find(type);
    if (device_it == index_->end()) {
      ELOG(INFO) << "Firmware directory has no firmware for device ID ["
                 << device_id << "]";
      return result;
    }

    const DeviceFirmwareCache& cache = device_it->second;
    FirmwareFileInfo info;

    // Null carrier ID -> just go for generic main and OEM firmwares.
    if (!carrier_id) {
      if (FindSpecificFirmware(cache.main_firmware, kGenericCarrierId, &info))
        result.main_firmware = info;
      if (FindSpecificFirmware(cache.oem_firmware, kGenericCarrierId, &info))
        result.oem_firmware = info;
      if (result.main_firmware.has_value())
        FindAssociatedFirmware(cache, result.main_firmware.value().version,
                               &result.assoc_firmware);
      return result;
    }

    // Searching for carrier firmware may change the carrier to generic. This
    // is fine, and the main firmware should use the same one in that case.
    if (FindFirmwareForCarrier(cache.carrier_firmware, carrier_id, &info))
      result.carrier_firmware = info;
    if (FindFirmwareForCarrier(cache.main_firmware, carrier_id, &info))
      result.main_firmware = info;
    if (FindFirmwareForCarrier(cache.oem_firmware, carrier_id, &info))
      result.oem_firmware = info;

    // Add associated firmware.
    if (result.main_firmware.has_value()) {
      FindAssociatedFirmware(cache, result.main_firmware.value().version,
                             &result.assoc_firmware);
    }

    return result;
  }

  const base::FilePath& GetFirmwarePath() override {
    return fw_manifest_directory_;
  };

  // modemfwd::IsUsingSameFirmware overrides.
  bool IsUsingSameFirmware(const std::string& device_id,
                           const std::string& carrier_a,
                           const std::string& carrier_b) override {
    // easy case: identical carrier UUID
    if (carrier_a == carrier_b)
      return true;

    DeviceType type{device_id, variant_};
    auto device_it = index_->find(type);
    // no firmware for this device
    if (device_it == index_->end())
      return true;

    const DeviceFirmwareCache& cache = device_it->second;
    auto main_a = cache.main_firmware.find(carrier_a);
    auto main_b = cache.main_firmware.find(carrier_b);
    auto cust_a = cache.carrier_firmware.find(carrier_a);
    auto cust_b = cache.carrier_firmware.find(carrier_b);
    // one or several firmwares are missing
    if (main_a == cache.main_firmware.end() ||
        main_b == cache.main_firmware.end() ||
        cust_a == cache.carrier_firmware.end() ||
        cust_b == cache.carrier_firmware.end())
      return main_a == main_b && cust_a == cust_b;
    // same firmware if they are pointing to the 2 same files.
    return main_a->second == main_b->second && cust_a->second == cust_b->second;
  }

  // modemfwd::OverrideVariantForTesting overrides.
  void OverrideVariantForTesting(const std::string& variant) override {
    if (variant.empty() || variant == variant_)
      return;
    LOG(INFO) << "Override variant value: " << variant;
    variant_ = variant;
  };

 private:
  bool FindFirmwareForCarrier(
      const DeviceFirmwareCache::CarrierIndex& carrier_index,
      std::string* carrier_id,
      FirmwareFileInfo* out_info) {
    if (FindSpecificFirmware(carrier_index, *carrier_id, out_info))
      return true;

    if (FindSpecificFirmware(carrier_index, kGenericCarrierId, out_info)) {
      *carrier_id = kGenericCarrierId;
      return true;
    }

    return false;
  }

  bool FindSpecificFirmware(
      const DeviceFirmwareCache::CarrierIndex& carrier_index,
      const std::string& carrier_id,
      FirmwareFileInfo* out_info) {
    auto it = carrier_index.find(carrier_id);
    if (it == carrier_index.end())
      return false;

    *out_info = *it->second;
    return true;
  }

  void FindAssociatedFirmware(
      const DeviceFirmwareCache& cache,
      const std::string& main_version,
      std::map<std::string, FirmwareFileInfo>* out_firmware) {
    for (const auto& main_firmware : cache.main_firmware) {
      FirmwareFileInfo* const main_info = main_firmware.second;
      if (main_version != main_info->version)
        continue;

      auto it = cache.assoc_firmware.find(main_info);
      if (it == cache.assoc_firmware.end())
        return;

      for (const auto& assoc_firmware_entry : it->second) {
        (*out_firmware)[assoc_firmware_entry.first] =
            *assoc_firmware_entry.second;
      }

      return;
    }
  }

  std::unique_ptr<FirmwareIndex> index_;
  base::FilePath fw_manifest_directory_;
  std::string variant_;
};

std::unique_ptr<FirmwareDirectory> CreateFirmwareDirectory(
    std::unique_ptr<FirmwareIndex> index,
    const base::FilePath& directory,
    const std::string& variant) {
  return std::make_unique<FirmwareDirectoryImpl>(std::move(index), directory,
                                                 variant);
}

}  // namespace modemfwd

// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "modemfwd/firmware_directory_stub.h"

#include <map>
#include <utility>

#include <base/check.h>

namespace {

template <typename Map, typename K, typename V>
bool GetValue(const Map& map, const K& key, V* out_value) {
  CHECK(out_value);

  auto it = map.find(key);
  if (it == map.end())
    return false;

  *out_value = it->second;
  return true;
}

}  // namespace

namespace modemfwd {

FirmwareDirectoryStub::FirmwareDirectoryStub(
    const base::FilePath& fw_manifest_directory)
    : fw_manifest_directory_(fw_manifest_directory) {}

void FirmwareDirectoryStub::AddMainFirmware(const std::string& device_id,
                                            FirmwareFileInfo info) {
  main_fw_info_.insert(std::make_pair(device_id, info));
}

void FirmwareDirectoryStub::AddMainFirmwareForCarrier(
    const std::string& device_id,
    const std::string& carrier_id,
    FirmwareFileInfo info) {
  main_fw_info_for_carrier_.insert(
      std::make_pair(std::make_pair(device_id, carrier_id), info));
}

void FirmwareDirectoryStub::AddAssocFirmware(const std::string& main_fw_path,
                                             const std::string& firmware_id,
                                             FirmwareFileInfo info) {
  assoc_fw_info_.insert(
      std::make_pair(std::make_pair(main_fw_path, firmware_id), info));
}

void FirmwareDirectoryStub::AddOemFirmware(const std::string& device_id,
                                           FirmwareFileInfo info) {
  oem_fw_info_.insert(std::make_pair(device_id, info));
}

void FirmwareDirectoryStub::AddOemFirmwareForCarrier(
    const std::string& device_id,
    const std::string& carrier_id,
    FirmwareFileInfo info) {
  oem_fw_info_for_carrier_.insert(
      std::make_pair(std::make_pair(device_id, carrier_id), info));
}

void FirmwareDirectoryStub::AddCarrierFirmware(const std::string& device_id,
                                               const std::string& carrier_id,
                                               FirmwareFileInfo info) {
  carrier_fw_info_.insert(
      std::make_pair(std::make_pair(device_id, carrier_id), info));
}

FirmwareDirectory::Files FirmwareDirectoryStub::FindFirmware(
    const std::string& device_id, std::string* carrier_id) {
  FirmwareDirectory::Files res;
  FirmwareFileInfo info;

  if (carrier_id) {
    if (FindCarrierFirmware(device_id, carrier_id, &info))
      res.carrier_firmware = info;
    if (GetValue(main_fw_info_for_carrier_,
                 std::make_pair(device_id, *carrier_id), &info)) {
      res.main_firmware = info;
    }
    if (GetValue(oem_fw_info_for_carrier_,
                 std::make_pair(device_id, *carrier_id), &info)) {
      res.oem_firmware = info;
    }
  }

  if (!res.oem_firmware.has_value() &&
      GetValue(oem_fw_info_, device_id, &info)) {
    res.oem_firmware = info;
  }

  if (!res.main_firmware.has_value() &&
      GetValue(main_fw_info_, device_id, &info)) {
    res.main_firmware = info;
  }

  auto it = assoc_fw_info_.begin();
  while (it != assoc_fw_info_.end()) {
    // Collect all associated firmwares for the selected main firmware's path
    if (it->first.first == res.main_firmware->firmware_path)
      res.assoc_firmware.insert(std::make_pair(it->first.second, it->second));
    it++;
  }
  return res;
}

bool FirmwareDirectoryStub::FindCarrierFirmware(const std::string& device_id,
                                                std::string* carrier_id,
                                                FirmwareFileInfo* out_info) {
  CHECK(carrier_id);
  if (GetValue(carrier_fw_info_, std::make_pair(device_id, *carrier_id),
               out_info)) {
    return true;
  }

  if (GetValue(carrier_fw_info_, std::make_pair(device_id, kGenericCarrierId),
               out_info)) {
    *carrier_id = kGenericCarrierId;
    return true;
  }

  return false;
}

bool FirmwareDirectoryStub::IsUsingSameFirmware(const std::string& device_id,
                                                const std::string& carrier_a,
                                                const std::string& carrier_b) {
  // easy case: identical carrier UUID
  if (carrier_a == carrier_b)
    return true;

  FirmwareFileInfo info_a;
  FirmwareFileInfo info_b;
  bool has_a =
      GetValue(carrier_fw_info_, std::make_pair(device_id, carrier_a), &info_a);
  bool has_b =
      GetValue(carrier_fw_info_, std::make_pair(device_id, carrier_b), &info_b);
  // one or several firmwares are missing
  if (!has_a || !has_b)
    return false;

  // same firmware if they are pointing to the 2 same files.
  return info_a.firmware_path == info_b.firmware_path;
}

const base::FilePath& FirmwareDirectoryStub::GetFirmwarePath() {
  return fw_manifest_directory_;
}

void FirmwareDirectoryStub::OverrideVariantForTesting(
    const std::string& variant) {}

}  // namespace modemfwd

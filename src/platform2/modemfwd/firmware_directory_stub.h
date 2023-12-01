// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MODEMFWD_FIRMWARE_DIRECTORY_STUB_H_
#define MODEMFWD_FIRMWARE_DIRECTORY_STUB_H_

#include <map>
#include <string>
#include <utility>

#include "modemfwd/firmware_directory.h"

namespace modemfwd {

class FirmwareDirectoryStub : public FirmwareDirectory {
 public:
  explicit FirmwareDirectoryStub(const base::FilePath& fw_manifest_directory);
  FirmwareDirectoryStub(const FirmwareDirectoryStub&) = delete;
  FirmwareDirectoryStub& operator=(const FirmwareDirectoryStub&) = delete;

  void AddMainFirmware(const std::string& device_id, FirmwareFileInfo info);
  void AddMainFirmwareForCarrier(const std::string& device_id,
                                 const std::string& carrier_id,
                                 FirmwareFileInfo info);
  void AddAssocFirmware(const std::string& main_fw_path,
                        const std::string& firmware_tag,
                        FirmwareFileInfo info);
  void AddOemFirmware(const std::string& device_id, FirmwareFileInfo info);
  void AddOemFirmwareForCarrier(const std::string& device_id,
                                const std::string& carrier_id,
                                FirmwareFileInfo info);
  void AddCarrierFirmware(const std::string& device_id,
                          const std::string& carrier_id,
                          FirmwareFileInfo info);

  // modemfwd::FirmwareDirectory overrides.
  FirmwareDirectory::Files FindFirmware(const std::string& device_id,
                                        std::string* carrier_id) override;
  // modemfwd::IsUsingSameFirmware overrides.
  bool IsUsingSameFirmware(const std::string& device_id,
                           const std::string& carrier_a,
                           const std::string& carrier_b) override;

  const base::FilePath& GetFirmwarePath() override;

  // modemfwd::OverrideVariantForTesting overrides.
  void OverrideVariantForTesting(const std::string& variant) override;

 private:
  using CarrierFirmwareMap =
      std::map<std::pair<std::string, std::string>, FirmwareFileInfo>;

  // Map (main_fw_path, associated_tag) -> FirmwareFileInfo
  using AssocFirmwareMap =
      std::map<std::pair<std::string, std::string>, FirmwareFileInfo>;

  bool FindCarrierFirmware(const std::string& device_id,
                           std::string* carrier_id,
                           FirmwareFileInfo* out_info);

  std::map<std::string, FirmwareFileInfo> main_fw_info_;
  std::map<std::string, FirmwareFileInfo> oem_fw_info_;
  AssocFirmwareMap assoc_fw_info_;
  CarrierFirmwareMap main_fw_info_for_carrier_;
  CarrierFirmwareMap oem_fw_info_for_carrier_;
  CarrierFirmwareMap carrier_fw_info_;
  base::FilePath fw_manifest_directory_;
};

}  // namespace modemfwd

#endif  // MODEMFWD_FIRMWARE_DIRECTORY_STUB_H_

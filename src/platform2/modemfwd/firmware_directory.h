// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MODEMFWD_FIRMWARE_DIRECTORY_H_
#define MODEMFWD_FIRMWARE_DIRECTORY_H_

#include <map>
#include <memory>
#include <optional>
#include <string>

#include <base/files/file_path.h>

#include "modemfwd/firmware_file_info.h"
#include "modemfwd/firmware_manifest.h"

namespace modemfwd {

class FirmwareDirectory {
 public:
  struct Files {
    std::optional<FirmwareFileInfo> main_firmware;
    std::optional<FirmwareFileInfo> oem_firmware;
    std::optional<FirmwareFileInfo> carrier_firmware;
    std::map<std::string, FirmwareFileInfo> assoc_firmware;
  };

  static const char kGenericCarrierId[];

  virtual ~FirmwareDirectory() = default;

  // Finds main firmware in the firmware directory for modems with device ID
  // |device_id|, and carrier firmware for the carrier |carrier_id| if it
  // is not null.
  //
  // |carrier_id| may be changed if we find a different carrier firmware
  // that supports the carrier |carrier_id|, such as a generic one.
  virtual Files FindFirmware(const std::string& device_id,
                             std::string* carrier_id) = 0;

  // Returns the path where the firmware files are stored. For DLCs, the path
  // is retrieved from dlcservice during runtime.
  virtual const base::FilePath& GetFirmwarePath() = 0;

  // Determine whether two potentially different carrier ID |carrier_a| and
  // |carrier_b| are using the same base and carrier firmwares.
  // e.g. a carrier and MVNO networks.
  virtual bool IsUsingSameFirmware(const std::string& device_id,
                                   const std::string& carrier_a,
                                   const std::string& carrier_b) = 0;

  // Override the variant variable for testing.
  virtual void OverrideVariantForTesting(const std::string& variant) = 0;
};

std::unique_ptr<FirmwareDirectory> CreateFirmwareDirectory(
    std::unique_ptr<FirmwareIndex> index,
    const base::FilePath& directory,
    const std::string& variant);

}  // namespace modemfwd

#endif  // MODEMFWD_FIRMWARE_DIRECTORY_H_

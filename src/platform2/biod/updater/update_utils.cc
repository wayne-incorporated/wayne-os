// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "biod/updater/update_utils.h"

#include <optional>
#include <string>
#include <string_view>

#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <brillo/vcsid.h>
#include <cros_config/cros_config_interface.h>

#include "biod/biod_config.h"

namespace {

constexpr char kFirmwareGlobSuffix[] = "_*.bin";
constexpr char kUpdateDisableFile[] =
    "/mnt/stateful_partition/.disable_fp_updater";

}  // namespace

namespace biod {
namespace updater {

std::string UpdaterVersion() {
  static_assert(brillo::kVCSID,
                "The updater requires VCSID to function properly.");
  return std::string(*brillo::kVCSID);
}

bool UpdateDisallowed(const BiodSystem& system) {
  // Disable updates when /mnt/stateful_partition/.disable_fp_updater exists
  // and Developer Mode can boot from unsigned kernel (it's a bit stronger check
  // than developer mode only).
  if (!system.OnlyBootSignedKernel() &&
      base::PathExists(base::FilePath(kUpdateDisableFile))) {
    return true;
  }

  return false;
}

FindFirmwareFileStatus FindFirmwareFile(
    const base::FilePath& directory,
    brillo::CrosConfigInterface* cros_config,
    base::FilePath* file) {
  std::optional<std::string> board_name = biod::FingerprintBoard(cros_config);
  if (!board_name.has_value() || board_name->empty()) {
    LOG(ERROR) << "Fingerprint board name is unavailable";
    return FindFirmwareFileStatus::kBoardUnavailable;
  }
  LOG(INFO) << "Identified fingerprint board name as '" << *board_name << "'.";

  if (!base::DirectoryExists(directory)) {
    return FindFirmwareFileStatus::kNoDirectory;
  }

  std::string glob(*board_name + std::string(kFirmwareGlobSuffix));
  base::FileEnumerator fw_bin_list(directory, false,
                                   base::FileEnumerator::FileType::FILES, glob);

  // Find provided firmware file
  base::FilePath fw_bin = fw_bin_list.Next();
  if (fw_bin.empty()) {
    return FindFirmwareFileStatus::kFileNotFound;
  }
  LOG(INFO) << "Found firmware file '" << fw_bin.value() << "'.";

  // Ensure that there are no other firmware files
  bool extra_fw_files = false;
  for (base::FilePath fw_extra = fw_bin_list.Next(); !fw_extra.empty();
       fw_extra = fw_bin_list.Next()) {
    extra_fw_files = true;
    LOG(ERROR) << "Found firmware file '" << fw_extra.value() << "'.";
  }
  if (extra_fw_files) {
    return FindFirmwareFileStatus::kMultipleFiles;
  }

  *file = fw_bin;
  return FindFirmwareFileStatus::kFoundFile;
}

std::string FindFirmwareFileStatusToString(FindFirmwareFileStatus status) {
  switch (status) {
    case FindFirmwareFileStatus::kFoundFile:
      return "Firmware file found.";
    case FindFirmwareFileStatus::kNoDirectory:
      return "Firmware directory does not exist.";
    case FindFirmwareFileStatus::kFileNotFound:
      return "Firmware file not found.";
    case FindFirmwareFileStatus::kMultipleFiles:
      return "More than one firmware file was found.";
    case FindFirmwareFileStatus::kBoardUnavailable:
      return "Fingerprint board name is not available.";
  }

  NOTREACHED();
  return "Unknown find firmware file status encountered.";
}

}  // namespace updater
}  // namespace biod

// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/udev_bluetooth_util.h"

#include <utility>
#include <vector>

#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/logging.h>
#include <base/strings/strcat.h>
#include <base/strings/string_split.h>
#include <base/strings/stringprintf.h>
#include <brillo/files/safe_fd.h>
#include <brillo/process/process.h>
#include <brillo/scoped_umask.h>

#include "crash-reporter/paths.h"
#include "crash-reporter/util.h"

namespace {

constexpr char kCoredumpFlagPath[] = "/run/bluetooth/coredump_disabled";
constexpr char kCoredumpParserPath[] = "/usr/bin/bluetooth_devcd_parser";
constexpr char kCoredumpMetaHeader[] = "Bluetooth devcoredump";

bool SafeDirChmod(const base::FilePath& path, mode_t mode) {
  // Reset mask since we are setting the mode explicitly.
  brillo::ScopedUmask scoped_umask(0);

  auto root_fd_result = brillo::SafeFD::Root();
  if (root_fd_result.second != brillo::SafeFD::Error::kNoError) {
    return false;
  }

  auto path_result = root_fd_result.first.OpenExistingDir(path);
  if (path_result.second != brillo::SafeFD::Error::kNoError) {
    return false;
  }

  if (HANDLE_EINTR(fchmod(path_result.first.get(), mode)) != 0) {
    PLOG(ERROR) << "Failed to set permissions in SafeDirChmod() for \""
                << path.value() << '"';
    return false;
  }

  return true;
}

}  // namespace

namespace bluetooth_util {

constexpr char kBluetoothDevCoredumpExecName[] = "bt_firmware";

std::string CreateCrashSig(const std::string& driver_name,
                           const std::string& vendor_name,
                           const std::string& controller_name,
                           const std::string& pc) {
  return base::StrCat({bluetooth_util::kBluetoothDevCoredumpExecName, "-",
                       driver_name, "-", vendor_name, "_", controller_name, "-",
                       pc});
}

bool ReadCrashSig(const base::FilePath& target_path, std::string* crash_sig) {
  std::string target_content;
  if (!base::ReadFileToString(target_path, &target_content)) {
    PLOG(ERROR) << "Failed to read parsed bluetooth coredump " << target_path;
    return false;
  }

  // Parse target file contents as key-value pairs.
  std::vector<std::pair<std::string, std::string>> target_keyval;
  std::string driver_name;
  std::string vendor_name;
  std::string controller_name;
  std::string pc;

  base::SplitStringIntoKeyValuePairs(target_content, '=', '\n', &target_keyval);
  for (const auto& key_value : target_keyval) {
    if (key_value.first == "Driver") {
      driver_name = key_value.second;
    } else if (key_value.first == "Vendor") {
      vendor_name = key_value.second;
    } else if (key_value.first == "Controller Name") {
      controller_name = key_value.second;
    } else if (key_value.first == "PC") {
      pc = key_value.second;
    }
  }

  if (driver_name.empty()) {
    LOG(ERROR) << "Missing Driver Name in the parsed bluetooth coredump";
    return false;
  } else if (vendor_name.empty()) {
    LOG(ERROR) << "Missing Vendor Name in the parsed bluetooth coredump";
    return false;
  } else if (controller_name.empty()) {
    LOG(ERROR) << "Missing Controller Name in the parsed bluetooth coredump";
    return false;
  } else if (pc.empty()) {
    LOG(ERROR) << "Missing PC in the parsed bluetooth coredump";
    return false;
  }

  *crash_sig = CreateCrashSig(driver_name, vendor_name, controller_name, pc);
  return true;
}

bool IsCoredumpEnabled() {
  std::string val;

  if (!base::ReadFileToString(paths::Get(kCoredumpFlagPath), &val)) {
    PLOG(ERROR) << "Failed to read " << paths::Get(kCoredumpFlagPath);
    return false;
  }
  val.resize(1);

  // The flag name is coredump_disabled. So, when disabled is 0, the feature is
  // enabled.
  return val == "0";
}

bool IsBluetoothCoredump(const base::FilePath& coredump_path) {
  std::string header;

  if (!base::ReadFileToString(coredump_path, &header)) {
    PLOG(ERROR) << "Failed to read " << coredump_path;
    return false;
  }

  return header.substr(0, header.find("\n")) == kCoredumpMetaHeader;
}

bool ProcessBluetoothCoredump(const base::FilePath& coredump_path,
                              const base::FilePath& target_path,
                              std::string* crash_sig) {
  if (!crash_sig)
    return false;

  // Create a scoped temp dir to store bluetooth parser output files.
  base::ScopedTempDir tmp_dir;
  if (!tmp_dir.CreateUniqueTempDir()) {
    LOG(ERROR) << "Error creating scoped temp dir";
    return false;
  }
  base::FilePath tmp_output_dir = tmp_dir.GetPath();

  // By default the scoped temp dir is accessible to the owner only, give access
  // to others so the bluetooth devcoredump parser can access it.
  if (!SafeDirChmod(tmp_output_dir, 0777)) {
    LOG(ERROR) << "Error in chmod scoped temp dir " << tmp_output_dir;
    return false;
  }

  // Copy input devcoredump file to the temp dir and run bluetooth devcoredump
  // parser with minimal permissions.
  base::FilePath tmp_coredump_path =
      tmp_output_dir.Append(target_path.BaseName().ReplaceExtension("devcd"));
  if (!base::CopyFile(coredump_path, tmp_coredump_path)) {
    LOG(ERROR) << "Error copying input devcoredump to " << tmp_coredump_path;
    return false;
  }

  brillo::ProcessImpl dump_parser;
  dump_parser.SetUid(65534);  // the nobody user
  dump_parser.SetGid(65534);  // the nobody group
  dump_parser.AddArg(kCoredumpParserPath);
  dump_parser.AddArg(
      base::StrCat({"--coredump_path=", tmp_coredump_path.value()}));
  dump_parser.AddArg(base::StrCat({"--output_dir=", tmp_output_dir.value()}));
  dump_parser.AddArg("--enable_syslog");
  if (util::IsDeveloperImage()) {
    dump_parser.AddArg("--save_dump_data");
  }

  int ret = dump_parser.Run();
  if (ret != EXIT_SUCCESS) {
    LOG(ERROR) << "Failed to run bluetooth devcoredump parser "
               << kCoredumpParserPath << " with exit code: " << ret;
    return false;
  }

  // Move parsed data to crash directory for further processing.
  base::FilePath tmp_target_path =
      tmp_output_dir.Append(target_path.BaseName());
  if (!base::CopyFile(tmp_target_path, target_path)) {
    LOG(ERROR) << "Error copying parsed devcoredump to " << target_path;
    return false;
  }

  if (util::IsDeveloperImage()) {
    base::FilePath tmp_data_path = tmp_target_path.ReplaceExtension("data");
    base::FilePath target_data_path = target_path.ReplaceExtension("data");
    if (!base::CopyFile(tmp_data_path, target_data_path)) {
      LOG(ERROR) << "Error copying binary devcoredump to " << target_data_path;
      return false;
    }
  }

  return ReadCrashSig(target_path, crash_sig);
}

}  // namespace bluetooth_util

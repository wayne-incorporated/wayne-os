// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/mount_failure_collector.h"

#include <memory>
#include <string>
#include <vector>

#include <base/files/file_enumerator.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/rand_util.h>
#include <base/strings/stringprintf.h>

#include "crash-reporter/constants.h"
#include "crash-reporter/paths.h"
#include "crash-reporter/util.h"

namespace {
const char kEncryptedStatefulDeviceLabel[] = "encstateful";
const char kStatefulDeviceLabel[] = "stateful";
const char kCryptohomeDeviceLabel[] = "cryptohome";
const char kInvalidDeviceLabel[] = "invalid";

std::vector<std::string> ConstructLoggingCommands(StorageDeviceType device_type,
                                                  bool is_mount_failure) {
  std::vector<std::string> cmds;
  switch (device_type) {
    case StorageDeviceType::kStateful:
      if (is_mount_failure)
        cmds = {"dumpe2fs_stateful", "kernel-warning", "console-ramoops"};
      else
        cmds = {"shutdown_umount_failure_state", "umount-encrypted"};
      break;
    case StorageDeviceType::kEncryptedStateful:
      cmds = {"dumpe2fs_encstateful", "kernel-warning", "console-ramoops",
              "mount-encrypted"};
      break;
    case StorageDeviceType::kCryptohome:
      cmds = {"cryptohome", "kernel-warning"};
      break;
    default:
      break;
  }
  return cmds;
}

}  // namespace

MountFailureCollector::MountFailureCollector(StorageDeviceType device_type,
                                             bool testonly_send_all)
    : CrashCollector("mount_failure_collector"),
      device_type_(device_type),
      testonly_send_all_(testonly_send_all) {}

// static
StorageDeviceType MountFailureCollector::ValidateStorageDeviceType(
    const std::string& device_label) {
  if (device_label == kStatefulDeviceLabel)
    return StorageDeviceType::kStateful;
  else if (device_label == kEncryptedStatefulDeviceLabel)
    return StorageDeviceType::kEncryptedStateful;
  else if (device_label == kCryptohomeDeviceLabel)
    return StorageDeviceType::kCryptohome;
  else
    return StorageDeviceType::kInvalidDevice;
}

// static
std::string MountFailureCollector::StorageDeviceTypeToString(
    StorageDeviceType device_type) {
  switch (device_type) {
    case StorageDeviceType::kStateful:
      return kStatefulDeviceLabel;
    case StorageDeviceType::kEncryptedStateful:
      return kEncryptedStatefulDeviceLabel;
    case StorageDeviceType::kCryptohome:
      return kCryptohomeDeviceLabel;
    default:
      return kInvalidDeviceLabel;
  }
}

bool MountFailureCollector::Collect(bool is_mount_failure) {
  if (device_type_ == StorageDeviceType::kInvalidDevice) {
    LOG(ERROR) << "Invalid storage device.";
    return true;
  }

  if (device_type_ == StorageDeviceType::kStateful && !is_mount_failure) {
    // Sample umount_failure_stateful crashes, as they're a significant source
    // of noise.
    if (!testonly_send_all_ &&
        base::RandGenerator(util::GetUmountStatefulFailureWeight()) != 0) {
      LOG(INFO) << "Skipping umount failure";
      return true;
    }
    AddCrashMetaUploadData(
        "weight",
        base::StringPrintf("%d", util::GetUmountStatefulFailureWeight()));
  }

  std::string device_label = StorageDeviceTypeToString(device_type_);
  std::string exec_name = (is_mount_failure ? "mount" : "umount");
  exec_name += "_failure_" + device_label;
  std::string dump_basename = FormatDumpBasename(exec_name, time(nullptr), 0);

  auto logging_cmds = ConstructLoggingCommands(device_type_, is_mount_failure);

  base::FilePath crash_directory;
  if (!GetCreatedCrashDirectoryByEuid(constants::kRootUid, &crash_directory,
                                      nullptr)) {
    return true;
  }

  // Use exec name as the crash signature.
  AddCrashMetaData("sig", exec_name);

  base::FilePath log_path = GetCrashPath(crash_directory, dump_basename, "log");
  base::FilePath meta_path =
      GetCrashPath(crash_directory, dump_basename, "meta");

  bool result =
      GetMultipleLogContents(log_config_path_, logging_cmds, log_path);
  if (result) {
    FinishCrash(meta_path, exec_name, log_path.BaseName().value());
  }

  return true;
}

// static
CollectorInfo MountFailureCollector::GetHandlerInfo(
    const std::string& mount_device,
    bool testonly_send_all,
    bool mount_failure,
    bool umount_failure) {
  auto mount_failure_collector = std::make_shared<MountFailureCollector>(
      ValidateStorageDeviceType(mount_device), testonly_send_all);
  return {
      .collector = mount_failure_collector,
      .handlers = {{
          .should_handle = mount_failure || umount_failure,
          .cb = base::BindRepeating(&MountFailureCollector::Collect,
                                    mount_failure_collector, mount_failure),
      }},
  };
}

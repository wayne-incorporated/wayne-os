// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/udev_collector.h"

#include <fcntl.h>

#include <map>
#include <memory>
#include <utility>
#include <vector>

#include <base/files/file_enumerator.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <brillo/process/process.h>

#include "crash-reporter/udev_bluetooth_util.h"
#include "crash-reporter/util.h"

using base::FilePath;

namespace {

const char kCollectUdevSignature[] = "crash_reporter-udev-collection";
const char kUdevExecName[] = "udev";
const char kUdevSignatureKey[] = "sig";
const char kUdevSubsystemDevCoredump[] = "devcoredump";
const char kDefaultDevCoredumpDirectory[] = "/sys/class/devcoredump";
const char kDevCoredumpFilePrefixFormat[] = "devcoredump_%s";

}  // namespace

UdevCollector::UdevCollector()
    : CrashCollector("udev"),
      dev_coredump_directory_(kDefaultDevCoredumpDirectory) {}

UdevCollector::~UdevCollector() {}

bool UdevCollector::IsSafeDevCoredump(
    std::map<std::string, std::string> udev_event_map) {
  // Is it a device coredump?
  if (udev_event_map["SUBSYSTEM"] != kUdevSubsystemDevCoredump)
    return false;

  int instance_number;
  if (!base::StringToInt(udev_event_map["KERNEL_NUMBER"], &instance_number)) {
    LOG(ERROR) << "Invalid kernel number: " << udev_event_map["KERNEL_NUMBER"];
    return false;
  }

  // Retrieve the driver name of the failing device.
  std::string driver_name = GetFailingDeviceDriverName(instance_number);
  if (driver_name.empty()) {
    LOG(ERROR) << "Failed to obtain driver name for instance: "
               << instance_number;
    return false;
  }

  // Check for safe drivers:
  return driver_name == "msm" || driver_name == "qcom-venus";
}

bool UdevCollector::HandleCrash(const std::string& udev_event) {
  // Process the udev event string.
  // First get all the key-value pairs.
  std::vector<std::pair<std::string, std::string>> udev_event_keyval;
  base::SplitStringIntoKeyValuePairs(udev_event, '=', ':', &udev_event_keyval);
  std::map<std::string, std::string> udev_event_map;
  for (const auto& key_value : udev_event_keyval) {
    udev_event_map[key_value.first] = key_value.second;
  }

  FilePath coredump_path = FilePath(
      base::StringPrintf("%s/devcd%s/data", dev_coredump_directory_.c_str(),
                         udev_event_map["KERNEL_NUMBER"].c_str()));

  if (bluetooth_util::IsCoredumpEnabled() &&
      bluetooth_util::IsBluetoothCoredump(coredump_path)) {
    LOG(INFO) << "Process bluetooth devcoredump.";
  } else if (UdevCollector::IsSafeDevCoredump(udev_event_map)) {
    LOG(INFO) << "Safe device coredumps are always processed";
  } else if (util::IsDeveloperImage()) {
    LOG(INFO) << "developer image - collect udev crash info.";
  } else if (udev_event_map["SUBSYSTEM"] == kUdevSubsystemDevCoredump) {
    LOG(INFO) << "Device coredumps are not processed on non-developer images.";
    // Clear devcoredump memory before returning.
    ClearDevCoredump(coredump_path);
    return false;
  } else {
    LOG(INFO) << "Consent given - collect udev crash info.";
  }

  // Make sure the crash directory exists, or create it if it doesn't.
  FilePath crash_directory;
  if (!GetCreatedCrashDirectoryByEuid(0, &crash_directory, nullptr)) {
    LOG(ERROR) << "Could not get crash directory.";
    return false;
  }

  if (udev_event_map["SUBSYSTEM"] == kUdevSubsystemDevCoredump) {
    int instance_number;
    if (!base::StringToInt(udev_event_map["KERNEL_NUMBER"], &instance_number)) {
      LOG(ERROR) << "Invalid kernel number: "
                 << udev_event_map["KERNEL_NUMBER"];
      return false;
    }
    return ProcessDevCoredump(crash_directory, instance_number);
  }

  return ProcessUdevCrashLogs(crash_directory, udev_event_map["ACTION"],
                              udev_event_map["KERNEL"],
                              udev_event_map["SUBSYSTEM"]);
}

bool UdevCollector::ProcessUdevCrashLogs(const FilePath& crash_directory,
                                         const std::string& action,
                                         const std::string& kernel,
                                         const std::string& subsystem) {
  // Construct the basename string for crash_reporter_logs.conf:
  //   "crash_reporter-udev-collection-[action]-[name]-[subsystem]"
  // If a udev field is not provided, "" is used in its place, e.g.:
  //   "crash_reporter-udev-collection-[action]--[subsystem]"
  // Hence, "" is used as a wildcard name string.
  // TODO(sque, crosbug.com/32238): Implement wildcard checking.
  std::string basename = action + "-" + kernel + "-" + subsystem;
  std::string udev_log_name =
      std::string(kCollectUdevSignature) + '-' + basename;

  // Create the destination path.
  std::string log_file_name = FormatDumpBasename(basename, time(nullptr), 0);
  FilePath crash_path = GetCrashPath(crash_directory, log_file_name, "log.gz");

  // Handle the crash.
  bool result = GetLogContents(log_config_path_, udev_log_name, crash_path);
  if (!result) {
    LOG(ERROR) << "Error reading udev log info " << udev_log_name;
    return false;
  }

  std::string exec_name = std::string(kUdevExecName) + "-" + subsystem;
  AddCrashMetaData(kUdevSignatureKey, udev_log_name);
  FinishCrash(GetCrashPath(crash_directory, log_file_name, "meta"), exec_name,
              crash_path.BaseName().value());
  return true;
}

bool UdevCollector::ProcessDevCoredump(const FilePath& crash_directory,
                                       int instance_number) {
  FilePath coredump_path = FilePath(base::StringPrintf(
      "%s/devcd%d/data", dev_coredump_directory_.c_str(), instance_number));
  if (!base::PathExists(coredump_path)) {
    LOG(ERROR) << "Device coredump file " << coredump_path.value()
               << " does not exist";
    return false;
  }

  if (bluetooth_util::IsCoredumpEnabled() &&
      bluetooth_util::IsBluetoothCoredump(coredump_path)) {
    if (!AppendBluetoothCoredump(crash_directory, coredump_path,
                                 instance_number)) {
      ClearDevCoredump(coredump_path);
      return false;
    }
    return ClearDevCoredump(coredump_path);
  }

  // Add coredump file to the crash directory.
  if (!AppendDevCoredump(crash_directory, coredump_path, instance_number)) {
    ClearDevCoredump(coredump_path);
    return false;
  }

  // Clear the coredump data to allow generation of future device coredumps
  // without having to wait for the 5-minutes timeout.
  return ClearDevCoredump(coredump_path);
}

bool UdevCollector::AppendBluetoothCoredump(const FilePath& crash_directory,
                                            const FilePath& coredump_path,
                                            int instance_number) {
  std::string coredump_prefix = bluetooth_util::kBluetoothDevCoredumpExecName;
  std::string dump_basename =
      FormatDumpBasename(coredump_prefix, time(nullptr), instance_number);
  FilePath target_path = GetCrashPath(crash_directory, dump_basename, "txt");
  FilePath log_path = GetCrashPath(crash_directory, dump_basename, "log");
  FilePath meta_path = GetCrashPath(crash_directory, dump_basename, "meta");
  std::string crash_sig;

  if (!bluetooth_util::ProcessBluetoothCoredump(coredump_path, target_path,
                                                &crash_sig)) {
    LOG(ERROR) << "Failed to parse bluetooth devcoredump.";
    return false;
  }

  if (GetLogContents(log_config_path_, coredump_prefix, log_path)) {
    AddCrashMetaUploadFile("logs", log_path.BaseName().value());
  }

  AddCrashMetaData(kUdevSignatureKey, crash_sig);
  FinishCrash(meta_path, coredump_prefix, target_path.BaseName().value());

  return true;
}

bool UdevCollector::AppendDevCoredump(const FilePath& crash_directory,
                                      const FilePath& coredump_path,
                                      int instance_number) {
  // Retrieve the driver name of the failing device.
  std::string driver_name = GetFailingDeviceDriverName(instance_number);
  if (driver_name.empty()) {
    LOG(ERROR) << "Failed to obtain driver name for instance: "
               << instance_number;
    return false;
  }

  std::string coredump_prefix =
      base::StringPrintf(kDevCoredumpFilePrefixFormat, driver_name.c_str());

  std::string dump_basename =
      FormatDumpBasename(coredump_prefix, time(nullptr), instance_number);
  FilePath core_path =
      GetCrashPath(crash_directory, dump_basename, "devcore.gz");
  FilePath log_path = GetCrashPath(crash_directory, dump_basename, "log");
  FilePath meta_path = GetCrashPath(crash_directory, dump_basename, "meta");

  // Collect coredump data.
  // We expect /sys/class/devcoredump/devcdN (the path we typically use to
  // access the dump) to be a symlink. devcdN/data, however, should not be a
  // symlink. This means we can't use functionality (e.g. SafeFD) that verifies
  // that no path components are symlinks, but we can use O_NOFOLLOW.
  const char* filename_cstr = coredump_path.value().c_str();
  int source_fd =
      HANDLE_EINTR(open(filename_cstr, O_RDONLY | O_NOFOLLOW | O_CLOEXEC));
  if (source_fd < 0) {
    PLOG(ERROR) << "Failed to open " << filename_cstr;
    return false;
  }
  // Similarly, the core_path will be of form /proc/self/fd/<n>/foo.devcore,
  // where /proc/self is a symlink, but foo.devcore should not be.
  if (!CopyFdToNewCompressedFile(base::ScopedFD(source_fd), core_path)) {
    PLOG(ERROR) << "Failed to copy device coredump file from "
                << coredump_path.value() << " to " << core_path.value();
    return false;
  }

  // Collect additional logs if one is specified in the config file.
  std::string udev_log_name = std::string(kCollectUdevSignature) + '-' +
                              kUdevSubsystemDevCoredump + '-' + driver_name;
  bool result = GetLogContents(log_config_path_, udev_log_name, log_path);
  if (result) {
    AddCrashMetaUploadFile("logs", log_path.BaseName().value());
  }

  AddCrashMetaData(kUdevSignatureKey, udev_log_name);

  FinishCrash(meta_path, coredump_prefix, core_path.BaseName().value());

  return true;
}

bool UdevCollector::ClearDevCoredump(const FilePath& coredump_path) {
  if (!base::WriteFile(coredump_path, "0", 1)) {
    PLOG(ERROR) << "Failed to delete the coredump data file "
                << coredump_path.value();
    return false;
  }
  return true;
}

FilePath UdevCollector::GetFailingDeviceDriverPath(
    int instance_number, const std::string& sub_path) {
  const FilePath dev_coredump_path(dev_coredump_directory_);
  FilePath failing_uevent_path = dev_coredump_path.Append(
      base::StringPrintf("devcd%d/%s", instance_number, sub_path.c_str()));
  return failing_uevent_path;
}

std::string UdevCollector::ExtractFailingDeviceDriverName(
    const FilePath& failing_uevent_path) {
  if (!base::PathExists(failing_uevent_path)) {
    LOG(ERROR) << "Failing uevent path " << failing_uevent_path.value()
               << " does not exist";
    return "";
  }

  std::string uevent_content;
  if (!base::ReadFileToString(failing_uevent_path, &uevent_content)) {
    PLOG(ERROR) << "Failed to read uevent file " << failing_uevent_path.value();
    return "";
  }

  // Parse uevent file contents as key-value pairs.
  std::vector<std::pair<std::string, std::string>> uevent_keyval;
  base::SplitStringIntoKeyValuePairs(uevent_content, '=', '\n', &uevent_keyval);
  for (const auto& key_value : uevent_keyval) {
    if (key_value.first == "DRIVER") {
      return key_value.second;
    }
  }

  return "";
}

std::string UdevCollector::GetFailingDeviceDriverName(int instance_number) {
  FilePath failing_uevent_path =
      GetFailingDeviceDriverPath(instance_number, "failing_device/uevent");
  std::string name = ExtractFailingDeviceDriverName(failing_uevent_path);
  if (name.empty()) {
    LOG(WARNING)
        << "Failed to obtain driver name; trying alternate uevent paths.";
    failing_uevent_path = GetFailingDeviceDriverPath(
        instance_number, "failing_device/device/uevent");
    name = ExtractFailingDeviceDriverName(failing_uevent_path);
  }
  return name;
}

// static
CollectorInfo UdevCollector::GetHandlerInfo(const std::string& udev_event) {
  auto udev_collector = std::make_shared<UdevCollector>();
  return {.collector = udev_collector,
          .handlers = {{
              .should_handle = !udev_event.empty(),
              .cb = base::BindRepeating(&UdevCollector::HandleCrash,
                                        udev_collector, udev_event),
          }}};
}

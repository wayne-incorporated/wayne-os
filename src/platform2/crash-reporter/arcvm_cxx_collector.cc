// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/arcvm_cxx_collector.h"

#include <memory>
#include <utility>

#include <unistd.h>

#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>
#include <brillo/syslog_logging.h>

#include "crash-reporter/arc_util.h"
#include "crash-reporter/constants.h"
#include "crash-reporter/util.h"

namespace {

// TODO(b/169638371): Remove the word "native".
constexpr char kArcvmCxxCollectorName[] = "ARCVM_native";

// "native_crash" is a tag defined in Android.
constexpr char kArcvmNativeCrashType[] = "native_crash";

}  // namespace

ArcvmCxxCollector::ArcvmCxxCollector()
    : CrashCollector(kArcvmCxxCollectorName,
                     kAlwaysUseUserCrashDirectory,
                     kNormalCrashSendMode) {}

ArcvmCxxCollector::~ArcvmCxxCollector() = default;

bool ArcvmCxxCollector::HandleCrash(
    const arc_util::BuildProperty& build_property,
    const CrashInfo& crash_info,
    base::TimeDelta uptime) {
  return HandleCrashWithMinidumpFD(build_property, crash_info, uptime,
                                   // use dup() to avoid closing STDIN_FILENO
                                   base::ScopedFD(dup(STDIN_FILENO)));
}

bool ArcvmCxxCollector::HandleCrashWithMinidumpFD(
    const arc_util::BuildProperty& build_property,
    const CrashInfo& crash_info,
    base::TimeDelta uptime,
    base::ScopedFD minidump_fd) {
  const std::string message =
      "Received crash notification for " + crash_info.exec_name;
  LogCrash(message, "handling");
  if (!minidump_fd.is_valid()) {
    LOG(ERROR) << "Failed to dup(STDIN_FILENO)";
    return false;
  }

  bool out_of_capacity = false;
  base::FilePath crash_dir;
  if (!GetCreatedCrashDirectoryByEuid(geteuid(), &crash_dir,
                                      &out_of_capacity)) {
    LOG(ERROR) << "Failed to create or find crash directory";
    if (!out_of_capacity)
      EnqueueCollectionErrorLog(kErrorSystemIssue, crash_info.exec_name);
    return false;
  }

  AddArcMetadata(build_property, crash_info, uptime);

  const std::string basename_without_ext =
      FormatDumpBasename(crash_info.exec_name, crash_info.time, crash_info.pid);
  const base::FilePath minidump_path = GetCrashPath(
      crash_dir, basename_without_ext, constants::kMinidumpExtension);
  if (!CopyFdToNewFile(std::move(minidump_fd), minidump_path)) {
    LOG(ERROR) << "Failed to write minidump file";
    return false;
  }

  const base::FilePath metadata_path =
      GetCrashPath(crash_dir, basename_without_ext, "meta");
  FinishCrash(metadata_path, crash_info.exec_name,
              minidump_path.BaseName().value());

  return true;
}

void ArcvmCxxCollector::AddArcMetadata(
    const arc_util::BuildProperty& build_property,
    const CrashInfo& crash_info,
    base::TimeDelta uptime) {
  for (const auto& metadata : arc_util::ListBasicARCRelatedMetadata(
           crash_info.exec_name, kArcvmNativeCrashType)) {
    AddCrashMetaUploadData(metadata.first, metadata.second);
  }
  AddCrashMetaUploadData(arc_util::kChromeOsVersionField, GetOsVersion());

  for (auto metadata : arc_util::ListMetadataForBuildProperty(build_property)) {
    AddCrashMetaUploadData(metadata.first, metadata.second);
  }

  if (!uptime.is_zero()) {
    AddCrashMetaUploadData(arc_util::kUptimeField,
                           arc_util::FormatDuration(uptime));
  }
}

std::string ArcvmCxxCollector::GetProductVersion() const {
  return arc_util::GetProductVersion();
}

// static
CollectorInfo ArcvmCxxCollector::GetHandlerInfo(
    bool arc_native,
    const arc_util::BuildProperty& build_property,
    const CrashInfo& crash_info,
    int64_t uptime_millis) {
  auto arcvm_cxx_collector = std::make_shared<ArcvmCxxCollector>();
  return {
      .collector = arcvm_cxx_collector,
      .handlers = {{
          // This handles C++ crashes of ARCVM.
          .should_handle = arc_native,
          .cb = base::BindRepeating(
              &ArcvmCxxCollector::HandleCrash, arcvm_cxx_collector,
              build_property, crash_info, base::Milliseconds(uptime_millis)),
      }},
  };
}

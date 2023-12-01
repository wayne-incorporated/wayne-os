// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/arc_java_collector.h"

#include <ctime>
#include <memory>
#include <utility>

#include <base/files/file.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/time/time.h>

#include "crash-reporter/arc_util.h"
#include "crash-reporter/util.h"

using base::File;
using base::FilePath;

namespace {

constexpr char kArcJavaCollectorName[] = "ARC_java";

}  // namespace

ArcJavaCollector::ArcJavaCollector()
    : CrashCollector(kArcJavaCollectorName,
                     kAlwaysUseUserCrashDirectory,
                     kNormalCrashSendMode,
                     kArcJavaCollectorName) {}

bool ArcJavaCollector::HandleCrash(
    const std::string& crash_type,
    const arc_util::BuildProperty& build_property,
    base::TimeDelta uptime) {
  std::ostringstream message;
  message << "Received " << crash_type << " notification";

  std::string contents;
  if (!base::ReadStreamToString(stdin, &contents)) {
    PLOG(ERROR) << "Failed to read crash log";
    return false;
  }
  if (contents.empty()) {
    LOG(ERROR) << "crash log was empty";
    return false;
  }

  CrashLogHeaderMap map;
  std::string exception_info, log;
  if (!arc_util::ParseCrashLog(crash_type, contents, &map, &exception_info,
                               &log)) {
    LOG(ERROR) << "Failed to parse crash log";
    return false;
  }

  const auto exec = arc_util::GetCrashLogHeader(map, arc_util::kProcessKey);
  message << " for " << exec;
  LogCrash(message.str(), "handling");

  bool out_of_capacity = false;
  if (!CreateReportForJavaCrash(crash_type, build_property, map, exception_info,
                                log, uptime, &out_of_capacity)) {
    if (!out_of_capacity) {
      EnqueueCollectionErrorLog(kErrorSystemIssue, exec);
    }
    return false;
  }

  return true;
}

std::string ArcJavaCollector::GetProductVersion() const {
  return arc_util::GetProductVersion();
}

void ArcJavaCollector::AddArcMetaData(const std::string& process,
                                      const std::string& crash_type,
                                      base::TimeDelta uptime) {
  for (const auto& metadata :
       arc_util::ListBasicARCRelatedMetadata(process, crash_type)) {
    AddCrashMetaUploadData(metadata.first, metadata.second);
  }
  AddCrashMetaUploadData(arc_util::kChromeOsVersionField, GetOsVersion());

#if USE_ARCPP
  if (uptime.is_zero()) {
    SetUpDBus();
    if (!arc_util::GetArcContainerUptime(session_manager_proxy_.get(),
                                         &uptime)) {
      uptime = base::TimeDelta();
    }
  }
#endif  // USE_ARCPP
  if (!uptime.is_zero()) {
    AddCrashMetaUploadData(arc_util::kUptimeField,
                           arc_util::FormatDuration(uptime));
  }

  if (arc_util::IsSilentReport(crash_type))
    AddCrashMetaData(arc_util::kSilentKey, "true");
}

bool ArcJavaCollector::CreateReportForJavaCrash(
    const std::string& crash_type,
    const arc_util::BuildProperty& build_property,
    const CrashLogHeaderMap& map,
    const std::string& exception_info,
    const std::string& log,
    base::TimeDelta uptime,
    bool* out_of_capacity) {
  FilePath crash_dir;
  if (!GetCreatedCrashDirectoryByEuid(geteuid(), &crash_dir, out_of_capacity)) {
    LOG(ERROR) << "Failed to create or find crash directory";
    return false;
  }

  const auto process = arc_util::GetCrashLogHeader(map, arc_util::kProcessKey);
  pid_t dt = arc_util::CreateRandomPID();
  const auto basename = FormatDumpBasename(process, std::time(nullptr), dt);
  const FilePath log_path = GetCrashPath(crash_dir, basename, "log");

  const int size = static_cast<int>(log.size());
  if (WriteNewFile(log_path, log) != size) {
    PLOG(ERROR) << "Failed to write log";
    return false;
  }

  AddArcMetaData(process, crash_type, uptime);
  for (auto metadata : arc_util::ListMetadataForBuildProperty(build_property)) {
    AddCrashMetaUploadData(metadata.first, metadata.second);
  }

  for (const auto& mapping : arc_util::kHeaderToFieldMapping) {
    if (map.count(mapping.first)) {
      AddCrashMetaUploadData(mapping.second,
                             arc_util::GetCrashLogHeader(map, mapping.first));
    }
  }

  if (exception_info.empty()) {
    if (const char* const tag = arc_util::GetSubjectTag(crash_type)) {
      std::ostringstream out;
      out << '[' << tag << ']';
      const auto it = map.find(arc_util::kSubjectKey);
      if (it != map.end())
        out << ' ' << it->second;

      AddCrashMetaData(arc_util::kSignatureField, out.str());
    } else {
      LOG(ERROR) << "Invalid crash type: " << crash_type;
      return false;
    }
  } else {
    const FilePath info_path = GetCrashPath(crash_dir, basename, "info");
    const int size = static_cast<int>(exception_info.size());

    if (WriteNewFile(info_path, exception_info) != size) {
      PLOG(ERROR) << "Failed to write exception info";
      return false;
    }

    AddCrashMetaUploadText(arc_util::kExceptionInfoField,
                           info_path.BaseName().value());
  }

  const FilePath meta_path = GetCrashPath(crash_dir, basename, "meta");
  FinishCrash(meta_path, process, log_path.BaseName().value());
  return true;
}

// static
CollectorInfo ArcJavaCollector::GetHandlerInfo(
    const std::string& arc_java_crash,
    const arc_util::BuildProperty& build_property,
    int64_t uptime_millis) {
  auto arc_java_collector = std::make_shared<ArcJavaCollector>();
  return {
      .collector = arc_java_collector,
      .handlers = {{
          // This handles Java app crashes of ARC++ and ARCVM.
          .should_handle = !arc_java_crash.empty(),
          .cb = base::BindRepeating(&ArcJavaCollector::HandleCrash,
                                    arc_java_collector, arc_java_crash,
                                    build_property,
                                    base::Milliseconds(uptime_millis)),
      }},
  };
}

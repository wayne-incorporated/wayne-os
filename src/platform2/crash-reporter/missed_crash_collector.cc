// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/missed_crash_collector.h"

#include <memory>

#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>

#include "crash-reporter/constants.h"

MissedCrashCollector::MissedCrashCollector()
    : CrashCollector("missed_crash"), input_file_(stdin) {}

MissedCrashCollector::~MissedCrashCollector() = default;

bool MissedCrashCollector::Collect(int pid,
                                   int recent_miss_count,
                                   int recent_match_count,
                                   int pending_miss_count) {
  LOG(INFO) << "Processing missed crash for process " << pid;

  std::string logs;
  if (!base::ReadStreamToString(input_file_, &logs)) {
    LOG(ERROR) << "Could not read input logs";
    logs += "<failed read>";
    // Keep going in hopes of getting some information.
  }

  base::FilePath crash_directory;
  // We always use kRootUid here (and thus write to /var/spool/crash), even
  // though the missed crash was probably under user ID 1000. Since we only
  // read system logs and system information, there should be no user-specific
  // information in the logs (that is, the logs don't contain anything from
  // the user's cryptohome). Furthermore, since we are launched by
  // anomaly_detector, we are inside anomaly_detector's minijail. Using the
  // "correct" userid here would mean allowing writes to many more locations in
  // that minijail config. I'd rather keep the write restrictions as tight as
  // possible unless we actually have sensitive information here.
  if (!GetCreatedCrashDirectoryByEuid(constants::kRootUid, &crash_directory,
                                      nullptr)) {
    LOG(WARNING) << "Could not get crash directory (full?)";
    return true;
  }

  StripSensitiveData(&logs);

  constexpr char kExecName[] = "missed_crash";
  std::string dump_basename = FormatDumpBasename(kExecName, time(nullptr), pid);
  const base::FilePath log_path =
      GetCrashPath(crash_directory, dump_basename, "log.gz");
  const base::FilePath meta_path =
      GetCrashPath(crash_directory, dump_basename, "meta");
  if (!WriteNewCompressedFile(log_path, logs.data(), logs.size())) {
    PLOG(WARNING) << "Error writing sanitized log to " << log_path.value();
  }

  AddCrashMetaData("sig", "missed-crash");
  AddCrashMetaUploadData("pid", base::NumberToString(pid));
  AddCrashMetaUploadData("recent_miss_count",
                         base::NumberToString(recent_miss_count));
  AddCrashMetaUploadData("recent_match_count",
                         base::NumberToString(recent_match_count));
  AddCrashMetaUploadData("pending_miss_count",
                         base::NumberToString(pending_miss_count));

  FinishCrash(meta_path, kExecName, log_path.BaseName().value());

  return true;
}

CollectorInfo MissedCrashCollector::GetHandlerInfo(bool missed_chrome_crash,
                                                   int32_t pid,
                                                   int32_t recent_miss_count,
                                                   int32_t recent_match_count,
                                                   int32_t pending_miss_count) {
  auto missed_crash_collector = std::make_shared<MissedCrashCollector>();
  return {
      .collector = missed_crash_collector,
      .handlers = {{
          .should_handle = missed_chrome_crash,
          .cb = base::BindRepeating(
              &MissedCrashCollector::Collect, missed_crash_collector, pid,
              recent_miss_count, recent_match_count, pending_miss_count),
      }},
  };
}

// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/anomaly_detector_log_reader.h"
#include "crash-reporter/anomaly_detector_text_file_reader.h"

#include <string>
#include <utility>

#include <base/logging.h>
#include <base/strings/string_number_conversions.h>

namespace anomaly {

LogReader::LogReader(const base::FilePath& path)
    : log_file_path_(path), log_file_(path) {
  // Go directly to the end of the file.  We don't want to parse the same
  // anomalies multiple times on reboot/restart.  We might miss some
  // anomalies, but so be it---it's too hard to keep track reliably of the
  // last parsed position in the syslog.
  log_file_.SeekToEnd();
}

LogReader::~LogReader() {}

void LogReader::SeekToBegin() {
  log_file_.SeekToBegin();
}

bool LogReader::GetNextEntry(LogEntry* entry) {
  std::string line;
  while (log_file_.GetLine(&line)) {
    // ReadLine returns true if the line contains a valid LogEntry.
    if (ReadLine(line, entry))
      return true;
  }
  return false;
}

bool AuditReader::ReadLine(const std::string& line, LogEntry* entry) {
  std::string log_time, log_message;
  if (!RE2::FullMatch(line, pattern_, &log_time, &log_message)) {
    return false;
  }

  double time_in_seconds;
  if (!base::StringToDouble(log_time, &time_in_seconds)) {
    LOG(WARNING) << "Ingnoring log entry due to invalid timestamp. time="
                 << log_time << " tag=audit"
                 << " message=" << log_message;
    return false;
  }

  entry->tag = "audit";
  entry->message = std::move(log_message);
  entry->timestamp = base::Time::FromDoubleT(time_in_seconds);
  return true;
}

bool MessageReader::ReadLine(const std::string& line, LogEntry* entry) {
  std::string log_time, service_name, log_message;
  if (!RE2::FullMatch(line, pattern_, &log_time, &service_name, &log_message)) {
    return false;
  }

  base::Time time;
  bool result = base::Time::FromString(log_time.c_str(), &time);
  if (!result) {
    LOG(WARNING)
        << "Ingnoring log entry due to invalid RFC3339 timestamp. time="
        << log_time << " tag=" << service_name << " message=" << log_message;
    return false;
  }

  entry->tag = std::move(service_name);
  entry->message = std::move(log_message);
  entry->timestamp = std::move(time);
  return true;
}

}  // namespace anomaly

// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec-foundation/tpm_error/handle_auth_failure.h"

#include <stddef.h>
#include <sys/wait.h>

#include <algorithm>
#include <string>
#include <vector>

#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/no_destructor.h>
#include <base/strings/string_split.h>
#include <re2/re2.h>

#include "libhwsec-foundation/da_reset/da_resetter.h"
#include "libhwsec-foundation/tpm_error/auth_failure_analysis.h"
#include "libhwsec-foundation/tpm_error/tpm_error_data.h"
#include "libhwsec-foundation/tpm_error/tpm_error_uma_reporter_impl.h"

namespace {

constexpr int64_t kLogMaxSize = 20'000;
constexpr int64_t kLogRemainingSize = 10'000;

// This should be read-only after the initialize.
const base::FilePath& LogFile(const char* path = "") {
  static base::NoDestructor<base::FilePath> log_file(path);
  return *log_file;
}

// This should be read-only after the initialize.
const base::FilePath& PermanentLogFile(const char* path = "") {
  static base::NoDestructor<base::FilePath> permanent_log_file(path);
  return *permanent_log_file;
}

// This would be read/write on multiple places.
std::string& LastError() {
  thread_local std::string last_error;
  return last_error;
}

// Append |msg| to |log_path|, and limit the size of log to |kLogMaxSize|;
bool AppendMessage(const base::FilePath& log_path, const std::string& msg) {
  if (!base::PathExists(log_path)) {
    return base::WriteFile(log_path, msg);
  }
  if (!base::AppendToFile(log_path, msg)) {
    return false;
  }

  int64_t file_size;
  if (!base::GetFileSize(log_path, &file_size)) {
    return false;
  }
  if (file_size >= kLogMaxSize) {
    std::string contents;
    if (!base::ReadFileToString(log_path, &contents)) {
      return false;
    }
    // Truncate log size to |kLogRemainingSize|.
    int64_t truncate_size = (int64_t)contents.size() - kLogRemainingSize;
    contents.erase(0, truncate_size);
    return base::WriteFile(log_path, contents);
  }
  return true;
}

// Handle any log message in this file, and send them to |log_file| and
// |permanent_log_file| which is set by InitializeAuthFailureLogging().
bool LogMessageHandler(int severity,
                       const char* file,
                       int line,
                       size_t message_start,
                       const std::string& str) {
  // Skip if the message is not genenrated by this file.
  if (strncmp(file, __FILE__, sizeof(__FILE__)) != 0) {
    return false;
  }
  if (!AppendMessage(LogFile(), str) ||
      !AppendMessage(PermanentLogFile(), str)) {
    LastError() = std::string("error logging");
  }
  return severity != logging::LOGGING_FATAL;
}

// This will log command to the file set by InitializeAuthFailureLogging().
void LogAuthFailureCommand(const struct TpmErrorData& data) {
  LOG(WARNING) << "auth failure: command " << data.command << ", response "
               << data.response;
}

constexpr LazyRE2 auth_failure_command = {
    R"(auth failure: command (\d+), response (\d+))"};

uint32_t GetCommandHash(const base::FilePath& log_path) {
  std::string contents;
  if (!base::ReadFileToString(log_path, &contents)) {
    return 0;
  }
  auto lines = base::SplitString(contents, "\n", base::KEEP_WHITESPACE,
                                 base::SPLIT_WANT_NONEMPTY);

  // Parse TpmErrorData from auth failure log.
  std::vector<struct TpmErrorData> data_set;
  for (const std::string& line : lines) {
    struct TpmErrorData data;
    if (!RE2::PartialMatch(line, *auth_failure_command, &data.command,
                           &data.response)) {
      continue;
    }
    data_set.push_back(data);
  }

  // Uniquify collcection of TpmErrorData.
  std::sort(data_set.begin(), data_set.end());
  auto it = std::unique(data_set.begin(), data_set.end());
  data_set.resize(std::distance(data_set.begin(), it));

  return GetHashFromTpmDataSet(data_set);
}

}  // namespace

extern "C" int FetchAuthFailureError(char out[], size_t size) {
  if (size <= LastError().length() + 1) {
    return 0;
  }

  size_t result_len = LastError().copy(out, LastError().length());
  out[result_len] = '\0';

  LastError().clear();
  return 1;
}

extern "C" void InitializeAuthFailureLogging(const char* log_path,
                                             const char* permanent_log_path) {
  CHECK(logging::GetLogMessageHandler() == nullptr)
      << "LogMessageHandler has already been set";
  LogFile(log_path);
  PermanentLogFile(permanent_log_path);
  logging::SetLogMessageHandler(LogMessageHandler);
}

extern "C" int CheckAuthFailureHistory(const char* current_path,
                                       const char* previous_path,
                                       size_t* auth_failure_hash) {
  base::FilePath current_log(current_path);
  base::FilePath previous_log(previous_path);

  if (!base::PathExists(current_log)) {
    return 0;
  }

  int64_t size;
  if (!base::GetFileSize(current_log, &size)) {
    LastError() = std::string("error checking file size");
    return 0;
  }
  // If there is no failure log in |current_log|, nothing to do here.
  if (size == 0) {
    return 0;
  }

  if (!base::Move(current_log, previous_log)) {
    LastError() = std::string("error moving file");
    return 0;
  }
  if (auth_failure_hash) {
    *auth_failure_hash = GetCommandHash(previous_log);
  }
  return 1;
}

extern "C" int HandleAuthFailure(const struct TpmErrorData* data) {
  if (!hwsec_foundation::DoesCauseDAIncrease(*data)) {
    return true;
  }

  LogAuthFailureCommand(*data);

  hwsec_foundation::TpmErrorUmaReporterImpl reporter;

  reporter.Report(*data);

  hwsec_foundation::DAResetter resetter;
  return resetter.ResetDictionaryAttackLock();
}

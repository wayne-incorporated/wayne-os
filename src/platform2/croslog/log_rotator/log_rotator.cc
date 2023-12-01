// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "croslog/log_rotator/log_rotator.h"

#include <algorithm>
#include <string>
#include <vector>

#include <base/files/file_enumerator.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>

#include "croslog/constants.h"

namespace log_rotator {

constexpr int DAYS_TO_PRESERVE_LOGS = 7;

LogRotator::LogRotator(base::FilePath base_log_path)
    : base_log_path_(base_log_path) {}

// Creating a new log file for Forwarder is handled outside this code.

base::FilePath LogRotator::GetFilePathWithIndex(int index) {
  CHECK_GE(index, 0);
  if (index == 0)
    return base_log_path_;

  return base_log_path_.InsertBeforeExtensionASCII("." +
                                                   base::NumberToString(index));
}

int LogRotator::GetIndexFromFilePath(const base::FilePath& log_path) {
  if (log_path == base_log_path_)
    return 0;

  if (log_path.value().length() <= base_log_path_.value().length()) {
    // Invalid input, since the given path must be longer than the base path.
    return -1;
  }

  // Verify the base part (before the index number) of the path.
  const base::FilePath base_path_body = base_log_path_.RemoveFinalExtension();
  size_t base_path_body_len = base_path_body.value().length();
  const std::string& log_path_body =
      log_path.value().substr(0, base_path_body_len);
  if (log_path_body != base_path_body.value()) {
    // Invalid input, since the path str doesn't start with the path string
    return -1;
  }
  if (log_path.value()[base_path_body_len] != '.') {
    // Invalid input, since in the path, the dot doesn't follow with the base
    // path.
    return -1;
  }

  // Verify the final extension of the path.
  const std::string& final_extension = base_log_path_.FinalExtension();
  size_t final_extension_len = final_extension.length();
  const std::string& log_path_final_extension = log_path.value().substr(
      log_path.value().length() - final_extension_len, final_extension_len);
  if (log_path_final_extension != final_extension) {
    // Invalid input, since the path str doesn't start with the path string
    return -1;
  }

  // Extract the index number.
  const std::string& log_path_index_str = log_path.value().substr(
      base_path_body_len + 1,
      log_path.value().length() - base_path_body_len - final_extension_len - 1);
  int index = 0;
  if (!base::StringToInt(log_path_index_str, &index))
    return -1;

  if (index == 0) {
    // The ".0" extension is invalid. The 0-th file should have no extension.
    return -1;
  }

  return index;
}

void LogRotator::CleanUpFiles(int max_index) {
  base::FilePath dir = base_log_path_.DirName();
  base::FilePath pattern = base_log_path_.BaseName().AddExtension("*");

  base::FileEnumerator file_enumerator(dir, false, base::FileEnumerator::FILES,
                                       pattern.value());

  while (!file_enumerator.Next().empty()) {
    base::FilePath file_path = dir.Append(file_enumerator.GetInfo().GetName());
    int index = GetIndexFromFilePath(file_path);
    if (index > max_index || index < 0)
      base::DeleteFile(file_path);
  }
}

void LogRotator::RotateLogFile(int max_index) {
  std::vector<base::FileEnumerator::FileInfo> info;

  base::FilePath max_index_path = GetFilePathWithIndex(max_index);
  if (base::PathExists(max_index_path))
    base::DeleteFile(max_index_path);

  for (int i = (max_index - 1); i >= 0; --i) {
    base::FilePath old_path = GetFilePathWithIndex(i);
    base::FilePath new_path = GetFilePathWithIndex(i + 1);

    if (!base::PathExists(old_path))
      continue;

    if (!base::Move(old_path, new_path)) {
      LOG(ERROR) << "File error while moving " << old_path << " to " << new_path
                 << ": "
                 << base::File::ErrorToString(base::File::GetLastFileError());
    }
  }

  CleanUpFiles(max_index);
  CreateNewBaseFile(max_index);
}

void LogRotator::CreateNewBaseFile(int max_index) {
  const base::FilePath base_file_path = GetFilePathWithIndex(0);
  if (base::PathExists(base_file_path))
    return;

  int mode = -1;
  uid_t uid = 0;
  gid_t gid = 0;
  bool failed_on_stat = false;
  // Traverse the log files from newer one, and retrieve the file info.
  for (int i = 1; i < max_index; ++i) {
    const base::FilePath previous_file_path = GetFilePathWithIndex(i);
    if (!base::PathExists(previous_file_path))
      continue;

    base::stat_wrapper_t file_info;
    if (base::File::Stat(previous_file_path.value().c_str(), &file_info) == 0) {
      constexpr int kFilePermissionMask = S_IRWXU | S_IRWXG | S_IRWXO;
      mode = file_info.st_mode & kFilePermissionMask;
      uid = file_info.st_uid;
      gid = file_info.st_gid;
      break;
    } else {
      PLOG(ERROR) << "Error on retrieving the file info: "
                  << previous_file_path;
      failed_on_stat = true;
    }
  }

  if (mode == -1) {
    if (failed_on_stat) {
      // Show an error only when the stat was called but failed.
      LOG(ERROR) << "A new log file won't be created, because retrieving the "
                    "mode from the all old files was failed.";
    }
    return;
  }

  // Create the log file.
  base::File base_file(base_file_path,
                       base::File::FLAG_CREATE | base::File::FLAG_WRITE);
  if (!base_file.IsValid()) {
    LOG(ERROR) << "Failed to create or open a new log file.";
    return;
  }

  // Set the same permission.
  if (HANDLE_EINTR(fchmod(base_file.GetPlatformFile(), mode)) != 0) {
    LOG(ERROR) << "Failed to set the mode to the new log file.";
  }

  // Set the same owner.
  if (HANDLE_EINTR(fchown(base_file.GetPlatformFile(), uid, gid)) != 0) {
    LOG(ERROR) << "Failed to set the owner and group to the new log file.";
  }
}

void RotateStandardLogFiles() {
  for (const auto& base_log_path_str : croslog::kLogsToRotate) {
    const base::FilePath& base_log_path =
        base::FilePath{base_log_path_str.data()};
    LogRotator rotator(base_log_path);
    rotator.RotateLogFile(DAYS_TO_PRESERVE_LOGS);
  }
}

}  // namespace log_rotator

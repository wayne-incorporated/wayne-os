// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CROSLOG_LOG_ROTATOR_LOG_ROTATOR_H_
#define CROSLOG_LOG_ROTATOR_LOG_ROTATOR_H_

#include <base/files/file_path.h>

namespace log_rotator {

class LogRotator {
 public:
  // Constructor. |base_log_file| is the file path without any index number
  // (eg. "/var/log/messages").
  explicit LogRotator(base::FilePath base_log_path);
  LogRotator(const LogRotator&) = delete;
  LogRotator& operator=(const LogRotator&) = delete;

  // Retrieve the log file path from the index number.
  base::FilePath GetFilePathWithIndex(int index);
  // Retrieve the index number from the log file path.
  int GetIndexFromFilePath(const base::FilePath& log_path);

  // Clean-up the files which are not necessary.
  void CleanUpFiles(int max_index);
  // Rotate the log files. This method keeps (|max_index| + 1) files in
  // maximum, including the log file numbered |max_index|.
  void RotateLogFile(int max_index);
  // Create the base log file with copying the permission from the previous
  // log files. It should be called after rotation.
  void CreateNewBaseFile(int max_index);

 private:
  base::FilePath base_log_path_;
};

// Rotate the standard log files defined in kLogSources in |log_path_constant|.
void RotateStandardLogFiles();

}  // namespace log_rotator

#endif  // CROSLOG_LOG_ROTATOR_LOG_ROTATOR_H_

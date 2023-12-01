// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// A simple program that locks a file (given on the command line). Helper
// binary for crash_sender_util_test.cc. It's necessary because a program can
// relock a file even if it already holds a lock on the file; to test the
// program's behavior when the file is locked, we need a separate program that
// locks the file.

#include <stdlib.h>

#include <base/files/file.h>
#include <base/logging.h>
#include <base/threading/platform_thread.h>
#include <base/time/time.h>
#include <brillo/syslog_logging.h>

int main(int argc, char** argv) {
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderr);

  if (argc != 2) {
    LOG(ERROR)
        << "Usage: hold_lock_file file_name.\n"
        << "Locks the given file. Will create the file if it doesn't exist.";
    return -1;
  }

  base::FilePath lock_file_path(argv[1]);
  base::File lock_file(lock_file_path, base::File::FLAG_OPEN_ALWAYS |
                                           base::File::FLAG_READ |
                                           base::File::FLAG_WRITE);
  if (!lock_file.IsValid()) {
    LOG(ERROR) << "Error opening " << lock_file_path.value() << ": "
               << base::File::ErrorToString(lock_file.error_details());
    return -2;
  }

  auto result = lock_file.Lock(base::File::LockMode::kExclusive);
  if (result != base::File::FILE_OK) {
    LOG(ERROR) << "Error locking " << lock_file_path.value() << ": "
               << base::File::ErrorToString(result);
    return -3;
  }

  // Normally, the parent unit test will kill us. But just in case the parent
  // crashes, eventually exit.
  base::PlatformThread::Sleep(base::Seconds(30));
  return 0;
}

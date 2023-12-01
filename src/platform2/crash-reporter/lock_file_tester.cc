// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// A simple program that checks if a file (given on the command line) is locked.
// It is a helper for crash_sender_util_test.cc. It's necessary because a
// program can't really check if it is holding a lock on a file itself
// (https://stackoverflow.com/q/55944551/608736).
// It exits with 0 if the file is locked, 1 if the file is not locked, and
// a negative exit value if the file can't be found or there are other errors.

#include <stdlib.h>

#include <base/files/file.h>
#include <base/logging.h>
#include <brillo/syslog_logging.h>

int main(int argc, char* argv[]) {
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderr);

  if (argc != 2) {
    LOG(ERROR)
        << "Usage: lock_file_tester file_name.\n"
        << "Tests to see if file_name is locked by another process. Exit\n"
        << "status 0 if locked, 1 if not locked.";
    exit(-1);
  }

  base::FilePath lock_file_path(argv[1]);
  base::File lock_file(lock_file_path, base::File::FLAG_OPEN |
                                           base::File::FLAG_READ |
                                           base::File::FLAG_WRITE);
  if (!lock_file.IsValid()) {
    LOG(ERROR) << "Error opening " << lock_file_path.value() << ": "
               << base::File::ErrorToString(lock_file.error_details());
    exit(-2);
  }

  if (lock_file.Lock(base::File::LockMode::kExclusive) == base::File::FILE_OK) {
    // We could lock the file, therefore no one else had locked it.
    exit(1);
  }

  // There is no way in the base::File API to distinguish "file is locked by
  // another process" vs "A different error occurred", so we treat all failures
  // as the former.
  exit(0);
}

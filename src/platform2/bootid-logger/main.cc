// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#include <sys/stat.h>

#include "base/files/file_util.h"
#include "base/files/scoped_file.h"
#include "base/logging.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/time/time.h"

#include "bootid-logger/bootid_logger.h"
#include "bootid-logger/timestamp_util.h"

namespace {

constexpr char kBootLogFile[] = "/var/log/boot_id.log";
constexpr size_t kBootLogMaxEntries = 500;

}  // anonymous namespace

int main(int argc, char* argv[]) {
  if (argc > 2) {
    LOG(ERROR) << "Doesn't support any command line options.";
    exit(EXIT_FAILURE);
  }

  struct stat sb;
  stat(kBootLogFile, &sb);
  if ((sb.st_mode & S_IFMT) != S_IFREG) {
    // The file is not a regular file. Remove this.
    unlink(kBootLogFile);
  }

  // Keep only the recent boot id logs so that the logs can cover the time of
  // |GetOldestModifiedTime()|.
  // Note: we keep logs at least for 8 day, even If |GetOldestModifiedTime()|
  // returns a most recent time.
  base::Time first_timestamp_to_keep =
      std::min(GetOldestModifiedTime(), base::Time::Now() - base::Days(8));

  if (WriteCurrentBootEntry(base::FilePath(kBootLogFile),
                            first_timestamp_to_keep, kBootLogMaxEntries))
    return 0;
  else
    return EXIT_FAILURE;
}

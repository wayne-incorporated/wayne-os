// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_APK_CACHE_APK_CACHE_CTL_COMMANDS_H_
#define ARC_APK_CACHE_APK_CACHE_CTL_COMMANDS_H_

#include <sysexits.h>

#include <iostream>

namespace base {
class FilePath;
}  // namespace base

namespace apk_cache {

// The program exits with these codes when error happens.
enum class ExitCode : int {
  // Exit normally.
  kOk = EX_OK,
  // APK Cache Database is not found. This means ApkCacheProvider has not
  // created the database.
  kErrorNoDatabase = 4,
  // APK Cache Database cannot be opened.
  kErrorDatabaseOpenFail = 5,
  // A query in the database fails.
  kErrorDatabaseQueryFail = 6
};

// Lists file entries stored in APK Cache. APK Cache directory is specified in
// |cache_root|. Results will be written to |out_stream|. Returns exit code.
// Returns 0 is there is no error. Error codes are defined in enum |ExitCode|.
ExitCode CommandLs(const base::FilePath& cache_root, std::ostream& out_stream);

}  // namespace apk_cache

#endif  // ARC_APK_CACHE_APK_CACHE_CTL_COMMANDS_H_

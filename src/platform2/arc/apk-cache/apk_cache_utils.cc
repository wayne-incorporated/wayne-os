// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/apk-cache/apk_cache_utils.h"

#include <array>
#include <cinttypes>
#include <iomanip>
#include <string>

#include <base/strings/stringprintf.h>

namespace apk_cache {

// APK Cache paths
constexpr char kApkCacheDir[] = "/mnt/stateful_partition/unencrypted/apkcache";
constexpr int kDatabaseFilesCount = 4;
constexpr char const* kDatabaseFiles[4] = {"index.db", "index.db-shm",
                                           "index.db-wal", "index.db-journal"};
constexpr char kDatabaseFile[] = "index.db";
constexpr char kFilesBase[] = "files";

// Value for |status| in |sessions| table.
constexpr int32_t kSessionStatusOpen = 1;
constexpr int32_t kSessionStatusClosed = 2;

// Value for |type| in |file_entries| table.
constexpr char kFileTypeBaseApk[] = "play.apk.base";

std::string GetFileNameById(int64_t id) {
  return base::StringPrintf("%016" PRIx64, id);
}

}  // namespace apk_cache

// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_APK_CACHE_APK_CACHE_UTILS_H_
#define ARC_APK_CACHE_APK_CACHE_UTILS_H_

#include <string>

namespace apk_cache {

// APK Cache base directory. All files including the database are stored here.
extern const char kApkCacheDir[];
// Expose database files to old cache cleaner so that it will not delete the
// database. Will be removed once old cache cleaner is removed.
extern const int kDatabaseFilesCount;
extern const char* const kDatabaseFiles[];
// APK Cache index database file name.
extern const char kDatabaseFile[];
// APK Cache files directory name. All cached files are stored under this.
extern const char kFilesBase[];

// Session status for testing.
extern const int32_t kSessionStatusOpen;
extern const int32_t kSessionStatusClosed;

// File types for testing.
extern const char kFileTypeBaseApk[];

// Generate file name from given file entry id.
std::string GetFileNameById(int64_t id);

}  // namespace apk_cache

#endif  // ARC_APK_CACHE_APK_CACHE_UTILS_H_

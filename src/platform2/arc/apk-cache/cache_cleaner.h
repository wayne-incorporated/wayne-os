// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_APK_CACHE_CACHE_CLEANER_H_
#define ARC_APK_CACHE_CACHE_CLEANER_H_

namespace base {
class FilePath;
class TimeDelta;
}  // namespace base

namespace apk_cache {

extern const char kAttrJson[];
extern const char kApkExtension[];
extern const char kObbExtension[];
extern const char kMainObbPrefix[];
extern const char kPatchObbPrefix[];
extern const base::TimeDelta kValidityPeriod;

// Performs cleaning of the APK cache directory. The path to the cache
// directory must be provided as |cache_path| parameter.
// It deletes:
// - all the files in the cache root;
// - all the package directories that:
//     1. have not been used last |kValidityPeriod|;
//     2. contain unexpected files. Any file except APK, main and patch OBB
//        and JSON with package attributes is considered unexpected;
//     3. contain directories;
//     4. contain no or more then one APK file, no attributes JSON file,
//        more than one main OBB file, more than one patch OBB file.
// Returns true if all the intended files and directories were successfully
// deleted.
bool Clean(const base::FilePath& cache_path);

}  // namespace apk_cache

#endif  // ARC_APK_CACHE_CACHE_CLEANER_H_

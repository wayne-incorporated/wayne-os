// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_APK_CACHE_CACHE_CLEANER_UTILS_H_
#define ARC_APK_CACHE_CACHE_CLEANER_UTILS_H_

#include <string>
#include <unordered_set>

namespace base {
class FilePath;
}  // namespace base

namespace apk_cache {

// Removes all unexpected items of type |item_type| (if any) from root.
// |item_type| should be base::FileEnumerator::FileType.
// Returns true if all the intended items were deleted.
bool RemoveUnexpectedItemsFromDir(
    const base::FilePath& root,
    int item_type,
    const std::unordered_set<std::string>& expected_items);

}  // namespace apk_cache

#endif  // ARC_APK_CACHE_CACHE_CLEANER_UTILS_H_

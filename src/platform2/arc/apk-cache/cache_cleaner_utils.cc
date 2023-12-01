// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/apk-cache/cache_cleaner_utils.h"

#include <string>
#include <unordered_set>

#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <brillo/files/file_util.h>

namespace apk_cache {

bool RemoveUnexpectedItemsFromDir(
    const base::FilePath& root,
    int item_type,
    const std::unordered_set<std::string>& expected_items) {
  bool success = true;
  base::FileEnumerator unexpected_items(root, false /* recursive */, item_type);

  for (base::FilePath unexpected_file_path = unexpected_items.Next();
       !unexpected_file_path.empty();
       unexpected_file_path = unexpected_items.Next()) {
    if (expected_items.find(unexpected_file_path.BaseName().MaybeAsASCII()) ==
        expected_items.end()) {
      LOG(INFO) << "Deleting " << unexpected_file_path.value();
      if (!brillo::DeletePathRecursively(unexpected_file_path)) {
        LOG(ERROR) << "Could not delete " << unexpected_file_path.value();
        success = false;
      }
    }
  }

  return success;
}

}  // namespace apk_cache

// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MISSIVE_STORAGE_STORAGE_UTIL_H_
#define MISSIVE_STORAGE_STORAGE_UTIL_H_

#include <string>
#include <tuple>
#include <unordered_set>

#include "missive/storage/storage_configuration.h"

namespace reporting {

class StorageDirectory {
 public:
  struct Hash {
    size_t operator()(
        const std::tuple<Priority, GenerationGuid>& v) const noexcept {
      const auto& [priority, guid] = v;
      static constexpr std::hash<Priority> priority_hasher;
      static constexpr std::hash<GenerationGuid> guid_hasher;
      return priority_hasher(priority) ^ guid_hasher(guid);
    }
  };
  using Set = std::unordered_set<std::tuple<Priority, GenerationGuid>, Hash>;
  static bool DeleteEmptySubdirectories(const base::FilePath directory);
  static Set FindQueueDirectories(const StorageOptions& options);

  static StatusOr<std::tuple<Priority, GenerationGuid>>
  GetPriorityAndGenerationGuid(const base::FilePath& full_name,
                               const StorageOptions& options);
  static StatusOr<GenerationGuid> ParseGenerationGuidFromFileName(
      const base::FilePath& full_name);
  static StatusOr<Priority> ParsePriorityFromQueueDirectory(
      const base::FilePath full_path, const StorageOptions& options);
};
}  // namespace reporting

#endif  // MISSIVE_STORAGE_STORAGE_UTIL_H_

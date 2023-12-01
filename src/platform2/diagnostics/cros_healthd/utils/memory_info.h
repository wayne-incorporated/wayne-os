// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_UTILS_MEMORY_INFO_H_
#define DIAGNOSTICS_CROS_HEALTHD_UTILS_MEMORY_INFO_H_

#include <stdint.h>

#include <optional>

#include <base/files/file_path.h>

namespace diagnostics {

// Store the system memory info from |/proc/meminfo|.
struct MemoryInfo {
  uint32_t total_memory_kib;
  uint32_t free_memory_kib;
  uint32_t available_memory_kib;

  // Gets the parsing result of |proc/meminfo| under |root_path|. If there is a
  // parse error, return std::nullopt.
  static std::optional<MemoryInfo> ParseFrom(const base::FilePath& root_path);
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_UTILS_MEMORY_INFO_H_

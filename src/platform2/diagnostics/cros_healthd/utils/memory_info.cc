// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/utils/memory_info.h"

#include <stdint.h>

#include <map>
#include <optional>
#include <string>

#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_tokenizer.h>

#include "diagnostics/base/file_utils.h"

namespace diagnostics {

namespace {

constexpr char kRelativeMeminfoPath[] = "proc/meminfo";
constexpr char kMemTotalName[] = "MemTotal";
constexpr char kMemFreeName[] = "MemFree";
constexpr char kMemAvailableName[] = "MemAvailable";

bool ParseRow(std::string raw_value, uint32_t* out_value) {
  // Parse each line in /proc/meminfo.
  // Format of |raw_value|: "${MEM_NAME}${PAD_SPACES}${MEM_AMOUNT} kb"
  base::StringTokenizer t(raw_value, " ");
  return t.GetNext() && base::StringToUint(t.token(), out_value) &&
         t.GetNext() && t.token() == "kB";
}

std::optional<MemoryInfo> Parse(const std::string& raw_data) {
  base::StringPairs pairs;
  if (!base::SplitStringIntoKeyValuePairs(raw_data, ':', '\n', &pairs)) {
    LOG(ERROR) << "Incorrectly formatted /proc/meminfo";
    return std::nullopt;
  }

  // Parse the meminfo contents for MemTotal, MemFree and MemAvailable. Note
  // that these values are actually reported in KiB from /proc/meminfo, despite
  // claiming to be in kB.
  std::map<std::string, uint32_t> memory_map_kib;
  uint32_t out_memory_kib;
  for (int i = 0; i < pairs.size(); i++) {
    if (pairs[i].first == kMemTotalName || pairs[i].first == kMemFreeName ||
        pairs[i].first == kMemAvailableName) {
      if (!ParseRow(pairs[i].second, &out_memory_kib)) {
        LOG(ERROR) << "Incorrectly formatted: " << pairs[i].first;
        return std::nullopt;
      }
      memory_map_kib[pairs[i].first] = out_memory_kib;
    }
  }

  for (const auto& memory_name :
       {kMemTotalName, kMemFreeName, kMemAvailableName}) {
    auto itr = memory_map_kib.find(memory_name);
    if (itr == memory_map_kib.end()) {
      LOG(ERROR) << memory_name << " not found in /proc/meminfo";
      return std::nullopt;
    }
  }

  return MemoryInfo{.total_memory_kib = memory_map_kib[kMemTotalName],
                    .free_memory_kib = memory_map_kib[kMemFreeName],
                    .available_memory_kib = memory_map_kib[kMemAvailableName]};
}

}  // namespace

std::optional<MemoryInfo> MemoryInfo::ParseFrom(
    const base::FilePath& root_path) {
  std::string file_contents;
  if (!ReadAndTrimString(root_path.Append(kRelativeMeminfoPath),
                         &file_contents)) {
    LOG(ERROR) << "Unable to read /proc/meminfo";
    return std::nullopt;
  }
  return Parse(file_contents);
}

}  // namespace diagnostics

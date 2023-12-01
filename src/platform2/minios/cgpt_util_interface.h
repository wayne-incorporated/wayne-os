// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MINIOS_CGPT_UTIL_INTERFACE_H_
#define MINIOS_CGPT_UTIL_INTERFACE_H_

#include <cstdint>
#include <optional>
#include <string>

namespace minios {

// Util to interact with the partition table.
class CgptUtilInterface {
 public:
  virtual ~CgptUtilInterface() = default;
  // Get partition number associated with a given label. Case sensitive. If
  // number of partitions with the given label is not equal to exactly 1, return
  // `nullopt`.
  virtual std::optional<int> GetPartitionNumber(
      const std::string& label) const = 0;
  // Given a valid partition number, return size of partition. Otherwise return
  // `nullopt`.
  virtual std::optional<uint64_t> GetSize(
      const uint32_t partition_number) const = 0;
};

}  // namespace minios

#endif  // MINIOS_CGPT_UTIL_INTERFACE_H_

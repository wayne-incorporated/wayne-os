// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_TOOLS_BATTERY_SAVER_PROTO_UTIL_H_
#define POWER_MANAGER_TOOLS_BATTERY_SAVER_PROTO_UTIL_H_

#include <algorithm>
#include <optional>
#include <string>
#include <vector>

namespace power_manager {

// Serialize the given proto instance into a `std::vector<uint8_t>`.
template <typename T>
std::vector<uint8_t> SerializeProto(const T& proto) {
  std::string serialized_proto = proto.SerializeAsString();
  std::vector<uint8_t> result;
  std::copy(serialized_proto.begin(), serialized_proto.end(),
            std::back_inserter(result));
  return result;
}

// Deserialize the given `std::vector<uint8_t>` into a proto.
//
// Returns std::nullopt on error.
template <typename T>
std::optional<T> DeserializeProto(const std::vector<uint8_t>& data) {
  T result{};
  bool success = result.ParseFromArray(data.data(), data.size());
  if (!success) {
    return std::nullopt;
  }
  return result;
}

}  // namespace power_manager

#endif  // POWER_MANAGER_TOOLS_BATTERY_SAVER_PROTO_UTIL_H_

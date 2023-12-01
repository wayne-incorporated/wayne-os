// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net-base/ip_address_utils.h"

#include <optional>
#include <string>
#include <utility>

#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>

namespace net_base {

std::optional<std::pair<std::string, int>> SplitCIDRString(
    const std::string& address_string) {
  const auto address_parts = base::SplitString(
      address_string, "/", base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
  if (address_parts.size() != 2) {
    return std::nullopt;
  }

  int prefix_length;
  if (!base::StringToInt(address_parts[1], &prefix_length)) {
    return std::nullopt;
  }
  return std::make_pair(address_parts[0], prefix_length);
}

}  // namespace net_base

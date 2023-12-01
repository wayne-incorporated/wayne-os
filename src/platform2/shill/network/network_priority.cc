// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/network/network_priority.h"

namespace shill {

bool operator==(const NetworkPriority& lhs, const NetworkPriority& rhs) {
  return lhs.is_primary_logical == rhs.is_primary_logical &&
         lhs.is_primary_physical == rhs.is_primary_physical &&
         lhs.is_primary_for_dns == rhs.is_primary_for_dns &&
         lhs.ranking_order == rhs.ranking_order;
}

std::ostream& operator<<(std::ostream& stream,
                         const NetworkPriority& priority) {
  stream << "{";
  stream << priority.ranking_order;
  if (priority.is_primary_logical) {
    stream << ", primary_logical";
  }
  if (priority.is_primary_physical) {
    stream << ", primary_physical";
  }
  if (priority.is_primary_for_dns) {
    stream << ", primary_for_dns";
  }
  return stream << "}";
}
}  // namespace shill

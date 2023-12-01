// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "missive/analytics/registry.h"

#include <utility>

#include <base/location.h>

namespace reporting::analytics {

void Registry::Add(base::StringPiece name,
                   std::unique_ptr<ResourceCollector> collector) {
  resource_collectors_.insert_or_assign(std::string(name),
                                        std::move(collector));
}

bool Registry::Remove(base::StringPiece name) {
  auto it = resource_collectors_.find(std::string(name));
  if (it == resource_collectors_.end()) {
    return false;
  }
  resource_collectors_.erase(it);
  return true;
}

}  // namespace reporting::analytics

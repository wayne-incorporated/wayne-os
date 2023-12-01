// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "runtime_probe/functions/generic_network.h"

#include <optional>

namespace runtime_probe {

std::optional<std::string> GenericNetworkFunction::GetNetworkType() const {
  return std::nullopt;
}

}  // namespace runtime_probe

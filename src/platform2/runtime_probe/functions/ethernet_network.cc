// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "runtime_probe/functions/ethernet_network.h"

#include <chromeos/dbus/shill/dbus-constants.h>

#include <optional>

namespace runtime_probe {

std::optional<std::string> EthernetNetworkFunction::GetNetworkType() const {
  return shill::kTypeEthernet;
}

}  // namespace runtime_probe

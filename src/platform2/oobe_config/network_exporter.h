// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef OOBE_CONFIG_NETWORK_EXPORTER_H_
#define OOBE_CONFIG_NETWORK_EXPORTER_H_

#include <optional>
#include <string>

namespace oobe_config {

// Exports network configuration for rollback from Chrome. Only call with the
// oobe_config_save user and while Chrome and shill are running.
std::optional<std::string> ExportNetworkConfig();

}  // namespace oobe_config

#endif  // OOBE_CONFIG_NETWORK_EXPORTER_H_

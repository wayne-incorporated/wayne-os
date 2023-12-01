// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "biod/biod_config.h"

#include <optional>
#include <string>

#include <cros_config/cros_config_interface.h>

namespace biod {

// Since /fingerprint/sensor-location is an optional field, the only information
// that is relevant to the updater is if fingerprint is explicitly supported.
bool FingerprintSupported(brillo::CrosConfigInterface* cros_config) {
  std::string fingerprint_location;
  if (cros_config->GetString(kCrosConfigFPPath, kCrosConfigFPLocation,
                             &fingerprint_location)) {
    if (fingerprint_location != "none") {
      return true;
    }
  }

  return false;
}

std::optional<std::string> FingerprintBoard(
    brillo::CrosConfigInterface* cros_config) {
  std::string board_name;
  if (!cros_config->GetString(kCrosConfigFPPath, kCrosConfigFPBoard,
                              &board_name)) {
    return std::nullopt;
  }
  return board_name;
}

}  // namespace biod

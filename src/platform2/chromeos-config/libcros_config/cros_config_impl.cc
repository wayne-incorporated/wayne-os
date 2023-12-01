// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Library to provide access to the Chrome OS model configuration

#include <cstdlib>

#include "chromeos-config/libcros_config/cros_config_interface.h"

namespace brillo {

bool CrosConfigInterface::IsLoggingEnabled() {
  static const char* logging_var = getenv("CROS_CONFIG_DEBUG");
  static bool enabled = logging_var && *logging_var;
  return enabled;
}

}  // namespace brillo

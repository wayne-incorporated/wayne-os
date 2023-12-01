// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/logging.h>
#include "biod/utils.h"

#include <string>

namespace biod {

std::string LogSafeID(const std::string& id) {
  // Truncate the string to the first 2 chars without extending to 2 chars.
  if (id.length() > 2) {
    return id.substr(0, 2) + "*";
  }
  return id;
}

void LogOnSignalConnected(const std::string& interface_name,
                          const std::string& signal_name,
                          bool success) {
  if (!success)
    LOG(ERROR) << "Failed to connect to signal " << signal_name
               << " of interface " << interface_name;
}

}  // namespace biod

// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/supplicant/wpa_supplicant.h"

#include <string>

#include "shill/logging.h"

#include <base/logging.h>

namespace shill {

// static

// static
bool WPASupplicant::ExtractRemoteCertification(const KeyValueStore& properties,
                                               std::string* subject,
                                               uint32_t* depth) {
  if (!properties.Contains<uint32_t>(WPASupplicant::kInterfacePropertyDepth)) {
    LOG(ERROR) << __func__ << " no depth parameter.";
    return false;
  }
  if (!properties.Contains<std::string>(
          WPASupplicant::kInterfacePropertySubject)) {
    LOG(ERROR) << __func__ << " no subject parameter.";
    return false;
  }

  *depth = properties.Get<uint32_t>(WPASupplicant::kInterfacePropertyDepth);
  *subject =
      properties.Get<std::string>(WPASupplicant::kInterfacePropertySubject);
  return true;
}

}  // namespace shill

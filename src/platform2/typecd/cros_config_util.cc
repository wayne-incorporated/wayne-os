// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "typecd/cros_config_util.h"

#include <string>

#include <base/logging.h>
#include <base/strings/string_util.h>

namespace typecd {

CrosConfigUtil::CrosConfigUtil() {
  config_ = std::make_unique<brillo::CrosConfig>();
}

bool CrosConfigUtil::APModeEntryDPOnly() {
  std::string dp_only;
  if (!config_->GetString("/typecd", "mode-entry-dp-only", &dp_only)) {
    LOG(INFO) << "Can't access DP-only config; assuming USB4 support.";
    return false;
  }

  base::TrimWhitespaceASCII(dp_only, base::TRIM_TRAILING, &dp_only);
  if (dp_only == "true") {
    LOG(INFO) << "Restricting AP-driven mode entry to DisplayPort only.";
    return true;
  }

  return false;
}

}  // namespace typecd

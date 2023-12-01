// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "lorgnette/debug_log.h"

#include <stdlib.h>
#include <utility>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <brillo/files/file_util.h>

namespace lorgnette {

namespace {

constexpr char kDebugFlagPath[] = "/run/lorgnette/debug/debug-flag";

}  // namespace

DebugLogManager::DebugLogManager()
    : debug_flag_path_{base::FilePath(kDebugFlagPath)} {}

bool DebugLogManager::IsDebuggingEnabled() const {
  return base::PathExists(debug_flag_path_);
}

SetDebugConfigResponse DebugLogManager::UpdateDebugConfig(
    const SetDebugConfigRequest& request) {
  SetDebugConfigResponse response;
  response.set_old_enabled(IsDebuggingEnabled());
  response.set_success(true);
  if (request.enabled()) {
    if (!base::WriteFile(debug_flag_path_, "")) {
      LOG(ERROR) << "Failed to create debug flag at " << debug_flag_path_;
      response.set_success(false);
    }
  } else {
    if (!brillo::DeleteFile(debug_flag_path_)) {
      LOG(ERROR) << "Failed to remove debug flag at " << debug_flag_path_;
      response.set_success(false);
    }
  }
  return response;
}

bool DebugLogManager::SetupDebugging() {
  if (!IsDebuggingEnabled()) {
    return false;
  }

  setenv("PFUFS_DEBUG", "1", 1);
  setenv("SANE_DEBUG_AIRSCAN", "16", 1);
  setenv("SANE_DEBUG_EPSONDS", "16", 1);
  setenv("SANE_DEBUG_EPSON2", "16", 1);
  setenv("SANE_DEBUG_FUJITSU", "20", 1);
  setenv("SANE_DEBUG_PIXMA", "4", 1);

  return true;
}

void DebugLogManager::SetFlagPathForTesting(base::FilePath path) {
  debug_flag_path_ = std::move(path);
}

}  // namespace lorgnette

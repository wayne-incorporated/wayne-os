// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <rmad/utils/futility_utils_impl.h>

#include <memory>
#include <sstream>
#include <string>
#include <utility>

#include <base/files/file_path.h>
#include <base/files/scoped_temp_dir.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <re2/re2.h>

#include "rmad/utils/cmd_utils_impl.h"

namespace {

constexpr char kFutilityCmd[] = "/usr/bin/futility";
constexpr char kFutilityWriteProtectDisabledStr[] = "WP status: disabled";

}  // namespace

namespace rmad {

FutilityUtilsImpl::FutilityUtilsImpl() : FutilityUtils() {
  cmd_utils_ = std::make_unique<CmdUtilsImpl>();
}

FutilityUtilsImpl::FutilityUtilsImpl(std::unique_ptr<CmdUtils> cmd_utils)
    : FutilityUtils(), cmd_utils_(std::move(cmd_utils)) {}

bool FutilityUtilsImpl::GetApWriteProtectionStatus(bool* enabled) {
  std::string futility_output;
  // Get WP status output string.
  if (!cmd_utils_->GetOutput(
          {kFutilityCmd, "flash", "--wp-status", "--ignore-hw"},
          &futility_output)) {
    return false;
  }

  // Check if WP is disabled.
  *enabled = (futility_output.find(kFutilityWriteProtectDisabledStr) ==
              std::string::npos);
  return true;
}

bool FutilityUtilsImpl::EnableApSoftwareWriteProtection() {
  // Enable AP WP.
  if (std::string output;
      !cmd_utils_->GetOutput({kFutilityCmd, "flash", "--wp-enable"}, &output)) {
    LOG(ERROR) << "Failed to enable AP SWWP";
    LOG(ERROR) << output;
    return false;
  }

  return true;
}

bool FutilityUtilsImpl::DisableApSoftwareWriteProtection() {
  // Disable AP WP.
  if (std::string output; !cmd_utils_->GetOutput(
          {kFutilityCmd, "flash", "--wp-disable"}, &output)) {
    LOG(ERROR) << "Failed to disable AP SWWP";
    LOG(ERROR) << output;
    return false;
  }

  return true;
}

}  // namespace rmad

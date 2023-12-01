// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/utils/write_protect_utils_impl.h"

#include <memory>
#include <utility>

#include <base/logging.h>

#include "rmad/utils/crossystem_utils_impl.h"
#include "rmad/utils/ec_utils_impl.h"
#include "rmad/utils/futility_utils_impl.h"

namespace rmad {

WriteProtectUtilsImpl::WriteProtectUtilsImpl()
    : crossystem_utils_(std::make_unique<CrosSystemUtilsImpl>()),
      ec_utils_(std::make_unique<EcUtilsImpl>()),
      futility_utils_(std::make_unique<FutilityUtilsImpl>()) {}

WriteProtectUtilsImpl::WriteProtectUtilsImpl(
    std::unique_ptr<CrosSystemUtils> crossystem_utils,
    std::unique_ptr<EcUtils> ec_utils,
    std::unique_ptr<FutilityUtils> futility_utils)
    : crossystem_utils_(std::move(crossystem_utils)),
      ec_utils_(std::move(ec_utils)),
      futility_utils_(std::move(futility_utils)) {}

bool WriteProtectUtilsImpl::GetHardwareWriteProtectionStatus(
    bool* enabled) const {
  int hwwp_status;
  if (!crossystem_utils_->GetHwwpStatus(&hwwp_status)) {
    LOG(ERROR) << "Failed to get hardware write protect with crossystem utils.";
    return false;
  }

  *enabled = (hwwp_status == 1);
  return true;
}

bool WriteProtectUtilsImpl::GetApWriteProtectionStatus(bool* enabled) const {
  if (!futility_utils_->GetApWriteProtectionStatus(enabled)) {
    LOG(ERROR) << "Failed to get AP write protect with futility utils.";
    return false;
  }
  return true;
}

bool WriteProtectUtilsImpl::GetEcWriteProtectionStatus(bool* enabled) const {
  if (!ec_utils_->GetEcWriteProtectionStatus(enabled)) {
    LOG(ERROR) << "Failed to get EC write protect with ec utils.";
    return false;
  }
  return true;
}

bool WriteProtectUtilsImpl::DisableSoftwareWriteProtection() {
  // Disable EC write protection.
  if (!ec_utils_->DisableEcSoftwareWriteProtection()) {
    LOG(ERROR) << "Failed to disable EC SWWP";
    return false;
  }

  return futility_utils_->DisableApSoftwareWriteProtection();
}

bool WriteProtectUtilsImpl::EnableSoftwareWriteProtection() {
  // Enable EC write protection.
  if (!ec_utils_->EnableEcSoftwareWriteProtection()) {
    LOG(ERROR) << "Failed to enable EC SWWP";
    return false;
  }

  // Enable AP write protection.
  return futility_utils_->EnableApSoftwareWriteProtection();
}

}  // namespace rmad

// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/utils/ec_utils_impl.h"

#include <fcntl.h>

#include <base/files/scoped_file.h>
#include <base/logging.h>
#include <libec/flash_protect_command.h>
#include <libec/reboot_command.h>

namespace {

constexpr char kEcPath[] = "/dev/cros_ec";

}  // namespace

namespace rmad {

bool EcUtilsImpl::Reboot() {
  base::ScopedFD ec_fd = GetEcFd();
  if (!ec_fd.is_valid()) {
    return false;
  }
  ec::RebootCommand reboot_cmd;
  return reboot_cmd.Run(ec_fd.get());
}

bool EcUtilsImpl::SetEcSoftwareWriteProtection(bool enable) {
  base::ScopedFD ec_fd = GetEcFd();
  if (!ec_fd.is_valid()) {
    return false;
  }

  ec::flash_protect::Flags mask = ec::flash_protect::Flags::kRoNow |
                                  ec::flash_protect::Flags::kRwNow |
                                  ec::flash_protect::Flags::kRoAtBoot;
  ec::flash_protect::Flags flags =
      enable ? mask : ec::flash_protect::Flags::kNone;
  auto flashprotect_cmd = ec::FlashProtectCommand_v1(flags, mask);
  return flashprotect_cmd.Run(ec_fd.get());
}

bool EcUtilsImpl::EnableEcSoftwareWriteProtection() {
  return EcUtilsImpl::SetEcSoftwareWriteProtection(true);
}

bool EcUtilsImpl::DisableEcSoftwareWriteProtection() {
  return EcUtilsImpl::SetEcSoftwareWriteProtection(false);
}

bool EcUtilsImpl::GetEcWriteProtectionStatus(bool* enabled) {
  base::ScopedFD ec_fd = GetEcFd();
  if (!ec_fd.is_valid()) {
    return false;
  }

  ec::flash_protect::Flags flags = ec::flash_protect::Flags::kNone;
  auto flashprotect_cmd = ec::FlashProtectCommand_v1(flags, flags);
  if (!flashprotect_cmd.Run(ec_fd.get())) {
    LOG(ERROR) << "Failed to run EC WP status command";
    return false;
  }

  *enabled =
      (flashprotect_cmd.GetFlags() & ec::flash_protect::Flags::kRoAtBoot) !=
      ec::flash_protect::Flags::kNone;

  return true;
}

base::ScopedFD EcUtilsImpl::GetEcFd() const {
  int ec_fd = open(kEcPath, O_RDWR | O_CLOEXEC);
  if (ec_fd == -1) {
    LOG(ERROR) << "Failed to get EC FD";
    return base::ScopedFD();
  }
  return base::ScopedFD(ec_fd);
}

}  // namespace rmad

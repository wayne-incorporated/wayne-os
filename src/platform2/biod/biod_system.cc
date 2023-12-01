// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "biod/biod_system.h"

extern "C" {
// Use libvboot_host for accessing crossystem variables.
#include <vboot/crossystem.h>
}

namespace {
constexpr char kHardwareWriteProtect[] = "wpsw_cur";
constexpr char kDevBootSignedOnly[] = "dev_boot_signed_only";
}

namespace biod {

bool BiodSystem::HardwareWriteProtectIsEnabled() const {
  return VbGetSystemPropertyInt(kHardwareWriteProtect) != 0;
}

bool BiodSystem::OnlyBootSignedKernel() const {
  return VbGetSystemPropertyInt(kDevBootSignedOnly) != 0;
}

int BiodSystem::VbGetSystemPropertyInt(const std::string& name) const {
  return ::VbGetSystemPropertyInt(name.c_str());
}

}  // namespace biod

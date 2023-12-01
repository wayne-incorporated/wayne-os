// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "typecd/alt_mode.h"

#include <string>

#include "typecd/utils.h"

namespace typecd {

// static
std::unique_ptr<AltMode> AltMode::CreateAltMode(const base::FilePath& syspath) {
  auto alt_mode = std::make_unique<AltMode>(syspath);

  if (!alt_mode->UpdateValuesFromSysfs()) {
    return nullptr;
  }

  return alt_mode;
}

bool AltMode::UpdateValuesFromSysfs() {
  // Create the various sysfs file paths.
  auto svid_path = syspath_.Append("svid");
  auto vdo_path = syspath_.Append("vdo");
  auto mode_index_path = syspath_.Append("mode");

  // Only proceed if we can read all the attributes.
  uint32_t svid;
  uint32_t vdo;
  uint32_t mode_index;

  if (!ReadHexFromPath(svid_path, &svid))
    return false;

  if (!ReadHexFromPath(vdo_path, &vdo))
    return false;

  if (!ReadHexFromPath(mode_index_path, &mode_index))
    return false;

  svid_ = svid;
  vdo_ = vdo;
  mode_index_ = mode_index;

  return true;
}

}  // namespace typecd

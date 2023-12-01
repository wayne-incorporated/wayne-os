// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "runtime_probe/probe_config_loader.h"

#include <base/system/sys_info.h>
#include <chromeos-config/libcros_config/cros_config.h>
#include <libcrossystem/crossystem.h>

#include "runtime_probe/system/context.h"

namespace runtime_probe {

CrosDebugFlag CrosDebug() {
  auto value = Context::Get()->crossystem()->VbGetSystemPropertyInt(
      kCrosSystemCrosDebugKey);
  if (value)
    return static_cast<CrosDebugFlag>(*value);

  // Fallback to disabled cros_debug.
  return CrosDebugFlag::kDisabled;
}

std::string ModelName() {
  std::string model_name;

  if (Context::Get()->cros_config()->GetString(
          kCrosConfigModelNamePath, kCrosConfigModelNameKey, &model_name))
    return model_name;

  // Fallback to sys_info.
  return base::SysInfo::GetLsbReleaseBoard();
}

}  // namespace runtime_probe

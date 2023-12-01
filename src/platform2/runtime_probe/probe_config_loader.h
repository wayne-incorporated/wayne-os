// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RUNTIME_PROBE_PROBE_CONFIG_LOADER_H_
#define RUNTIME_PROBE_PROBE_CONFIG_LOADER_H_

#include <optional>
#include <string>

#include "runtime_probe/probe_config.h"

namespace runtime_probe {

inline constexpr char kCrosSystemCrosDebugKey[] = "cros_debug";
inline constexpr char kCrosConfigModelNamePath[] = "/";
inline constexpr char kCrosConfigModelNameKey[] = "name";
inline constexpr char kRuntimeProbeConfigDir[] = "etc/runtime_probe";
inline constexpr char kUsrLocal[] = "usr/local";

enum class CrosDebugFlag {
  kDisabled = 0,
  kEnabled = 1,
  kUnknown = 2,
};

// Interface that provides ways to load probe configs.
class ProbeConfigLoader {
 public:
  virtual ~ProbeConfigLoader() = default;

  // Load the probe config.
  // Return |std::nullopt| if loading fails.
  virtual std::optional<ProbeConfig> Load() const = 0;
};

// Read the cros_debug crossystem property.
// Return |CrosDebugFlag::kDisabled| if read fails.
CrosDebugFlag CrosDebug();

// Get the device model name.
std::string ModelName();

}  // namespace runtime_probe

#endif  // RUNTIME_PROBE_PROBE_CONFIG_LOADER_H_

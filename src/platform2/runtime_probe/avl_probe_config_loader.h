// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RUNTIME_PROBE_AVL_PROBE_CONFIG_LOADER_H_
#define RUNTIME_PROBE_AVL_PROBE_CONFIG_LOADER_H_

#include <array>
#include <optional>
#include <vector>

#include <base/files/file_path.h>

#include "runtime_probe/functions/all_functions.h"
#include "runtime_probe/probe_config_loader.h"

namespace runtime_probe {

inline constexpr char kAvlProbeConfigName[] = "probe_config.json";

// AvlProbeConfigLoader loads probe configs for AVL verification.
class AvlProbeConfigLoader : public ProbeConfigLoader {
 public:
  AvlProbeConfigLoader() = default;

  // Load probe config from AVL config paths. The function will return
  // |std::nullopt| when loading fails.
  std::optional<ProbeConfig> Load() const override;

 private:
  static constexpr auto kAllowedProbeFunctionNames =
      AvlAllowedProbeFunctions::GetFunctionNames();

  static bool ValidateProbeConfig(const ProbeConfig& config);

  // Return default paths for AVL probe configs.  When cros_debug is disabled,
  // the default paths will be:
  //     * `/etc/runtime_probe/<model_name>/probe_config.json`
  //     * `/etc/runtime_probe/probe_config.json`
  // When cros_debug is enabled, the config paths under the stateful partition
  // will also be included:
  //     * `/usr/local/etc/runtime_probe/<model_name>/probe_config.json`
  //     * `/usr/local/etc/runtime_probe/probe_config.json`
  //     * `/etc/runtime_probe/<model_name>/probe_config.json`
  //     * `/etc/runtime_probe/probe_config.json`
  std::vector<base::FilePath> GetPaths() const;
};

}  // namespace runtime_probe

#endif  // RUNTIME_PROBE_AVL_PROBE_CONFIG_LOADER_H_

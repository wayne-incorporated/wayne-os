// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RUNTIME_PROBE_GENERIC_PROBE_CONFIG_LOADER_H_
#define RUNTIME_PROBE_GENERIC_PROBE_CONFIG_LOADER_H_

#include <optional>
#include <vector>

#include <base/files/file_path.h>

#include "runtime_probe/probe_config_loader.h"

namespace runtime_probe {

// GenericProbeConfigLoader loads probe configs from the given path.
class GenericProbeConfigLoader : public ProbeConfigLoader {
 public:
  explicit GenericProbeConfigLoader(const base::FilePath& path) : path_(path) {}

  // Loads probe config from the given path.  This method only works when
  // cros_debug is enabled.
  std::optional<ProbeConfig> Load() const override;

 private:
  base::FilePath path_;
};

}  // namespace runtime_probe

#endif  // RUNTIME_PROBE_GENERIC_PROBE_CONFIG_LOADER_H_

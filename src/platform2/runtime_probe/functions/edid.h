// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RUNTIME_PROBE_FUNCTIONS_EDID_H_
#define RUNTIME_PROBE_FUNCTIONS_EDID_H_

#include <memory>
#include <string>
#include <vector>

#include <base/files/file_path.h>

#include "runtime_probe/probe_function.h"
#include "runtime_probe/probe_function_argument.h"

namespace runtime_probe {

// Parse EDID files from DRM devices in sysfs.
//
// @param edid_patterns a list of paths to be evaluated. (Default:
// {"sys/class/drm/*/edid"})
class EdidFunction final : public PrivilegedProbeFunction {
  using PrivilegedProbeFunction::PrivilegedProbeFunction;

 public:
  NAME_PROBE_FUNCTION("edid");

 private:
  DataType EvalImpl() const override;

  // The path of target edid files, can contain wildcard.
  PROBE_FUNCTION_ARG_DEF(std::vector<std::string>,
                         edid_patterns,
                         (std::vector<std::string>{"sys/class/drm/*/edid"}));
};

}  // namespace runtime_probe

#endif  // RUNTIME_PROBE_FUNCTIONS_EDID_H_

// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RUNTIME_PROBE_FUNCTIONS_MMC_HOST_H_
#define RUNTIME_PROBE_FUNCTIONS_MMC_HOST_H_

#include "runtime_probe/probe_function.h"
#include "runtime_probe/probe_function_argument.h"

namespace runtime_probe {

// Probe mmc host components.
class MmcHostFunction : public PrivilegedProbeFunction {
  using PrivilegedProbeFunction::PrivilegedProbeFunction;

 public:
  NAME_PROBE_FUNCTION("mmc_host");

 private:
  // PrivilegedProbeFunction overrides.
  DataType EvalImpl() const override;

  // Only fetches the devices match the emmc attached state. If omit, all the
  // devices are fetched.
  PROBE_FUNCTION_ARG_DEF(std::optional<bool>, is_emmc_attached);
};

}  // namespace runtime_probe

#endif  // RUNTIME_PROBE_FUNCTIONS_MMC_HOST_H_

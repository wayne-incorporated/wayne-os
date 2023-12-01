// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RUNTIME_PROBE_FUNCTIONS_TCPC_H_
#define RUNTIME_PROBE_FUNCTIONS_TCPC_H_

#include <memory>
#include <base/files/scoped_file.h>

#include "runtime_probe/probe_function.h"

namespace ec {
class PdChipInfoCommandV0;
}

namespace runtime_probe {

// Probe tcpc info from libec.
class TcpcFunction : public PrivilegedProbeFunction {
  using PrivilegedProbeFunction::PrivilegedProbeFunction;

 public:
  NAME_PROBE_FUNCTION("tcpc");

 private:
  DataType EvalImpl() const override;

  // For mocking.
  virtual std::unique_ptr<ec::PdChipInfoCommandV0> GetPdChipInfoCommandV0(
      uint8_t port) const;

  virtual base::ScopedFD GetEcDevice() const;
};

}  // namespace runtime_probe

#endif  // RUNTIME_PROBE_FUNCTIONS_TCPC_H_

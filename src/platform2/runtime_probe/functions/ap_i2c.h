// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RUNTIME_PROBE_FUNCTIONS_AP_I2C_H_
#define RUNTIME_PROBE_FUNCTIONS_AP_I2C_H_

#include "runtime_probe/probe_function.h"
#include "runtime_probe/probe_function_argument.h"

namespace runtime_probe {

// Read data from an I2C register on AP (application processor).
// This probe function takes the following arguments:
//   i2c_bus: The port of the I2C connected to EC.
//   chip_addr: The I2C address
//   data_addr: The register offset.
class ApI2cFunction : public PrivilegedProbeFunction {
  using PrivilegedProbeFunction::PrivilegedProbeFunction;

 public:
  NAME_PROBE_FUNCTION("ap_i2c");

 private:
  DataType EvalImpl() const override;

  PROBE_FUNCTION_ARG_DEF(int, i2c_bus);
  PROBE_FUNCTION_ARG_DEF(int, chip_addr);
  PROBE_FUNCTION_ARG_DEF(int, data_addr);
};

}  // namespace runtime_probe

#endif  // RUNTIME_PROBE_FUNCTIONS_AP_I2C_H_

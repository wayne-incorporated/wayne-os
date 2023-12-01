// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RUNTIME_PROBE_FUNCTIONS_EC_I2C_H_
#define RUNTIME_PROBE_FUNCTIONS_EC_I2C_H_

#include <memory>
#include <string>

#include <base/files/scoped_file.h>
#include <base/logging.h>
#include <base/values.h>

#include "runtime_probe/probe_function.h"
#include "runtime_probe/probe_function_argument.h"

namespace ec {
class I2cReadCommand;
};

namespace runtime_probe {

// Read data from an I2C register on EC (embedded controller).
// This probe function takes the following arguments:
//   i2c_bus: The port of the I2C connected to EC.
//   chip_addr: The I2C address
//   data_addr: The register offset.
//   size: Return bits, it can be either 8 or 16.
//
// More details can be found under command "ectool i2cread help"
class EcI2cFunction : public PrivilegedProbeFunction {
  using PrivilegedProbeFunction::PrivilegedProbeFunction;

 public:
  NAME_PROBE_FUNCTION("ec_i2c");

 private:
  // PrivilegedProbeFunction overrides.
  bool PostParseArguments() final;
  DataType EvalImpl() const override;

  virtual std::unique_ptr<ec::I2cReadCommand> GetI2cReadCommand() const;

  virtual base::ScopedFD GetEcDevice() const;

  PROBE_FUNCTION_ARG_DEF(int, i2c_bus);
  PROBE_FUNCTION_ARG_DEF(int, chip_addr);
  PROBE_FUNCTION_ARG_DEF(int, data_addr);
  PROBE_FUNCTION_ARG_DEF(int, size, (8));
};

}  // namespace runtime_probe

#endif  // RUNTIME_PROBE_FUNCTIONS_EC_I2C_H_

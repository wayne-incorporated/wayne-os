// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBEC_I2C_PASSTHRU_COMMAND_H_
#define LIBEC_I2C_PASSTHRU_COMMAND_H_

#include <type_traits>
#include <vector>

#include <base/containers/span.h>
#include <brillo/brillo_export.h>
#include "libec/ec_command.h"
#include "libec/i2c_passthru_params.h"

namespace ec {

class BRILLO_EXPORT I2cPassthruCommand
    : public EcCommand<i2c_passthru::Params, i2c_passthru::Response> {
 public:
  explicit I2cPassthruCommand(uint8_t port,
                              uint8_t addr,
                              const std::vector<uint8_t>& msg,
                              size_t read_len);

  ~I2cPassthruCommand() override = default;

  // Returns the status code from the response of the I2C command.
  virtual uint8_t I2cStatus() const { return Resp()->resp.i2c_status; }

  // Returns a byte array containing the data from the response of the
  // I2C command.
  virtual base::span<const uint8_t> RespData() const;
};

static_assert(!std::is_copy_constructible_v<I2cPassthruCommand>,
              "EcCommands are not copyable by default");
static_assert(!std::is_copy_assignable_v<I2cPassthruCommand>,
              "EcCommands are not copy-assignable by default");

}  // namespace ec

#endif  // LIBEC_I2C_PASSTHRU_COMMAND_H_

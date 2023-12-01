// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBEC_I2C_READ_COMMAND_H_
#define LIBEC_I2C_READ_COMMAND_H_

#include <memory>
#include <type_traits>

#include <base/memory/ptr_util.h>

#include "libec/i2c_passthru_command.h"

namespace ec {

class BRILLO_EXPORT I2cReadCommand : public I2cPassthruCommand {
 public:
  template <typename T = I2cReadCommand>
  static std::unique_ptr<T> Create(uint8_t port,
                                   uint8_t addr8,
                                   uint8_t offset,
                                   uint8_t read_len) {
    static_assert(std::is_base_of_v<I2cReadCommand, T>,
                  "Only classes derived from I2cReadCommand can use Create");

    if (read_len != 1 && read_len != 2) {
      return nullptr;
    }

    // Using new to access non-public constructor.
    return base::WrapUnique(new T(port, addr8, offset, read_len));
  }
  ~I2cReadCommand() override = default;

  virtual uint16_t Data() const;

 protected:
  I2cReadCommand(uint8_t port, uint8_t addr8, uint8_t offset, uint8_t read_len)
      : I2cPassthruCommand(port, addr8 >> 1, {offset}, read_len),
        read_len_(read_len) {}

 private:
  uint8_t read_len_;
};

static_assert(!std::is_copy_constructible_v<I2cReadCommand>,
              "EcCommands are not copyable by default");
static_assert(!std::is_copy_assignable_v<I2cReadCommand>,
              "EcCommands are not copy-assignable by default");

}  // namespace ec

#endif  // LIBEC_I2C_READ_COMMAND_H_

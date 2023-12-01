// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBEC_I2C_PASSTHRU_PARAMS_H_
#define LIBEC_I2C_PASSTHRU_PARAMS_H_

#include <array>

#include "libec/ec_command.h"

namespace ec::i2c_passthru {

struct Params {
  struct Header {
    // I2C port number
    uint8_t port;
    // Number of messages
    uint8_t num_msgs;
  };

  struct Header req;
  // This variable contains |num_msgs| messages with the struct type
  // |ec_params_i2c_passthru_msg| and byte payloads to be written.
  // There can only be at most one "write" message and one "read" message.
  ArrayData<uint8_t, struct Header> msg_and_payload{};
};

struct Response {
  struct Header {
    // Status flags
    uint8_t i2c_status;
    // Number of messages processed
    uint8_t num_msgs;
  };

  struct Header resp;
  // The data read from the I2C bus when the "read" message is sent.
  ArrayData<uint8_t, struct Header> data{};
};

inline constexpr size_t kResponseDataMaxSize =
    std::tuple_size_v<decltype(Response::data)>;

}  // namespace ec::i2c_passthru

#endif  // LIBEC_I2C_PASSTHRU_PARAMS_H_

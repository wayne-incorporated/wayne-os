// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <algorithm>

#include <base/check.h>
#include <base/containers/span.h>
#include "libec/i2c_passthru_command.h"

namespace ec {

I2cPassthruCommand::I2cPassthruCommand(uint8_t port,
                                       uint8_t addr,
                                       const std::vector<uint8_t>& write_data,
                                       size_t read_len)
    : EcCommand(EC_CMD_I2C_PASSTHRU) {
  Req()->req.port = port;
  Req()->req.num_msgs = (write_data.size() > 0) + (read_len > 0);
  CHECK_LE(Req()->req.num_msgs, 2);

  size_t req_size = realsizeof<decltype(Req()->req)>;
  size_t resp_size = realsizeof<decltype(Resp()->resp)>;
  using PassthruMessage = struct ec_params_i2c_passthru_msg;
  constexpr size_t message_size = realsizeof<PassthruMessage>;

  base::span<PassthruMessage> messages(
      reinterpret_cast<PassthruMessage*>(Req()->msg_and_payload.data()),
      Req()->req.num_msgs);
  auto message_it = messages.begin();

  if (write_data.size() > 0) {
    message_it->addr_flags = addr;
    message_it->len = write_data.size();
    uint8_t* payload = Req()->msg_and_payload.data() + messages.size_bytes();
    std::copy(write_data.begin(), write_data.end(), payload);
    req_size += message_size + write_data.size();
    ++message_it;
  }

  if (read_len > 0) {
    if (read_len > i2c_passthru::kResponseDataMaxSize) {
      LOG(WARNING) << "read_len (" << static_cast<int>(read_len)
                   << ") should not be greater than "
                   << i2c_passthru::kResponseDataMaxSize;
    }
    message_it->addr_flags = addr | EC_I2C_FLAG_READ;
    message_it->len = read_len;
    req_size += message_size;
    resp_size += read_len;
  }

  SetReqSize(req_size);
  SetRespSize(resp_size);
}

base::span<const uint8_t> I2cPassthruCommand::RespData() const {
  if (I2cStatus())
    return {};
  CHECK(RespSize() - realsizeof<decltype(Resp()->resp)> >= 0);
  return {Resp()->data.begin(),
          RespSize() - realsizeof<decltype(Resp()->resp)>};
}

}  // namespace ec

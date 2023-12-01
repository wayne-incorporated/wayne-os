// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libec/fingerprint/fp_template_command.h"

#include <algorithm>
#include <vector>

namespace ec {

bool FpTemplateCommand::Run(int fd) {
  uint32_t max_data_chunk = max_write_size_ - sizeof(fp_template::Header);

  auto pos = template_data_.begin();
  const auto end = template_data_.cend();
  while (pos < end) {
    uint32_t remaining = end - pos;
    uint32_t transfer_len = std::min(max_data_chunk, remaining);
    Req()->req.offset = pos - template_data_.begin();
    Req()->req.size =
        transfer_len | (remaining == transfer_len ? FP_TEMPLATE_COMMIT : 0);
    std::copy(pos, pos + transfer_len, Req()->data.begin());
    SetReqSize(transfer_len + sizeof(fp_template::Header));
    if (!EcCommandRun(fd)) {
      LOG(ERROR) << "Failed to run FP_TEMPLATE command";
      return false;
    }
    if (Result() != EC_RES_SUCCESS) {
      LOG(ERROR) << "FP_TEMPLATE command failed @ "
                 << pos - template_data_.begin();
      return false;
    }
    pos += transfer_len;
  }
  return true;
}

bool FpTemplateCommand::EcCommandRun(int fd) {
  return EcCommand::Run(fd);
}

}  // namespace ec

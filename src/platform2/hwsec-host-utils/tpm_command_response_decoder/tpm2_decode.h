// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HWSEC_HOST_UTILS_TPM_COMMAND_RESPONSE_DECODER_TPM2_DECODE_H_
#define HWSEC_HOST_UTILS_TPM_COMMAND_RESPONSE_DECODER_TPM2_DECODE_H_

#include <cstdint>
#include <string>

namespace hwsec_host_utils {

std::string DecodeTpm2CommandResponse(uint32_t cc, uint32_t rc);

}  // namespace hwsec_host_utils

#endif  // HWSEC_HOST_UTILS_TPM_COMMAND_RESPONSE_DECODER_TPM2_DECODE_H_

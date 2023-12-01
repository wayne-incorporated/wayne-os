// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "trunks/csme/pinweaver_core_client_null.h"

#include <base/logging.h>

namespace trunks {
namespace csme {

PinWeaverCoreClientNull::PinWeaverCoreClientNull() {
  static bool s_is_logged = false;
  LOG_IF(WARNING, !s_is_logged)
      << __func__ << ": Creating null-implemented core client.";
  s_is_logged = true;
}

bool PinWeaverCoreClientNull::ExtendPcr(uint32_t pcr_index,
                                        uint32_t hash_alg,
                                        const std::string& extension) {
  return false;
}
bool PinWeaverCoreClientNull::ReadPcr(uint32_t pcr_index_in,
                                      uint32_t hash_alg_in,
                                      uint32_t* pcr_index_out,
                                      uint32_t* hash_alg_out,
                                      std::string* pcr_value) {
  return false;
}

bool PinWeaverCoreClientNull::PinWeaverCommand(
    const std::string& pinweaver_request, std::string* pinweaver_response) {
  return false;
}
}  // namespace csme
}  // namespace trunks

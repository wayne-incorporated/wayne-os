// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TRUNKS_CSME_PINWEAVER_CORE_CLIENT_NULL_H_
#define TRUNKS_CSME_PINWEAVER_CORE_CLIENT_NULL_H_

#include "trunks/csme/pinweaver_core_client.h"

#include <memory>
#include <string>

#include "trunks/csme/mei_client.h"

namespace trunks {
namespace csme {

class PinWeaverCoreClientNull : public PinWeaverCoreClient {
 public:
  PinWeaverCoreClientNull();
  ~PinWeaverCoreClientNull() override = default;
  bool ExtendPcr(uint32_t pcr_index,
                 uint32_t hash_alg,
                 const std::string& extension) override;
  bool ReadPcr(uint32_t pcr_index_in,
               uint32_t hash_alg_in,
               uint32_t* pcr_index_out,
               uint32_t* hash_alg_out,
               std::string* pcr_value) override;
  bool PinWeaverCommand(const std::string& pinweaver_request,
                        std::string* pinweaver_response) override;
};

}  // namespace csme
}  // namespace trunks

#endif  // TRUNKS_CSME_PINWEAVER_CORE_CLIENT_NULL_H_

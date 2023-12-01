// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TRUNKS_CSME_PINWEAVER_CORE_CLIENT_H_
#define TRUNKS_CSME_PINWEAVER_CORE_CLIENT_H_

#include <memory>
#include <string>

#include "trunks/csme/mei_client_factory.h"

namespace trunks {
namespace csme {

class PinWeaverCoreClient {
 public:
  static std::unique_ptr<PinWeaverCoreClient> Create(
      MeiClientFactory* mei_client_factory);
  virtual ~PinWeaverCoreClient() = default;
  virtual bool ExtendPcr(uint32_t pcr_index,
                         uint32_t hash_alg,
                         const std::string& extension) = 0;
  virtual bool ReadPcr(uint32_t pcr_index_in,
                       uint32_t hash_alg_in,
                       uint32_t* pcr_index_out,
                       uint32_t* hash_alg_out,
                       std::string* pcr_value) = 0;
  virtual bool PinWeaverCommand(const std::string& pinweaver_request,
                                std::string* pinweaver_response) = 0;
};

}  // namespace csme
}  // namespace trunks

#endif  // TRUNKS_CSME_PINWEAVER_CORE_CLIENT_H_

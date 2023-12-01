// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TRUNKS_CSME_PINWEAVER_CORE_CLIENT_IMPL_H_
#define TRUNKS_CSME_PINWEAVER_CORE_CLIENT_IMPL_H_

#include "trunks/csme/pinweaver_core_client.h"

#include <memory>
#include <string>

#include "trunks/csme/mei_client.h"
#include "trunks/csme/mei_client_factory.h"
#include "trunks/csme/pinweaver_csme_types.h"

namespace trunks {
namespace csme {

class PinWeaverCoreClientImpl : public PinWeaverCoreClient {
 public:
  explicit PinWeaverCoreClientImpl(MeiClientFactory* mei_client_factory);
  bool ExtendPcr(uint32_t pcr_index,
                 uint32_t hash_alg,
                 const std::string& extension);
  bool ReadPcr(uint32_t pcr_index_in,
               uint32_t hash_alg_in,
               uint32_t* pcr_index_out,
               uint32_t* hash_alg_out,
               std::string* pcr_value);
  bool PinWeaverCommand(const std::string& pinweaver_request,
                        std::string* pinweaver_response);

 private:
  MeiClient* GetMeiClient();
  bool UnpackStringFromResponse(const pw_heci_header_req& req_header,
                                const std::string& response,
                                std::string* payload);

  MeiClientFactory* const mei_client_factory_;
  std::unique_ptr<MeiClient> mei_client_;
  int seq_ = 0;
};

}  // namespace csme
}  // namespace trunks

#endif  // TRUNKS_CSME_PINWEAVER_CORE_CLIENT_IMPL_H_

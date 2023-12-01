// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TRUNKS_CSME_PINWEAVER_PROVISION_CLIENT_H_
#define TRUNKS_CSME_PINWEAVER_PROVISION_CLIENT_H_

#include <memory>
#include <string>

#include "trunks/csme/mei_client.h"
#include "trunks/csme/mei_client_factory.h"
#include "trunks/trunks_export.h"

namespace trunks {
namespace csme {

class TRUNKS_EXPORT PinWeaverProvisionClient {
 public:
  explicit PinWeaverProvisionClient(MeiClientFactory* mei_client_factory);
  bool SetSaltingKeyHash(const std::string& hash);
  bool GetSaltingKeyHash(std::string* salting_key_hash, bool* committed);
  bool CommitSaltingKeyHash();
  bool InitOwner();

 private:
  MeiClient* GetMeiClient();

  MeiClientFactory* const mei_client_factory_;
  std::unique_ptr<MeiClient> mei_client_;
  int seq_ = 0;
};

}  // namespace csme
}  // namespace trunks

#endif  // TRUNKS_CSME_PINWEAVER_PROVISION_CLIENT_H_

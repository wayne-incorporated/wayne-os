// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "trunks/csme/pinweaver_provision_client.h"

#include <algorithm>
#include <string>

#include <base/check.h>
#include <base/logging.h>

#include "trunks/csme/mei_client.h"
#include "trunks/csme/mei_client_factory.h"
#include "trunks/csme/pinweaver_client_utils.h"
#include "trunks/csme/pinweaver_csme_types.h"

namespace trunks {
namespace csme {

PinWeaverProvisionClient::PinWeaverProvisionClient(
    MeiClientFactory* mei_client_factory)
    : mei_client_factory_(mei_client_factory) {
  CHECK(mei_client_factory_);
}

// TODO(b/b:190621192): Extract the common code for all commands using tamplate
// or lambda.
bool PinWeaverProvisionClient::SetSaltingKeyHash(const std::string& hash) {
  pw_prov_salting_key_hash_set_request req;
  BuildFixedSizedRequest(PW_SALTING_KEY_HASH_SET, seq_++, &req);
  if (hash.size() != req.header.total_length) {
    LOG(ERROR) << __func__ << ": unexpected hash size: " << hash.size();
    return false;
  }
  std::copy(hash.begin(), hash.end(), req.buffer);
  const std::string request = SerializeToString(req);
  std::string response;
  if (!GetMeiClient()->Send(request, /*wait_for_response_ready=*/true) ||
      !GetMeiClient()->Receive(&response)) {
    LOG(ERROR) << __func__ << ": Failed to send request.";
    return false;
  }

  if (!UnpackFromResponse(req.header, response)) {
    LOG(ERROR) << __func__ << ": failed to unpack response.";
    return false;
  }
  return true;
}

bool PinWeaverProvisionClient::GetSaltingKeyHash(std::string* salting_key_hash,
                                                 bool* committed) {
  pw_prov_salting_key_hash_get_request req;
  BuildFixedSizedRequest(PW_SALTING_KEY_HASH_GET, seq_++, &req);
  const std::string request = SerializeToString(req);
  std::string response;
  if (!GetMeiClient()->Send(request, /*wait_for_response_ready=*/true) ||
      !GetMeiClient()->Receive(&response)) {
    LOG(ERROR) << __func__ << ": Failed to send request.";
    return false;
  }

  uint8_t buffer[PW_SHA_256_DIGEST_SIZE];
  if (!UnpackFromResponse(req.header, response, committed, &buffer)) {
    LOG(ERROR) << __func__ << ": failed to unpack response.";
    return false;
  }
  salting_key_hash->assign(std::begin(buffer), std::end(buffer));
  return true;
}

bool PinWeaverProvisionClient::CommitSaltingKeyHash() {
  pw_prov_salting_key_hash_commit_request req;
  BuildFixedSizedRequest(PW_SALTING_KEY_HASH_COMMIT, seq_++, &req);
  const std::string request = SerializeToString(req);
  std::string response;
  if (!GetMeiClient()->Send(request, /*wait_for_response_ready=*/true) ||
      !GetMeiClient()->Receive(&response)) {
    LOG(ERROR) << __func__ << ": Failed to send request.";
    return false;
  }
  if (!UnpackFromResponse(req.header, response)) {
    LOG(ERROR) << __func__ << ": failed to unpack response.";
    return false;
  }
  return true;
}

bool PinWeaverProvisionClient::InitOwner() {
  pw_prov_initialize_owner_request req;
  BuildFixedSizedRequest(PW_PROV_INITIALIZE_OWNER, seq_++, &req);
  const std::string request = SerializeToString(req);
  std::string response;
  if (!GetMeiClient()->Send(request, /*wait_for_response_ready=*/true) ||
      !GetMeiClient()->Receive(&response)) {
    LOG(ERROR) << __func__ << ": Failed to send request.";
    return false;
  }

  if (!UnpackFromResponse(req.header, response)) {
    LOG(ERROR) << __func__ << ": failed to unpack response.";
    return false;
  }
  return true;
}

MeiClient* PinWeaverProvisionClient::GetMeiClient() {
  if (!mei_client_) {
    mei_client_ = mei_client_factory_->CreateMeiClientForPinWeaverProvision();
  }
  return mei_client_.get();
}

}  // namespace csme
}  // namespace trunks

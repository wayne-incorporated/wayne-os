// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "trunks/csme/pinweaver_core_client_impl.h"

#include <algorithm>
#include <string>

#include <base/check.h>
#include <base/logging.h>

#include "trunks/csme/pinweaver_client_utils.h"
#include "trunks/csme/pinweaver_csme_types.h"

namespace trunks {
namespace csme {

PinWeaverCoreClientImpl::PinWeaverCoreClientImpl(
    MeiClientFactory* mei_client_factory)
    : mei_client_factory_(mei_client_factory) {
  CHECK(USE_PINWEAVER_CSME);
  CHECK(mei_client_factory_);
}

bool PinWeaverCoreClientImpl::ExtendPcr(uint32_t pcr_index,
                                        uint32_t hash_alg,
                                        const std::string& extension) {
  pw_pcr_extend_request req;
  BuildFixedSizedRequest(PW_PCR_EXTEND, seq_++, &req);
  req.pcr_index = pcr_index;
  req.hash_alg = hash_alg;
  // Only fixed-sized extension is supported.
  if (extension.size() != sizeof(req.buffer)) {
    LOG(ERROR) << __func__
               << ": Mismatched extension size: " << extension.size()
               << "; expecting " << sizeof(req.buffer) << ".";
    return false;
  }
  std::copy(extension.begin(), extension.end(), req.buffer);
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
bool PinWeaverCoreClientImpl::ReadPcr(uint32_t pcr_index_in,
                                      uint32_t hash_alg_in,
                                      uint32_t* pcr_index_out,
                                      uint32_t* hash_alg_out,
                                      std::string* pcr_value) {
  pw_pcr_read_request req;
  BuildFixedSizedRequest(PW_PCR_READ, seq_++, &req);
  req.pcr_index = pcr_index_in;
  req.hash_alg = hash_alg_in;
  const std::string request = SerializeToString(req);
  std::string response;
  if (!GetMeiClient()->Send(request, /*wait_for_response_ready=*/true) ||
      !GetMeiClient()->Receive(&response)) {
    LOG(ERROR) << __func__ << ": Failed to send request.";
    return false;
  }

  if (!UnpackFromResponse(req.header, response, pcr_index_out, hash_alg_out,
                          pcr_value)) {
    LOG(ERROR) << __func__ << ": failed to unpack response.";
    return false;
  }
  return true;
}

bool PinWeaverCoreClientImpl::PinWeaverCommand(
    const std::string& pinweaver_request, std::string* pinweaver_response) {
  union {
    pw_core_pinweaver_command_request req;
    char req_serialized[sizeof(pw_core_pinweaver_command_request)];
  };
  req.header.pw_heci_cmd = pw_core_pinweaver_cmd_t::PW_CORE_PINWEAVER_CMD;
  req.header.pw_heci_seq = seq_++;
  req.header.total_length = pinweaver_request.size();
  std::copy(pinweaver_request.begin(), pinweaver_request.end(),
            req.pinweaver_request_blob);
  const std::string request(std::begin(req_serialized),
                            std::begin(req_serialized) +
                                sizeof(pw_heci_header_req) +
                                pinweaver_request.size());
  std::string response;
  if (!GetMeiClient()->Send(request, /*wait_for_response_ready=*/true) ||
      !GetMeiClient()->Receive(&response)) {
    LOG(ERROR) << __func__ << ": Failed to send request.";
    return false;
  }
  if (!UnpackStringFromResponse(req.header, response, pinweaver_response)) {
    LOG(ERROR) << __func__ << ": Failed to unpack response.";
  }
  return true;
}

MeiClient* PinWeaverCoreClientImpl::GetMeiClient() {
  if (!mei_client_) {
    mei_client_ = mei_client_factory_->CreateMeiClientForPinWeaverCore();
  }
  return mei_client_.get();
}

bool PinWeaverCoreClientImpl::UnpackStringFromResponse(
    const pw_heci_header_req& req_header,
    const std::string& response,
    std::string* payload) {
  struct __attribute__((packed)) PackedResponse {
    pw_heci_header_res header;
    char buffer[PW_MAX_HECI_PAYLOAD_SIZE];
  };
  if (response.size() > sizeof(PackedResponse)) {
    LOG(ERROR) << __func__
               << ": Unexpectedly large size of response: " << response.size()
               << "; expecting <" << sizeof(PackedResponse) << ".";
    return false;
  }
  const PackedResponse* resp =
      reinterpret_cast<const PackedResponse*>(response.data());

  // Perform rationality check.
  if (req_header.pw_heci_seq != resp->header.pw_heci_seq) {
    LOG(ERROR) << __func__ << ": Mismatched sequence: expected "
               << req_header.pw_heci_seq << " got " << resp->header.pw_heci_seq;
    return false;
  }
  if (req_header.pw_heci_cmd != resp->header.pw_heci_cmd) {
    LOG(ERROR) << __func__ << ": Mismatched command: expected "
               << req_header.pw_heci_cmd << " got " << resp->header.pw_heci_cmd;
    return false;
  }
  if (resp->header.pw_heci_rc) {
    LOG(ERROR) << __func__
               << ": CSME returns error: " << int(resp->header.pw_heci_rc);
    return false;
  }
  if (resp->header.total_length > PW_MAX_HECI_PAYLOAD_SIZE) {
    LOG(ERROR) << __func__ << ": Unexpectedly large payload length: "
               << resp->header.total_length;
    return false;
  }
  payload->assign(std::begin(resp->buffer),
                  std::begin(resp->buffer) + resp->header.total_length);
  return true;
}

}  // namespace csme
}  // namespace trunks

// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "trunks/csme/tpm_tunnel_service.h"

#include <algorithm>
#include <cstdint>
#include <memory>
#include <string>

#include <base/check.h>
#include <base/logging.h>

#include "trunks/csme/mei_client.h"
#include "trunks/csme/mei_client_factory.h"
#include "trunks/csme/pinweaver_csme_types.h"
#include "trunks/trunks_dbus_proxy.h"

namespace trunks {
namespace csme {

TpmTunnelService::TpmTunnelService(TrunksDBusProxy* proxy)
    : trunks_proxy_(proxy) {
  // Don't accept null `proxy`.
  CHECK(proxy);
}

bool TpmTunnelService::Initialize() {
  if (initialized_) {
    return true;
  }

  if (!trunks_proxy_->Init()) {
    LOG(ERROR) << __func__ << "Failed to initialize dbus proxy.";
    return false;
  }

  mei_client_ = mei_client_factory_.CreateMeiClientForPinWeaverTpmTunnel();
  if (!mei_client_->Initialize()) {
    LOG(ERROR) << __func__ << ": Failed to initialize MEI client.";
    return false;
  }
  initialized_ = true;
  return true;
}

bool TpmTunnelService::Run() {
  // It is caller's responsibility to control the initialization flow.
  CHECK(initialized_);
  while (true) {
    std::string csme_request;
    if (!mei_client_->Receive(&csme_request)) {
      LOG(ERROR) << __func__ << ": Failed to get request from CSME.";
      return false;
    }
    union {
      pw_tpm_command_request req;
      char req_serialized[sizeof(pw_tpm_command_request)];
    };
    int csme_rc = 0;
    if (csme_request.size() < sizeof(req.header)) {
      LOG(ERROR) << __func__
                 << ": Request size too small: " << csme_request.size();
      csme_rc = 1;
    } else if (csme_request.size() > sizeof(req_serialized)) {
      LOG(ERROR) << __func__
                 << ": Request size too large: " << csme_request.size();
      csme_rc = 1;
    }
    if (!csme_rc) {
      // Deserialize the request from CSME.
      std::copy(csme_request.begin(), csme_request.end(), req_serialized);
      if (req.header.total_length + sizeof(req.header) != csme_request.size()) {
        LOG(ERROR) << __func__ << ": Bad request size of paylaod: "
                   << req.header.total_length << "; should be "
                   << csme_request.size() - sizeof(req.header);
        csme_rc = 2;
      }
      if (req.header.pw_heci_cmd != PW_TPM_TUNNEL_CMD) {
        LOG(ERROR) << __func__
                   << ": Bad tpm tunnel command: " << req.header.pw_heci_cmd;
        csme_rc = 2;
      }
    }
    std::string tpm_response;
    if (!csme_rc) {
      tpm_response = trunks_proxy_->SendCommandAndWait(
          std::string(req.tpm_request_blob,
                      req.header.total_length + req.tpm_request_blob));
    }

    union {
      pw_tpm_command_response resp;
      char resp_serialized[sizeof(pw_tpm_command_response)];
    };
    if (tpm_response.size() <= sizeof(resp.tpm_response_blob)) {
      std::copy(tpm_response.begin(), tpm_response.end(),
                resp.tpm_response_blob);
    } else {
      LOG(ERROR) << __func__
                 << "TPM response size too large: " << tpm_response.size();
      tpm_response.clear();
      csme_rc = 3;
    }
    resp.header.pw_heci_cmd = req.header.pw_heci_cmd;
    resp.header.pw_heci_seq = req.header.pw_heci_seq;
    resp.header.pw_heci_rc = csme_rc;
    resp.header.total_length = tpm_response.size();
    if (!mei_client_->Send(
            std::string(std::begin(resp_serialized),
                        std::begin(resp_serialized) + sizeof(resp.header) +
                            tpm_response.size()),
            /*wait_for_response_ready=*/false)) {
      LOG(ERROR) << __func__ << "Failed to send TPM resposne back to CSME.";
      return false;
    }
  }
}

}  // namespace csme
}  // namespace trunks

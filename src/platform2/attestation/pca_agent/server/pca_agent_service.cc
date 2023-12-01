// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "attestation/pca_agent/server/pca_agent_service.h"

#include <string>
#include <utility>

#include <attestation/proto_bindings/interface.pb.h>
#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <base/memory/ref_counted.h>
#include <brillo/http/http_utils.h>
#include <brillo/mime_utils.h>

#include "attestation/pca_agent/server/pca_request.h"

namespace attestation {
namespace pca_agent {

namespace {

constexpr char kDefaultPCAServerUrl[] = "https://chromeos-ca.gstatic.com";
constexpr char kTestPCAServerUrl[] = "https://asbestos-qa.corp.google.com";

constexpr char kEnrollPath[] = "enroll";
constexpr char kSignPath[] = "sign";

std::string ACATypeToServerUrl(ACAType type) {
  if (type == TEST_ACA) {
    return kTestPCAServerUrl;
  }
  return kDefaultPCAServerUrl;
}

std::string EnrollRequestToServerUrl(const EnrollRequest& req) {
  return ACATypeToServerUrl(req.aca_type()) + "/" + kEnrollPath;
}

std::string CertRequestToServerUrl(const GetCertificateRequest& req) {
  return ACATypeToServerUrl(req.aca_type()) + "/" + kSignPath;
}

}  // namespace

void PcaAgentService::Enroll(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<EnrollReply>>
        response,
    const EnrollRequest& request) {
  VLOG(1) << __func__;
  scoped_refptr<PcaRequest<EnrollReply>> pca_request =
      new PcaRequest<EnrollReply>(__func__, EnrollRequestToServerUrl(request),
                                  request.request(), std::move(response));
  pca_request->SendRequest();
}

void PcaAgentService::GetCertificate(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<GetCertificateReply>>
        response,
    const GetCertificateRequest& request) {
  VLOG(1) << __func__;
  scoped_refptr<PcaRequest<GetCertificateReply>> pca_request =
      new PcaRequest<GetCertificateReply>(
          __func__, CertRequestToServerUrl(request), request.request(),
          std::move(response));
  pca_request->SendRequest();
}

}  // namespace pca_agent
}  // namespace attestation

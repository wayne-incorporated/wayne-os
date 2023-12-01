// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "hwsec-test-utils/fake_pca_agent/service.h"

#include <attestation/proto_bindings/interface.pb.h>
#include <attestation/proto_bindings/pca_agent.pb.h>

#include "hwsec-test-utils/fake_pca_agent/pca_factory.h"

namespace hwsec_test_utils {
namespace fake_pca_agent {

namespace {

constexpr char kPreprocessError[] = "Preprocess error";
constexpr char kVerificationError[] = "Verification error";
constexpr char kGenerationError[] = "Generation error";
constexpr char kWriteError[] = "Write error";

}  // namespace

FakePcaAgentService::FakePcaAgentService() = default;

void FakePcaAgentService::Enroll(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        attestation::pca_agent::EnrollReply>> response,
    const attestation::pca_agent::EnrollRequest& in_request) {
  attestation::AttestationEnrollmentRequest request;
  attestation::pca_agent::EnrollReply reply;
  if (!request.ParseFromString(in_request.request())) {
    reply.set_status(attestation::AttestationStatus::STATUS_INVALID_PARAMETER);
    response->Return(reply);
    return;
  }
  attestation::AttestationEnrollmentResponse enroll_response;
  enroll_response.set_status(attestation::ResponseStatus::BAD_REQUEST);
  auto pca_enroll = CreatePcaEnroll(request);
  if (!pca_enroll->Preprocess()) {
    enroll_response.set_detail(kPreprocessError);
  } else if (!pca_enroll->Verify()) {
    enroll_response.set_detail(kVerificationError);
  } else if (!pca_enroll->Generate()) {
    enroll_response.set_detail(kGenerationError);
  } else if (!pca_enroll->Write(&enroll_response)) {
    enroll_response.set_detail(kWriteError);
  } else {
    enroll_response.set_status(attestation::ResponseStatus::OK);
  }
  if (!enroll_response.SerializeToString(reply.mutable_response())) {
    reply.set_status(
        attestation::AttestationStatus::STATUS_UNEXPECTED_DEVICE_ERROR);
  }
  response->Return(reply);
}

void FakePcaAgentService::GetCertificate(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        attestation::pca_agent::GetCertificateReply>> response,
    const attestation::pca_agent::GetCertificateRequest& in_request) {
  attestation::AttestationCertificateRequest request;
  attestation::pca_agent::GetCertificateReply reply;
  if (!request.ParseFromString(in_request.request())) {
    reply.set_status(attestation::AttestationStatus::STATUS_INVALID_PARAMETER);
    response->Return(reply);
    return;
  }
  attestation::AttestationCertificateResponse certify_response;
  certify_response.set_status(attestation::ResponseStatus::BAD_REQUEST);
  certify_response.set_message_id(request.message_id());
  auto pca_certify = CreatePcaCertify(request);
  if (!pca_certify->Preprocess()) {
    certify_response.set_detail(kPreprocessError);
  } else if (!pca_certify->Verify()) {
    certify_response.set_detail(kVerificationError);
  } else if (!pca_certify->Generate()) {
    certify_response.set_detail(kGenerationError);
  } else if (!pca_certify->Write(&certify_response)) {
    certify_response.set_detail(kWriteError);
  } else {
    certify_response.set_status(attestation::ResponseStatus::OK);
  }
  if (!certify_response.SerializeToString(reply.mutable_response())) {
    reply.set_status(
        attestation::AttestationStatus::STATUS_UNEXPECTED_DEVICE_ERROR);
  }
  response->Return(reply);
}

}  // namespace fake_pca_agent
}  // namespace hwsec_test_utils

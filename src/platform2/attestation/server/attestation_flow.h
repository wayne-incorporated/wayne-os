// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ATTESTATION_SERVER_ATTESTATION_FLOW_H_
#define ATTESTATION_SERVER_ATTESTATION_FLOW_H_

#include <optional>
#include <string>
#include <utility>

#include <attestation/proto_bindings/interface.pb.h>
#include <base/functional/callback.h>

#include "attestation/common/attestation_interface.h"

namespace attestation {

// Indicates what is the next action in the entire attestation flow, either
// for enrollment or for certificate. See the comments inlined.
enum class AttestationFlowAction {
  // Unknown action.
  kUnknown,
  // Inficates what some error occurs during the attestation flow so the action
  // is to abort the transactions.
  kAbort,
  // The request is created and the next action is to process the request to the
  // corresponding CA, e.g., sending the result request to the corresponding CA
  // server.
  kProcessRequest,
  // The request should be enqueued and processed later.
  kEnqueue,
  // The request is done, no further actions is needed.
  kNoop,
};

// An adaptor class to provide a unified interpretation result of
// |EnrollRequest| and |GetCertificateRequest|. This class provides the
// following families of operations:
// 1. Constructors that build |AttestationFlowData| based on |EnrollRequest| or
// |GetCertificateRequest|, and their accompanying callbacks.
// 2. Derived information from the data input.
// 3. Accessors of the current status of the attestation flow.
// 4. Operations that call callbacks.
class AttestationFlowData {
  using EnrollCallback = AttestationInterface::EnrollCallback;
  using GetCertificateCallback = AttestationInterface::GetCertificateCallback;

 public:
  AttestationFlowData() = delete;
  AttestationFlowData(const EnrollRequest& request, EnrollCallback callback);
  AttestationFlowData(const GetCertificateRequest& request,
                      GetCertificateCallback callback);

  // Derived information from the static data.
  ACAType aca_type() const;
  bool shall_enroll() const;
  bool shall_get_certificate() const;
  bool forced_enrollment() const;
  bool forced_get_certificate() const;
  const GetCertificateRequest& get_certificate_request() const;
  std::string username() const;
  std::string key_label() const;

  // Statuses of this attestation flow.
  AttestationFlowAction action() const { return action_; }
  void set_action(AttestationFlowAction action) { action_ = action; }
  AttestationStatus status() const { return status_; }
  void set_status(AttestationStatus status) { status_ = status; }
  std::string result_request() const { return result_request_; }
  void emplace_result_request(std::string&& result_request) {
    result_request_ = std::move(result_request);
  }
  std::string result_response() const { return result_response_; }
  void set_result_response(const std::string& result_response) {
    result_response_ = result_response;
  }
  const std::string& certificate() const { return certificate_; }
  const std::string& certified_key_credential() const {
    return certified_key_credential_;
  }
  const std::string& key_blob() const { return key_blob_; }
  void set_public_key(std::string public_key) {
    public_key_ = std::move(public_key);
  }
  void set_certificate(std::string certificate) {
    certificate_ = std::move(certificate);
  }
  void set_certified_key_credential(std::string certified_key_credential) {
    certified_key_credential_ = std::move(certified_key_credential);
  }
  void set_key_blob(std::string blob) { key_blob_ = std::move(blob); }

  // Operations on callbacks.
  void ReturnStatus();
  void ReturnCertificate();

 private:
  const std::optional<EnrollRequest> enroll_request_;
  EnrollCallback enroll_callback_;
  const std::optional<GetCertificateRequest> get_certificate_request_;
  GetCertificateCallback get_certificate_callback_;
  AttestationFlowAction action_{AttestationFlowAction::kUnknown};
  AttestationStatus status_{STATUS_SUCCESS};
  std::string result_request_;
  std::string result_response_;
  std::string public_key_;
  std::string certificate_;
  std::string certified_key_credential_;
  std::string key_blob_;
};

}  // namespace attestation

#endif  // ATTESTATION_SERVER_ATTESTATION_FLOW_H_

// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ATTESTATION_PCA_AGENT_CLIENT_FAKE_PCA_AGENT_PROXY_H_
#define ATTESTATION_PCA_AGENT_CLIENT_FAKE_PCA_AGENT_PROXY_H_

#include <string>
#include <utility>

#include <attestation/pca_agent/dbus-proxy-mocks.h>
#include <attestation/proto_bindings/pca_agent.pb.h>
#include <base/task/single_thread_task_runner.h>
#include <base/time/time.h>

namespace attestation {
namespace pca_agent {
namespace client {

// This class supports faking 4 conditions:
// 1) no any failure (default behavior),
// 2) dbus connection error (injected by |Set***DBusError|.
// 3) bad pca_agentd returned status (injected by |SetBad***Status|.
// 4) bad pca response from server (injected by |SetBad***PcaResponse|.
// Also,it supports the dbus response delay (injected by |Set***CallbackDelay|.
//
// Note that after any error injection, any other follow-up error injections are
// not considered as normal usecase; also, this class doesn't support the reset
// of any error injection because we don't have such usecase yet.
class FakePcaAgentProxy : public org::chromium::PcaAgentProxyMock {
 public:
  explicit FakePcaAgentProxy(TpmVersion tpm_version)
      : tpm_version_(tpm_version) {
    using testing::_;
    using testing::Invoke;
    ON_CALL(*this, EnrollAsync(_, _, _, _))
        .WillByDefault(Invoke(this, &FakePcaAgentProxy::FakeEnrollAsync));
    ON_CALL(*this, GetCertificateAsync(_, _, _, _))
        .WillByDefault(
            Invoke(this, &FakePcaAgentProxy::FakeGetCertificateAsync));
  }

  // Error/delay injections. More information can be found in the doc of this
  // class.
  void SetEnrollDBusError() { enroll_config_.success = false; }
  void SetBadEnrollStatus(AttestationStatus status) {
    ASSERT_NE(status, STATUS_SUCCESS);
    enroll_config_.status = status;
  }
  void SetBadEnrollPcaResponse() {
    enroll_config_.is_good_pca_response = false;
  }
  void SetEnrollCallbackDelay(const base::TimeDelta& t) {
    enroll_config_.delay = t;
  }
  void SetGetCertificateDBusError() { get_certificate_config_.success = false; }
  void SetBadGetCertificateStatus(AttestationStatus status) {
    ASSERT_NE(status, STATUS_SUCCESS);
    get_certificate_config_.status = status;
  }
  void SetBadGetCertificatePcaResponse() {
    get_certificate_config_.is_good_pca_response = false;
  }
  void SetGetCertificateCallbackDelay(const base::TimeDelta& t) {
    get_certificate_config_.delay = t;
  }

 private:
  const TpmVersion tpm_version_;
  // Internal configuration data; see fields for details.
  struct Config {
    // Success of dbus call. If |false|, then all other error flags below are
    // ineffective.
    bool success{true};
    // Returned status from |pca_agentd|. If |false|, |is_good_pca_response| is
    // ineffective.
    AttestationStatus status{STATUS_SUCCESS};
    // If the PCA response is good.
    bool is_good_pca_response{true};

    // Delay the task is posted with.
    base::TimeDelta delay{base::Milliseconds(0)};
  };

  // Respective configurations for enrollment and certification.
  Config enroll_config_;
  Config get_certificate_config_;

  // Respective the expected replies.
  EnrollReply enroll_reply_;
  GetCertificateReply get_certificate_reply_;

  // Error returned when dbus error.
  brillo::ErrorPtr dbus_error_{
      brillo::Error::Create(base::Location(), "", "", "")};

  template <class ReplyType, class SuccessCallbackType, class ErrorCallbackType>
  void PostTask(const Config& config,
                const ReplyType& reply,
                SuccessCallbackType on_success,
                ErrorCallbackType on_error) {
    auto task = config.success
                    ? base::BindOnce(std::move(on_success), reply)
                    : base::BindOnce(std::move(on_error), dbus_error_.get());
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
        FROM_HERE, std::move(task), config.delay);
  }

  void FakeEnrollAsync(
      const EnrollRequest& request,
      base::OnceCallback<void(const EnrollReply&)> success_callback,
      base::OnceCallback<void(brillo::Error*)> error_callback,
      int /*timeout_ms*/) {
    enroll_reply_.set_status(enroll_config_.status);
    if (enroll_config_.status == STATUS_SUCCESS) {
      enroll_reply_.set_response(
          CreateCAEnrollResponse(enroll_config_.is_good_pca_response));
    }
    PostTask(enroll_config_, enroll_reply_, std::move(success_callback),
             std::move(error_callback));
  }

  void FakeGetCertificateAsync(
      const GetCertificateRequest& request,
      base::OnceCallback<void(const GetCertificateReply&)> success_callback,
      base::OnceCallback<void(brillo::Error*)> error_callback,
      int /*timeout_ms*/) {
    get_certificate_reply_.set_status(get_certificate_config_.status);
    if (get_certificate_config_.status == STATUS_SUCCESS) {
      AttestationCertificateRequest pca_request;
      ASSERT_TRUE(pca_request.ParseFromString(request.request()));
      get_certificate_reply_.set_response(
          CreateCACertResponse(get_certificate_config_.is_good_pca_response,
                               pca_request.message_id()));
    }
    PostTask(get_certificate_config_, get_certificate_reply_,
             std::move(success_callback), std::move(error_callback));
  }

  // Creates a fake enroll response.
  std::string CreateCAEnrollResponse(bool success) {
    AttestationEnrollmentResponse response_pb;
    if (success) {
      response_pb.set_status(OK);
      response_pb.set_detail("");
      response_pb.mutable_encrypted_identity_credential()->set_tpm_version(
          tpm_version_);
      response_pb.mutable_encrypted_identity_credential()->set_asym_ca_contents(
          "1234");
      response_pb.mutable_encrypted_identity_credential()
          ->set_sym_ca_attestation("5678");
      response_pb.mutable_encrypted_identity_credential()->set_encrypted_seed(
          "seed");
      response_pb.mutable_encrypted_identity_credential()->set_credential_mac(
          "mac");
      response_pb.mutable_encrypted_identity_credential()
          ->mutable_wrapped_certificate()
          ->set_wrapped_key("wrapped");
    } else {
      response_pb.set_status(SERVER_ERROR);
      response_pb.set_detail("fake_enroll_error");
    }
    std::string response_str;
    response_pb.SerializeToString(&response_str);
    return response_str;
  }

  // Creates a fake certificate response corresponding to the request with
  // |message_id|.
  std::string CreateCACertResponse(bool success, std::string message_id) {
    AttestationCertificateResponse response_pb;
    if (success) {
      response_pb.set_status(OK);
      response_pb.set_detail("");
      response_pb.set_message_id(message_id);
      response_pb.set_certified_key_credential("fake_cert");
      response_pb.set_intermediate_ca_cert("fake_ca_cert");
      *response_pb.add_additional_intermediate_ca_cert() = "fake_ca_cert2";
    } else {
      response_pb.set_status(SERVER_ERROR);
      response_pb.set_message_id(message_id);
      response_pb.set_detail("fake_sign_error");
    }
    std::string response_str;
    response_pb.SerializeToString(&response_str);
    return response_str;
  }
};

}  // namespace client
}  // namespace pca_agent
}  // namespace attestation

#endif  // ATTESTATION_PCA_AGENT_CLIENT_FAKE_PCA_AGENT_PROXY_H_

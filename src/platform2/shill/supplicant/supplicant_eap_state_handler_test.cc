// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/supplicant/supplicant_eap_state_handler.h"

#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "shill/mock_log.h"
#include "shill/supplicant/wpa_supplicant.h"

using testing::_;
using testing::EndsWith;
using testing::Mock;

namespace shill {

class SupplicantEAPStateHandlerTest : public testing::Test {
 public:
  SupplicantEAPStateHandlerTest() : failure_(Service::kFailureNone) {}
  ~SupplicantEAPStateHandlerTest() override = default;

 protected:
  void StartEAP() {
    EXPECT_CALL(log_, Log(logging::LOGGING_INFO, _,
                          EndsWith("Authentication starting.")));
    EXPECT_FALSE(
        handler_.ParseStatus(WPASupplicant::kEAPStatusStarted, "", &failure_));
    Mock::VerifyAndClearExpectations(&log_);
  }

  const std::string& GetTLSError() { return handler_.tls_error_; }

  SupplicantEAPStateHandler handler_;
  Service::ConnectFailure failure_;
  ScopedMockLog log_;
};

TEST_F(SupplicantEAPStateHandlerTest, Construct) {
  EXPECT_FALSE(handler_.is_eap_in_progress());
  EXPECT_EQ("", GetTLSError());
}

TEST_F(SupplicantEAPStateHandlerTest, AuthenticationStarting) {
  StartEAP();
  EXPECT_TRUE(handler_.is_eap_in_progress());
  EXPECT_EQ("", GetTLSError());
  EXPECT_EQ(Service::kFailureNone, failure_);
}

TEST_F(SupplicantEAPStateHandlerTest, AcceptedMethod) {
  StartEAP();
  const std::string kEAPMethod("EAP-ROCHAMBEAU");
  EXPECT_CALL(log_, Log(logging::LOGGING_INFO, _,
                        EndsWith("accepted method " + kEAPMethod)));
  EXPECT_FALSE(handler_.ParseStatus(
      WPASupplicant::kEAPStatusAcceptProposedMethod, kEAPMethod, &failure_));
  EXPECT_TRUE(handler_.is_eap_in_progress());
  EXPECT_EQ("", GetTLSError());
  EXPECT_EQ(Service::kFailureNone, failure_);
}

TEST_F(SupplicantEAPStateHandlerTest, SuccessfulCompletion) {
  StartEAP();
  EXPECT_CALL(log_,
              Log(_, _, EndsWith("Completed authentication successfully.")));
  EXPECT_TRUE(handler_.ParseStatus(WPASupplicant::kEAPStatusCompletion,
                                   WPASupplicant::kEAPParameterSuccess,
                                   &failure_));
  EXPECT_FALSE(handler_.is_eap_in_progress());
  EXPECT_EQ("", GetTLSError());
  EXPECT_EQ(Service::kFailureNone, failure_);
}

TEST_F(SupplicantEAPStateHandlerTest, EAPFailureGeneric) {
  StartEAP();
  // An EAP failure without a previous TLS indication yields a generic failure.
  EXPECT_FALSE(handler_.ParseStatus(WPASupplicant::kEAPStatusCompletion,
                                    WPASupplicant::kEAPParameterFailure,
                                    &failure_));

  // Since it hasn't completed successfully, we must assume even in failure
  // that wpa_supplicant is continuing the EAP authentication process.
  EXPECT_TRUE(handler_.is_eap_in_progress());
  EXPECT_EQ("", GetTLSError());
  EXPECT_EQ(Service::kFailureEAPAuthentication, failure_);
}

TEST_F(SupplicantEAPStateHandlerTest, EAPFailureLocalTLSIndication) {
  StartEAP();
  // A TLS indication should be stored but a failure should not be returned.
  EXPECT_FALSE(handler_.ParseStatus(WPASupplicant::kEAPStatusLocalTLSAlert, "",
                                    &failure_));
  EXPECT_TRUE(handler_.is_eap_in_progress());
  EXPECT_EQ(WPASupplicant::kEAPStatusLocalTLSAlert, GetTLSError());
  EXPECT_EQ(Service::kFailureNone, failure_);

  // An EAP failure with a previous TLS indication yields a specific failure.
  EXPECT_FALSE(handler_.ParseStatus(WPASupplicant::kEAPStatusCompletion,
                                    WPASupplicant::kEAPParameterFailure,
                                    &failure_));
  EXPECT_TRUE(handler_.is_eap_in_progress());
  EXPECT_EQ(Service::kFailureEAPLocalTLS, failure_);
}

TEST_F(SupplicantEAPStateHandlerTest, EAPFailureRemoteTLSIndication) {
  StartEAP();
  // A TLS indication should be stored but a failure should not be returned.
  EXPECT_FALSE(handler_.ParseStatus(WPASupplicant::kEAPStatusRemoteTLSAlert, "",
                                    &failure_));
  EXPECT_TRUE(handler_.is_eap_in_progress());
  EXPECT_EQ(WPASupplicant::kEAPStatusRemoteTLSAlert, GetTLSError());
  EXPECT_EQ(Service::kFailureNone, failure_);

  // An EAP failure with a previous TLS indication yields a specific failure.
  EXPECT_FALSE(handler_.ParseStatus(WPASupplicant::kEAPStatusCompletion,
                                    WPASupplicant::kEAPParameterFailure,
                                    &failure_));
  EXPECT_TRUE(handler_.is_eap_in_progress());
  EXPECT_EQ(Service::kFailureEAPRemoteTLS, failure_);
}

TEST_F(SupplicantEAPStateHandlerTest, BadRemoteCertificateVerification) {
  StartEAP();
  const std::string kStrangeParameter("ennui");
  EXPECT_CALL(
      log_,
      Log(logging::LOGGING_ERROR, _,
          EndsWith(std::string("Unexpected ") +
                   WPASupplicant::kEAPStatusRemoteCertificateVerification +
                   " parameter: " + kStrangeParameter)));
  EXPECT_FALSE(handler_.ParseStatus(
      WPASupplicant::kEAPStatusRemoteCertificateVerification, kStrangeParameter,
      &failure_));
  // Although we reported an error, this shouldn't mean failure.
  EXPECT_TRUE(handler_.is_eap_in_progress());
  EXPECT_EQ("", GetTLSError());
  EXPECT_EQ(Service::kFailureNone, failure_);
}

TEST_F(SupplicantEAPStateHandlerTest, ParameterNeeded) {
  StartEAP();
  const std::string kAuthenticationParameter("nudge nudge say no more");
  EXPECT_CALL(
      log_,
      Log(logging::LOGGING_ERROR, _,
          EndsWith(
              std::string("aborted due to missing authentication parameter: ") +
              kAuthenticationParameter)));
  EXPECT_FALSE(handler_.ParseStatus(WPASupplicant::kEAPStatusParameterNeeded,
                                    kAuthenticationParameter, &failure_));
  EXPECT_TRUE(handler_.is_eap_in_progress());
  EXPECT_EQ("", GetTLSError());
  EXPECT_EQ(Service::kFailureEAPAuthentication, failure_);
}

TEST_F(SupplicantEAPStateHandlerTest, ParameterNeededPin) {
  StartEAP();
  EXPECT_FALSE(handler_.ParseStatus(WPASupplicant::kEAPStatusParameterNeeded,
                                    WPASupplicant::kEAPRequestedParameterPin,
                                    &failure_));
  EXPECT_TRUE(handler_.is_eap_in_progress());
  EXPECT_EQ("", GetTLSError());
  EXPECT_EQ(Service::kFailurePinMissing, failure_);
}

}  // namespace shill

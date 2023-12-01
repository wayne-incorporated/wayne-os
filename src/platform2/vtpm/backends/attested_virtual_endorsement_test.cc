// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vtpm/backends/attested_virtual_endorsement.h"

#include <attestation/proto_bindings/attestation_ca.pb.h>
#include <attestation/proto_bindings/interface.pb.h>
#include <brillo/errors/error.h>

// Requires proto_bindings `attestation`.
#include <attestation-client-test/attestation/dbus-proxy-mocks.h>

namespace vtpm {

namespace {

using org::chromium::AttestationProxyMock;
using ::testing::_;
using ::testing::ByMove;
using ::testing::DoAll;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::SetArgPointee;
using ::testing::StrictMock;
using ::testing::WithArgs;

constexpr char kFakeCertificate[] = "fake cert";
constexpr attestation::AttestationStatus kFailedStatus =
    attestation::STATUS_UNEXPECTED_DEVICE_ERROR;

}  // namespace

class AttestedVirtualEndorsementTest : public testing::Test {
 public:
  void SetUp() override {
    ON_CALL(mock_attestation_proxy_, GetCertificate(_, _, _, _))
        .WillByDefault(WithArgs<0, 1>(
            Invoke(this, &AttestedVirtualEndorsementTest::FakeGetCertificate)));
  }
  // Serializes the request and put it into `reply`'s `key_blob()` field, so
  // that the tester can parse the request back and check what is inside the
  // request.
  bool FakeGetCertificate(const attestation::GetCertificateRequest& request,
                          attestation::GetCertificateReply* reply) {
    reply->set_key_blob(request.SerializeAsString());
    reply->set_certified_key_credential(kFakeCertificate);
    reply->set_status(attestation::STATUS_SUCCESS);
    return true;
  }
  bool FakeGetCertificateWithFailedStatus(
      attestation::GetCertificateReply* reply) {
    reply->set_status(kFailedStatus);
    return true;
  }
  bool FakeGetCertificateWithError(brillo::ErrorPtr* err) {
    *err = brillo::Error::Create(base::Location(), "", "", "");
    return false;
  }

 protected:
  StrictMock<AttestationProxyMock> mock_attestation_proxy_;
  AttestedVirtualEndorsement endorsemnet_{&mock_attestation_proxy_};
};

namespace {

TEST_F(AttestedVirtualEndorsementTest, Success) {
  EXPECT_CALL(mock_attestation_proxy_, GetCertificate(_, _, _, _));
  EXPECT_EQ(endorsemnet_.Create(), trunks::TPM_RC_SUCCESS);

  EXPECT_EQ(endorsemnet_.GetEndorsementCertificate(), kFakeCertificate);

  const std::string ek = endorsemnet_.GetEndorsementKey();
  attestation::GetCertificateRequest request;
  ASSERT_TRUE(request.ParseFromString(ek));
  EXPECT_EQ(request.certificate_profile(),
            attestation::ENTERPRISE_VTPM_EK_CERTIFICATE);
  EXPECT_EQ(request.key_type(), attestation::KEY_TYPE_ECC);
  EXPECT_TRUE(request.shall_trigger_enrollment());
}

TEST_F(AttestedVirtualEndorsementTest, FailureDBusError) {
  EXPECT_CALL(mock_attestation_proxy_, GetCertificate(_, _, _, _))
      .WillOnce(WithArgs<2>(Invoke(
          this, &AttestedVirtualEndorsementTest::FakeGetCertificateWithError)));
  EXPECT_NE(endorsemnet_.Create(), trunks::TPM_RC_SUCCESS);
}

TEST_F(AttestedVirtualEndorsementTest, FailureAttestationService) {
  EXPECT_CALL(mock_attestation_proxy_, GetCertificate(_, _, _, _))
      .WillOnce(
          WithArgs<1>(Invoke(this, &AttestedVirtualEndorsementTest::
                                       FakeGetCertificateWithFailedStatus)));
  EXPECT_NE(endorsemnet_.Create(), trunks::TPM_RC_SUCCESS);
}

}  // namespace

}  // namespace vtpm

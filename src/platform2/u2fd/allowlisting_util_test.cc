// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "u2fd/allowlisting_util.h"

#include <functional>
#include <limits>
#include <memory>
#include <optional>

#include <attestation/proto_bindings/interface.pb.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <policy/device_policy.h>
#include <policy/libpolicy.h>
#include <policy/mock_device_policy.h>
#include <policy/mock_libpolicy.h>

#include "u2fd/client/util.h"

namespace u2f {
namespace {

using testing::_;
using testing::DoAll;
using testing::Return;
using testing::ReturnRef;
using testing::SetArgPointee;
using testing::StrictMock;

// Certificate, before attestation data is appended.
constexpr uint8_t kCertificateHeader[2] = {0x30, 0x82};
constexpr uint8_t kCertificateLength[2] = {0x01, 0x2c};  // = 300
constexpr uint8_t kCertificateBody[300] = {[0 ... 299] = 0xff};

// Data returned from attestationd.
constexpr char kTpmMetadata[109] = {[0 ... 108] = 0x1a};
constexpr char kTpmSignature[256] = {[0 ... 255] = 0x1e};

// Data loaded from policy.
constexpr char kDeviceId[36 + 1 /* null terminator */] =
    "aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb";

// Certificate, after attestation data is appended. Elements not listed here are
// unchanged.
constexpr uint8_t kFinalCertificateMetadataHeader[2] = {
    0x04 /* Octet String */, sizeof(kTpmMetadata) /* Metadata Length */};
constexpr uint8_t kFinalCertificateSignatureHeader[4] = {
    0x04,       // Octet String
    0x82,       // Long Form Length, 2 bytes
    0x01, 0x00  // Signature Length: 256
};
constexpr uint8_t kFinalCertificateDeviceIdHeader[2] = {
    0x13 /* Printable String */,
    sizeof(kDeviceId) - 1 /* Device Id Length (excl. null terminator) */};

// New length of the certificate body is the original length, plus all appended
// data and associated headers.
//
// Original Length:  300 +
// Metadata Header:  2   +
// Metadata          109 +
// Signature Header: 4   +
// Signature:        256 +
// Device Id Header: 2   +
// Device Id:        36
//                       = 709
constexpr uint8_t kFinalCertificateLength[2] = {0x02, 0xc5};

constexpr int kMaxAsn1FieldSize = std::numeric_limits<uint16_t>::max();

class AllowlistingUtilTest : public ::testing::Test {
 public:
  AllowlistingUtilTest() : util_(CreateMockAttestationdCallback()) {}

  void SetUp() override {
    mock_policy_provider_ = new StrictMock<policy::MockPolicyProvider>();
    util_.SetPolicyProviderForTest(
        std::unique_ptr<policy::PolicyProvider>(mock_policy_provider_));
    attestationd_called_ = false;
    expect_attestationd_call_ = false;
  }

  void TearDown() override {
    EXPECT_EQ(expect_attestationd_call_, attestationd_called_);
  }

 protected:
  // Build and return a standard G2F certificate.
  std::vector<uint8_t> BuildCert() {
    std::vector<uint8_t> cert;
    util::AppendToVector(kCertificateHeader, &cert);
    util::AppendToVector(kCertificateLength, &cert);
    util::AppendToVector(kCertificateBody, &cert);
    expected_attestationd_cert_size_ = cert.size();
    return cert;
  }

  // Builds a success reply for the specified cert, which will be returned by
  // any expected calls to attestationd.
  void ReturnAttestationSuccessReply(const std::vector<uint8_t>& cert) {
    attestationd_reply_ = attestation::GetCertifiedNvIndexReply();
    attestationd_reply_->set_status(attestation::STATUS_SUCCESS);
    attestationd_reply_->mutable_certified_data()->append(kTpmMetadata,
                                                          sizeof(kTpmMetadata));
    attestationd_reply_->mutable_certified_data()->append(
        reinterpret_cast<const char*>(cert.data()), cert.size());
    attestationd_reply_->mutable_signature()->append(kTpmSignature,
                                                     sizeof(kTpmSignature));
  }

  // Expect a call to attestationd, and respond with a success message
  // containing a certified copy of the G2F certificate stored in cert_ (call
  // BuildCert() first).
  void ExpectAttestationCall() { expect_attestationd_call_ = true; }

  // Expect a call to get Device Id, and respond with a success response
  // including the the specified |id|.
  void ExpectGetDeviceId(std::string id) {
    EXPECT_CALL(*mock_policy_provider_, Reload()).WillOnce(Return(true));
    EXPECT_CALL(*mock_policy_provider_, GetDevicePolicy())
        .WillOnce(ReturnRef(mock_device_policy_));
    EXPECT_CALL(mock_device_policy_, GetDeviceDirectoryApiId(_))
        .WillOnce(DoAll(SetArgPointee<0>(id), Return(true)));
  }

  // Get a copy of the certificate, as we expect it to be once the allowlisting
  // data has been appended.
  std::vector<uint8_t> GetExpectedCertWithAllowlistData() {
    std::vector<uint8_t> cert;

    // Header with updated length.
    util::AppendToVector(kCertificateHeader, &cert);
    util::AppendToVector(kFinalCertificateLength, &cert);

    // Original Body.
    util::AppendToVector(kCertificateBody, &cert);

    // TPM Metadata.
    util::AppendToVector(kFinalCertificateMetadataHeader, &cert);
    util::AppendToVector(kTpmMetadata, &cert);

    // Signature.
    util::AppendToVector(kFinalCertificateSignatureHeader, &cert);
    util::AppendToVector(kTpmSignature, &cert);

    // Device Id.
    util::AppendToVector(kFinalCertificateDeviceIdHeader, &cert);
    util::AppendToVector(std::string(kDeviceId), &cert);

    return cert;
  }

  // Attempt to append data to the specified cert, and check it fails.
  void ExpectAppendDataFails(std::vector<uint8_t>* cert) {
    std::vector<uint8_t> cert_original = *cert;
    EXPECT_FALSE(util_.AppendDataToCert(cert));
    // Check we didn't modify cert.
    EXPECT_EQ(cert_original, *cert);
  }

 private:
  std::function<std::optional<attestation::GetCertifiedNvIndexReply>(int)>
  CreateMockAttestationdCallback() {
    return [this](int size) {
      // Check we were expecting this.
      EXPECT_TRUE(expect_attestationd_call_);

      // We should only ever have at most one call.
      EXPECT_FALSE(attestationd_called_);
      attestationd_called_ = true;

      EXPECT_EQ(expected_attestationd_cert_size_, size);

      return attestationd_reply_;
    };
  }

  // Whether we expect a call to attestationd, and if so, the size of the cert
  // parameter passed.
  bool expect_attestationd_call_;
  int expected_attestationd_cert_size_;

  // Actual behavior.
  bool attestationd_called_;

 protected:
  AllowlistingUtil util_;

  StrictMock<policy::MockPolicyProvider>* mock_policy_provider_;  // Not Owned.
  StrictMock<policy::MockDevicePolicy> mock_device_policy_;

  // If called, what we should return from 'attestationd'
  std::optional<attestation::GetCertifiedNvIndexReply> attestationd_reply_;
};

TEST_F(AllowlistingUtilTest, AppendDataSuccess) {
  std::vector<uint8_t> cert = BuildCert();

  ExpectAttestationCall();
  ReturnAttestationSuccessReply(cert);
  ExpectGetDeviceId(kDeviceId);

  // Sanity Check.
  EXPECT_NE(GetExpectedCertWithAllowlistData(), cert);

  EXPECT_TRUE(util_.AppendDataToCert(&cert));

  // Check contents of resulting cert.
  EXPECT_EQ(GetExpectedCertWithAllowlistData(), cert);
}

TEST_F(AllowlistingUtilTest, AppendDataNullCertificate) {
  EXPECT_FALSE(util_.AppendDataToCert(nullptr));
}

TEST_F(AllowlistingUtilTest, AppendDataCertTooShort) {
  std::vector<uint8_t> cert;
  util::AppendToVector(kCertificateHeader, &cert);
  ExpectAppendDataFails(&cert);
}

TEST_F(AllowlistingUtilTest, AppendDataCertUnexpectedFirstBytes) {
  std::vector<uint8_t> cert = {0xff, 0xff, 0xff, 0xff};
  EXPECT_FALSE(util_.AppendDataToCert(&cert));
  ExpectAppendDataFails(&cert);

  cert[0] = kCertificateHeader[0];
  ExpectAppendDataFails(&cert);
}

TEST_F(AllowlistingUtilTest, AppendDataPolicyReloadFailure) {
  std::vector<uint8_t> cert = BuildCert();

  EXPECT_CALL(*mock_policy_provider_, Reload()).WillOnce(Return(false));

  ExpectAppendDataFails(&cert);
}

TEST_F(AllowlistingUtilTest, AppendDataDeviceIdMissing) {
  std::vector<uint8_t> cert = BuildCert();

  EXPECT_CALL(*mock_policy_provider_, Reload()).WillOnce(Return(true));
  EXPECT_CALL(*mock_policy_provider_, GetDevicePolicy())
      .WillOnce(ReturnRef(mock_device_policy_));
  EXPECT_CALL(mock_device_policy_, GetDeviceDirectoryApiId(_))
      .WillOnce(Return(false));

  ExpectAppendDataFails(&cert);
}

TEST_F(AllowlistingUtilTest, AppendDataAttestationdCallFails) {
  std::vector<uint8_t> cert = BuildCert();
  ExpectGetDeviceId(kDeviceId);

  // Expect the call, we haven't set the reply so will return std::nullopt.
  ExpectAttestationCall();

  ExpectAppendDataFails(&cert);
}

TEST_F(AllowlistingUtilTest, AppendDataAttestationdReturnsError) {
  std::vector<uint8_t> cert = BuildCert();

  ExpectAttestationCall();
  ReturnAttestationSuccessReply(cert);
  // Override with failure status.
  attestationd_reply_->set_status(attestation::STATUS_NOT_AVAILABLE);

  ExpectGetDeviceId(kDeviceId);

  ExpectAppendDataFails(&cert);
}

TEST_F(AllowlistingUtilTest, AppendDataCertifiedDataTooShort) {
  std::vector<uint8_t> cert = BuildCert();

  ExpectAttestationCall();
  ReturnAttestationSuccessReply(cert);
  // Resize certified data to be smaller than the original cert.
  attestationd_reply_->mutable_certified_data()->resize(
      sizeof(kCertificateBody));

  ExpectGetDeviceId(kDeviceId);

  ExpectAppendDataFails(&cert);
}

TEST_F(AllowlistingUtilTest, AppendDataCertPrefixTooLong) {
  std::vector<uint8_t> cert = BuildCert();

  ReturnAttestationSuccessReply(cert);
  // Append enough data that the prefix will be too long to store as an ASN1
  // field with two byte length.
  attestationd_reply_->mutable_certified_data()->append(kMaxAsn1FieldSize, 'a');

  ExpectGetDeviceId(kDeviceId);
  ExpectAttestationCall();

  ExpectAppendDataFails(&cert);
}

TEST_F(AllowlistingUtilTest, AppendDataSignatureTooLong) {
  std::vector<uint8_t> cert = BuildCert();

  ExpectAttestationCall();
  ReturnAttestationSuccessReply(cert);
  // Append enough data that the prefix will be too long to store as an ASN1
  // field with two byte length.
  attestationd_reply_->mutable_signature()->append(kMaxAsn1FieldSize, 'a');

  ExpectGetDeviceId(kDeviceId);

  ExpectAppendDataFails(&cert);
}

TEST_F(AllowlistingUtilTest, AppendDataDeviceIdTooLong) {
  std::vector<uint8_t> cert = BuildCert();

  ExpectAttestationCall();
  ReturnAttestationSuccessReply(cert);

  std::string device_id_too_long(kMaxAsn1FieldSize + 1, 'a');
  ExpectGetDeviceId(device_id_too_long);

  ExpectAppendDataFails(&cert);
}

TEST_F(AllowlistingUtilTest, AppendDataAppendedDataTooLong) {
  std::vector<uint8_t> cert = BuildCert();

  ExpectAttestationCall();
  ReturnAttestationSuccessReply(cert);
  // Append enough data that overall, the total appended data will cause the
  // size of the modified cert to be too long to store as an ASN1 field with two
  // byte length.
  attestationd_reply_->mutable_signature()->append(
      // The signature is 256 bytes so we'll still exceed the max size.
      kMaxAsn1FieldSize - 100, 'a');

  ExpectGetDeviceId(kDeviceId);

  ExpectAppendDataFails(&cert);
}

}  // namespace
}  // namespace u2f

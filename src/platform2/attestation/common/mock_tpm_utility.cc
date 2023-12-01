// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "attestation/common/mock_tpm_utility.h"

#include <base/check.h>

#include <libhwsec-foundation/tpm/tpm_version.h>

using ::testing::_;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::WithArgs;

namespace {

class TransformString {
 public:
  explicit TransformString(std::string method) : method_(method) {}
  bool operator()(const std::string& in, std::string* out) {
    *out = attestation::MockTpmUtility::Transform(method_, in);
    return true;
  }

 private:
  std::string method_;
};

// Puts the fake identity key and binding data to |identity| to mock
// |MockTpmUtility::CreateIdentity|.
bool SetFakeIdentity(attestation::AttestationDatabase::Identity* identity) {
  auto identity_binding_pb = identity->mutable_identity_binding();
  auto identity_key_pb = identity->mutable_identity_key();
  identity_binding_pb->set_identity_public_key_der("identity_public_key_der");
  identity_binding_pb->set_identity_public_key_tpm_format(
      "identity_public_key_tpm_format");
  identity_binding_pb->set_identity_binding("identity_binding");
  identity_binding_pb->set_pca_public_key("pca_public_key");
  identity_binding_pb->set_identity_label("identity_label");
  identity_key_pb->set_identity_public_key_der("identity_public_key");
  identity_key_pb->set_identity_key_blob("identity_key_blob");
  return true;
}

}  // namespace

namespace attestation {

MockTpmUtility::MockTpmUtility() {
  ON_CALL(*this, Initialize()).WillByDefault(Return(true));
  ON_CALL(*this, GetVersion()).WillByDefault(Invoke([]() {
    TPM_SELECT_BEGIN;
    TPM1_SECTION({ return TPM_1_2; });
    TPM2_SECTION({ return TPM_2_0; });
    OTHER_TPM_SECTION({
      CHECK(false) << "Needs to specify the TPM version in test environment.";
      return TPM_2_0;
    });
    TPM_SELECT_END;
  }));
  ON_CALL(*this, IsTpmReady()).WillByDefault(Return(true));
  ON_CALL(*this, ActivateIdentity(_, _, _, _)).WillByDefault(Return(true));
  ON_CALL(*this, ActivateIdentityForTpm2(_, _, _, _, _, _))
      .WillByDefault(Return(true));
  ON_CALL(*this, CreateCertifiedKey(_, _, _, _, _, _, _, _, _, _, _))
      .WillByDefault(Return(true));
  ON_CALL(*this, Unbind(_, _, _))
      .WillByDefault(WithArgs<1, 2>(Invoke(TransformString("Unbind"))));
  ON_CALL(*this, Sign(_, _, _))
      .WillByDefault(WithArgs<1, 2>(Invoke(TransformString("Sign"))));
  ON_CALL(*this, GetEndorsementPublicKey(_, _)).WillByDefault(Return(true));
  ON_CALL(*this, GetEndorsementCertificate(_, _)).WillByDefault(Return(true));
  ON_CALL(*this, GetNVDataSize(_, _)).WillByDefault(Return(true));
  ON_CALL(*this, CertifyNV(_, _, _, _, _)).WillByDefault(Return(true));
  ON_CALL(*this, ReadPCR(_, _)).WillByDefault(Return(true));
  ON_CALL(*this, RemoveOwnerDependency()).WillByDefault(Return(true));
  ON_CALL(*this, CreateIdentity(_, _))
      .WillByDefault(WithArgs<1>(Invoke(SetFakeIdentity)));
}

MockTpmUtility::~MockTpmUtility() {}

// static
std::string MockTpmUtility::Transform(const std::string& method,
                                      const std::string& input) {
  return input + "_fake_transform_" + method;
}

}  // namespace attestation

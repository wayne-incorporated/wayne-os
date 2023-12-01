// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>
#include <utility>
#include <variant>

#include <gtest/gtest.h>
#include <libhwsec/structures/signature_sealed_data_test_utils.h>

#include "cryptohome/signature_sealing/structures_proto.h"

using brillo::BlobFromString;

namespace cryptohome {

TEST(ChallengeSignatureAlgorithmTest, ToProtoFromProto) {
  for (auto algo : {
           structure::ChallengeSignatureAlgorithm::kRsassaPkcs1V15Sha1,
           structure::ChallengeSignatureAlgorithm::kRsassaPkcs1V15Sha256,
           structure::ChallengeSignatureAlgorithm::kRsassaPkcs1V15Sha384,
           structure::ChallengeSignatureAlgorithm::kRsassaPkcs1V15Sha512,
       }) {
    EXPECT_EQ(algo, proto::FromProto(proto::ToProto(algo)));
  }
}

TEST(ChallengeSignatureAlgorithmTest, FromProtoToProto) {
  for (auto algo : {
           ChallengeSignatureAlgorithm::CHALLENGE_RSASSA_PKCS1_V1_5_SHA1,
           ChallengeSignatureAlgorithm::CHALLENGE_RSASSA_PKCS1_V1_5_SHA256,
           ChallengeSignatureAlgorithm::CHALLENGE_RSASSA_PKCS1_V1_5_SHA384,
           ChallengeSignatureAlgorithm::CHALLENGE_RSASSA_PKCS1_V1_5_SHA512,
       }) {
    EXPECT_EQ(algo, proto::ToProto(proto::FromProto(algo)));
  }
}

TEST(SignatureSealedDataTest, ToProtoFromProtoTPM2) {
  hwsec::Tpm2PolicySignedData data{
      .public_key_spki_der = BlobFromString("public_key_spki_der"),
      .srk_wrapped_secret = BlobFromString("srk_wrapped_secret"),
      .scheme = 0x54321,
      .hash_alg = 0x12345,
      .pcr_policy_digests =
          {
              hwsec::Tpm2PolicyDigest{.digest = BlobFromString("digest0")},
              hwsec::Tpm2PolicyDigest{.digest = BlobFromString("digest1")},
          },
  };

  hwsec::SignatureSealedData struct_data = data;
  ASSERT_TRUE(std::holds_alternative<hwsec::Tpm2PolicySignedData>(struct_data));

  hwsec::SignatureSealedData final_data =
      proto::FromProto(proto::ToProto(struct_data));
  ASSERT_TRUE(std::holds_alternative<hwsec::Tpm2PolicySignedData>(final_data));

  const hwsec::Tpm2PolicySignedData& tpm2_data =
      std::get<hwsec::Tpm2PolicySignedData>(final_data);

  EXPECT_EQ(tpm2_data.public_key_spki_der, data.public_key_spki_der);
  EXPECT_EQ(tpm2_data.srk_wrapped_secret, data.srk_wrapped_secret);
  EXPECT_EQ(tpm2_data.scheme, data.scheme);
  EXPECT_EQ(tpm2_data.hash_alg, data.hash_alg);
  ASSERT_EQ(tpm2_data.pcr_policy_digests.size(), 2);
  ASSERT_EQ(data.pcr_policy_digests.size(), 2);
  EXPECT_EQ(tpm2_data.pcr_policy_digests[0].digest,
            data.pcr_policy_digests[0].digest);
  EXPECT_EQ(tpm2_data.pcr_policy_digests[1].digest,
            data.pcr_policy_digests[1].digest);
}

TEST(SignatureSealedDataTest, ToProtoFromProtoTPM1) {
  hwsec::Tpm12CertifiedMigratableKeyData data{
      .public_key_spki_der = BlobFromString("public_key_spki_der"),
      .srk_wrapped_cmk = BlobFromString("srk_wrapped_cmk"),
      .cmk_pubkey = BlobFromString("cmk_pubkey"),
      .cmk_wrapped_auth_data = BlobFromString("cmk_wrapped_auth_data"),
      .pcr_bound_items =
          {
              hwsec::Tpm12PcrBoundItem{
                  .pcr_values =
                      {
                          hwsec::Tpm12PcrValue{
                              .pcr_index = 4,
                              .pcr_value = BlobFromString("pcr_value1"),
                          },
                      },
                  .bound_secret = BlobFromString("bound_secret0"),
              },
              hwsec::Tpm12PcrBoundItem{
                  .pcr_values =
                      {
                          hwsec::Tpm12PcrValue{
                              .pcr_index = 4,
                              .pcr_value = BlobFromString("pcr_value1"),
                          },
                      },
                  .bound_secret = BlobFromString("bound_secret1"),
              },
          },
  };

  hwsec::SignatureSealedData struct_data = data;
  ASSERT_TRUE(std::holds_alternative<hwsec::Tpm12CertifiedMigratableKeyData>(
      struct_data));

  hwsec::SignatureSealedData final_data =
      proto::FromProto(proto::ToProto(struct_data));
  ASSERT_TRUE(std::holds_alternative<hwsec::Tpm12CertifiedMigratableKeyData>(
      final_data));

  const hwsec::Tpm12CertifiedMigratableKeyData& tpm1_data =
      std::get<hwsec::Tpm12CertifiedMigratableKeyData>(final_data);

  EXPECT_EQ(tpm1_data, data);
}

TEST(SignatureChallengeInfoTest, ToProtoFromProto) {
  hwsec::Tpm2PolicySignedData policy_data = {
      .public_key_spki_der = BlobFromString("public_key_spki_der"),
      .srk_wrapped_secret = BlobFromString("srk_wrapped_secret"),
      .scheme = 0x54321,
      .hash_alg = 0x12345,
      .pcr_policy_digests =
          {
              hwsec::Tpm2PolicyDigest{.digest = BlobFromString("digest0")},
              hwsec::Tpm2PolicyDigest{.digest = BlobFromString("digest1")},
          },
  };
  structure::SignatureChallengeInfo data{
      .public_key_spki_der = BlobFromString("public_key_spki_der"),
      .sealed_secret = policy_data,
      .salt = BlobFromString("salt"),
      .salt_signature_algorithm =
          structure::ChallengeSignatureAlgorithm::kRsassaPkcs1V15Sha384,
  };

  structure::SignatureChallengeInfo final_data =
      proto::FromProto(proto::ToProto(data));
  EXPECT_EQ(final_data.public_key_spki_der, data.public_key_spki_der);
  EXPECT_EQ(final_data.salt, data.salt);
  EXPECT_EQ(final_data.salt_signature_algorithm, data.salt_signature_algorithm);

  ASSERT_TRUE(std::holds_alternative<hwsec::Tpm2PolicySignedData>(
      final_data.sealed_secret));
  const hwsec::Tpm2PolicySignedData& tpm2_data =
      std::get<hwsec::Tpm2PolicySignedData>(final_data.sealed_secret);

  EXPECT_EQ(tpm2_data.public_key_spki_der, policy_data.public_key_spki_der);
  EXPECT_EQ(tpm2_data.srk_wrapped_secret, policy_data.srk_wrapped_secret);
  EXPECT_EQ(tpm2_data.scheme, policy_data.scheme);
  EXPECT_EQ(tpm2_data.hash_alg, policy_data.hash_alg);
  ASSERT_EQ(tpm2_data.pcr_policy_digests.size(), 2);
  ASSERT_EQ(policy_data.pcr_policy_digests.size(), 2);
  EXPECT_EQ(tpm2_data.pcr_policy_digests[0].digest,
            policy_data.pcr_policy_digests[0].digest);
  EXPECT_EQ(tpm2_data.pcr_policy_digests[1].digest,
            policy_data.pcr_policy_digests[1].digest);
}

TEST(ChallengePublicKeyInfoTest, ToProtoFromProto) {
  structure::ChallengePublicKeyInfo data{
      .public_key_spki_der = BlobFromString("public_key_spki_der"),
      .signature_algorithm = {
          structure::ChallengeSignatureAlgorithm::kRsassaPkcs1V15Sha1,
          structure::ChallengeSignatureAlgorithm::kRsassaPkcs1V15Sha256,
      }};

  structure::ChallengePublicKeyInfo final_data =
      proto::FromProto(proto::ToProto(data));
  EXPECT_EQ(final_data.public_key_spki_der, data.public_key_spki_der);
  EXPECT_EQ(final_data.signature_algorithm, data.signature_algorithm);
}

}  // namespace cryptohome

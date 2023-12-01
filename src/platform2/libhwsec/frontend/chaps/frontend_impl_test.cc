// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstdint>
#include <memory>
#include <utility>

#include <brillo/secure_blob.h>
#include <gmock/gmock-matchers.h>
#include <gtest/gtest.h>
#include <libhwsec-foundation/error/testing_helper.h>

#include "libhwsec/backend/digest_algorithms.h"
#include "libhwsec/backend/signing.h"
#include "libhwsec/error/tpm_retry_action.h"
#include "libhwsec/factory/tpm2_simulator_factory_for_test.h"
#include "libhwsec/frontend/chaps/frontend.h"
#include "libhwsec/structures/key.h"

using brillo::BlobFromString;
using hwsec_foundation::error::testing::NotOkWith;

namespace hwsec {

class ChapsFrontendImplTpm2SimTest : public testing::Test {
 public:
  void SetUp() override { hwsec_chaps_ = hwsec_factory_.GetChapsFrontend(); }

 protected:
  hwsec::Tpm2SimulatorFactoryForTest hwsec_factory_;
  std::unique_ptr<const ChapsFrontend> hwsec_chaps_;
};

TEST_F(ChapsFrontendImplTpm2SimTest, SignRsaCombinations) {
  const brillo::Blob kData(64, 'X');

  brillo::SecureBlob auth_value("auth_value");
  brillo::Blob public_exponent = {0x01, 0x00, 0x01};

  auto signing_only_key = hwsec_chaps_->GenerateRSAKey(
      1024, public_exponent, auth_value,
      ChapsFrontend::AllowSoftwareGen::kAllow,
      ChapsFrontend::AllowDecrypt::kNotAllow, ChapsFrontend::AllowSign::kAllow);

  ASSERT_OK(signing_only_key);

  auto normal_key = hwsec_chaps_->GenerateRSAKey(
      1024, public_exponent, auth_value,
      ChapsFrontend::AllowSoftwareGen::kAllow,
      ChapsFrontend::AllowDecrypt::kAllow, ChapsFrontend::AllowSign::kAllow);

  ASSERT_OK(normal_key);

  auto signing_only_key_2048 = hwsec_chaps_->GenerateRSAKey(
      2048, public_exponent, auth_value,
      ChapsFrontend::AllowSoftwareGen::kAllow,
      ChapsFrontend::AllowDecrypt::kNotAllow, ChapsFrontend::AllowSign::kAllow);

  ASSERT_OK(signing_only_key_2048);

  auto normal_key_2048 = hwsec_chaps_->GenerateRSAKey(
      1024, public_exponent, auth_value,
      ChapsFrontend::AllowSoftwareGen::kAllow,
      ChapsFrontend::AllowDecrypt::kAllow, ChapsFrontend::AllowSign::kAllow);

  ASSERT_OK(normal_key_2048);

  auto signing_only_key_no_software = hwsec_chaps_->GenerateRSAKey(
      1024, public_exponent, auth_value,
      ChapsFrontend::AllowSoftwareGen::kNotAllow,
      ChapsFrontend::AllowDecrypt::kNotAllow, ChapsFrontend::AllowSign::kAllow);

  ASSERT_OK(signing_only_key_no_software);

  auto normal_key_no_software = hwsec_chaps_->GenerateRSAKey(
      1024, public_exponent, auth_value,
      ChapsFrontend::AllowSoftwareGen::kNotAllow,
      ChapsFrontend::AllowDecrypt::kAllow, ChapsFrontend::AllowSign::kAllow);

  ASSERT_OK(normal_key_no_software);

  struct KeyParam {
    Key key;
    bool sign_only;
  };

  for (auto [key, sign_only] :
       {KeyParam{signing_only_key->key.GetKey(), true},
        KeyParam{normal_key->key.GetKey(), false},
        KeyParam{signing_only_key_2048->key.GetKey(), true},
        KeyParam{normal_key_2048->key.GetKey(), false},
        KeyParam{signing_only_key_no_software->key.GetKey(), true},
        KeyParam{normal_key_no_software->key.GetKey(), false}}) {
    for (DigestAlgorithm algo :
         {DigestAlgorithm::kMd5, DigestAlgorithm::kSha1,
          DigestAlgorithm::kSha256, DigestAlgorithm::kSha384,
          DigestAlgorithm::kSha512}) {
      for (SigningOptions::RsaPaddingScheme padding :
           {SigningOptions::RsaPaddingScheme::kPkcs1v15,
            SigningOptions::RsaPaddingScheme::kRsassaPss}) {
        auto digest = DigestData(algo, kData);
        ASSERT_OK(digest);

        auto sign_result = hwsec_chaps_->Sign(key, *digest,
                                              SigningOptions{
                                                  .digest_algorithm = algo,
                                                  .rsa_padding_scheme = padding,
                                              });

        if (sign_only && algo == DigestAlgorithm::kMd5 &&
            padding == SigningOptions::RsaPaddingScheme::kRsassaPss) {
          // We don't support this kind of case.
          EXPECT_THAT(sign_result, NotOkWith("Unsupported"));
          continue;
        }

        ASSERT_OK(sign_result);
        EXPECT_FALSE(sign_result->empty());

        // Check the null signing for kPkcs1v15.
        if (padding == SigningOptions::RsaPaddingScheme::kPkcs1v15) {
          auto header = GetDigestAlgorithmEncoding(algo);
          ASSERT_OK(header);
          brillo::Blob data_to_sign = brillo::CombineBlobs({*header, *digest});

          auto null_sign_result = hwsec_chaps_->Sign(
              key, data_to_sign,
              SigningOptions{
                  .digest_algorithm = DigestAlgorithm::kNoDigest,
                  .rsa_padding_scheme = padding,
              });
          ASSERT_OK(null_sign_result);
          EXPECT_FALSE(null_sign_result->empty());

          EXPECT_THAT(*sign_result, testing::ContainerEq(*null_sign_result));
        }
      }
    }
  }
}

TEST_F(ChapsFrontendImplTpm2SimTest, SignEccCombinations) {
  const brillo::Blob kData(64, 'X');

  brillo::SecureBlob auth_value("auth_value");

  auto signing_only_key = hwsec_chaps_->GenerateECCKey(
      NID_X9_62_prime256v1, auth_value, ChapsFrontend::AllowDecrypt::kNotAllow,
      ChapsFrontend::AllowSign::kAllow);

  ASSERT_OK(signing_only_key);

  auto normal_key = hwsec_chaps_->GenerateECCKey(
      NID_X9_62_prime256v1, auth_value, ChapsFrontend::AllowDecrypt::kAllow,
      ChapsFrontend::AllowSign::kAllow);

  ASSERT_OK(normal_key);

  for (Key key : {signing_only_key->key.GetKey(), normal_key->key.GetKey()}) {
    for (DigestAlgorithm algo :
         {DigestAlgorithm::kSha1, DigestAlgorithm::kSha256,
          DigestAlgorithm::kSha384, DigestAlgorithm::kSha512}) {
      auto digest = DigestData(algo, kData);
      ASSERT_OK(digest);

      auto sign_result = hwsec_chaps_->Sign(key, *digest,
                                            SigningOptions{
                                                .digest_algorithm = algo,
                                            });
      ASSERT_OK(sign_result);
      EXPECT_FALSE(sign_result->empty());
    }
  }
}

}  // namespace hwsec

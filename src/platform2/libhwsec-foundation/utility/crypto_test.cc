// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <limits>
#include <memory>
#include <string>
#include <vector>

#include <base/check.h>
#include <base/strings/string_number_conversions.h>
#include <base/logging.h>
#include <crypto/scoped_openssl_types.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libhwsec-foundation/utility/crypto.h"

using testing::_;
using testing::NiceMock;
using testing::Return;

namespace {

// RSA 1024 pre-generated key
// Public key: DER encoded SubjectPublicKeyInfo
// Private key: DER encoded PKCS#1 RSAPrivateKey
constexpr char kRsaDerPrivateKey[] =
    "3082025c02010002818100c080fd814be63035ca6bd264a5b300ceea9e93702d66ebf0c0c3"
    "cfd21a287c9195491225887b931d51a8b28813ecb2a256d427b13502b563103070d7de6ef8"
    "e0dce3b48987926d576fa6136d9209e1da6fe3f59be83d879054c1e2233c5f28c4a426978e"
    "97e18390c99e32f7e1ffd4187774c6939d15b5663c14ed08e741ea7b020301000102818025"
    "2840c6764a06403bc43826293db6083a8d45543fcf3ff7869dc53d7ec315d85c0270b841f1"
    "e8619e637ba27c8611acf8299747c33db4995c849d236dd1e9c3d7219ebaf3f90774144839"
    "0284653102cac0bfbdd2da07903a71b62d4b4577136b87ba5f837c6e70baa3284610a2a770"
    "598382e24e6b23c99824dc0ad0cec761024100fe441c16fc098a311b2b08f74e2ac58e269f"
    "d12e6a72d4e83d5e0bb2c00ba71db7889481349367507883ebf6d82bfd1bb68e506ddc0472"
    "57aa7ae8c9364d28d3024100c1d10ed2bcfea3806e60c991123727781fe9256332ead379de"
    "9b1290599fd57f34ebed4adf0943da2349bc3bbf8ae7519181f4ac81db96be302bb8681140"
    "aeb902407b3d5df4120339b4e57b2d6458c1c87146ed4d8156dd03aef117a549e565808199"
    "d49c4e27c28e5fe599e384087101c42deebab314e21eddb8e6cbefc2df113b0240212930bd"
    "13c3099c76c62e9698a4412787662f946a68cd2803d34a78d22ccbad891378b51fb6091af0"
    "80b42910dba63a49880fa1d85206d7a18c496fdccbd159024100d932619513fe956c64428f"
    "2dda042d3e20353b1b29b2e863b917708091866c47bf7a4492607af8eba66d8d7bf45d6ada"
    "4d19aea9004c05449b8c6369a109e081";
constexpr char kRsaDerPublicKey[] =
    "30819f300d06092a864886f70d010101050003818d0030818902818100c080fd814be63035"
    "ca6bd264a5b300ceea9e93702d66ebf0c0c3cfd21a287c9195491225887b931d51a8b28813"
    "ecb2a256d427b13502b563103070d7de6ef8e0dce3b48987926d576fa6136d9209e1da6fe3"
    "f59be83d879054c1e2233c5f28c4a426978e97e18390c99e32f7e1ffd4187774c6939d15b5"
    "663c14ed08e741ea7b0203010001";

// EC P-256 (prime256v1) pre-generated key
// Public key: DER encoded SubjectPublicKeyInfo
// Private key: DER encoded ECPrivateKey
constexpr char kEcDerPrivateKey[] =
    "307702010104207e1e647025d7bbf93ce583b88a0e554a22c5d711ea3754e39f9c6fabb2b6"
    "6b6ba00a06082a8648ce3d030107a14403420004b6a397746f0cad8f1cdf1cb1ddafabe35e"
    "65836a1a33a0f4b13ff5b0319cdb9f120b1e7cf733bcf0cdc490c251c982845e8326070e27"
    "f007c82767acab1c2700";
constexpr char kEcDerPublicKey[] =
    "3059301306072a8648ce3d020106082a8648ce3d03010703420004b6a397746f0cad8f1cdf"
    "1cb1ddafabe35e65836a1a33a0f4b13ff5b0319cdb9f120b1e7cf733bcf0cdc490c251c982"
    "845e8326070e27f007c82767acab1c2700";

std::vector<uint8_t> HexDecode(const std::string& hex) {
  std::vector<uint8_t> output;
  CHECK(base::HexStringToBytes(hex, &output));
  return output;
}

}  // namespace

namespace hwsec_foundation {
namespace utility {

class CryptoUtilityTest : public testing::Test {
 public:
  ~CryptoUtilityTest() override = default;

  void SetUp() override {
    SetupPreGeneratedRsaKey();
    SetupPreGeneratedEcKey();
  }

  void SetupPreGeneratedRsaKey() {
    std::vector<uint8_t> der_key = HexDecode(kRsaDerPrivateKey);
    const unsigned char* buf = der_key.data();
    rsa_key_.reset(d2i_RSAPrivateKey(nullptr, &buf, der_key.size()));
  }

  void SetupPreGeneratedEcKey() {
    std::vector<uint8_t> der_key = HexDecode(kEcDerPrivateKey);
    const unsigned char* buf = der_key.data();
    ecc_key_.reset(d2i_ECPrivateKey(nullptr, &buf, der_key.size()));
  }

 protected:
  crypto::ScopedRSA rsa_key_;
  crypto::ScopedEC_KEY ecc_key_;
};

TEST_F(CryptoUtilityTest, CreateSecureRandomBlobBadLength) {
  static_assert(sizeof(size_t) >= sizeof(int), "size_t is smaller than int!");
  size_t int_max = static_cast<size_t>(std::numeric_limits<int>::max());
  EXPECT_EQ(CreateSecureRandomBlob(int_max + 1).size(), 0);
}

TEST_F(CryptoUtilityTest, PreGeneratedKeyIsValid) {
  EXPECT_TRUE(rsa_key_);
  EXPECT_TRUE(ecc_key_);
}

TEST_F(CryptoUtilityTest, RsaKeyToSubjectPublicKeyInfoBytesSuccess) {
  auto opt_public_key = RsaKeyToSubjectPublicKeyInfoBytes(rsa_key_);
  EXPECT_TRUE(opt_public_key);
  EXPECT_EQ(*opt_public_key, HexDecode(kRsaDerPublicKey));
}

TEST_F(CryptoUtilityTest, RsaKeyToSubjectPublicKeyInfoBytesFailWithNullptr) {
  EXPECT_FALSE(RsaKeyToSubjectPublicKeyInfoBytes(nullptr));
}

TEST_F(CryptoUtilityTest, EccKeyToSubjectPublicKeyInfoBytesSuccess) {
  auto opt_public_key = EccKeyToSubjectPublicKeyInfoBytes(ecc_key_);
  EXPECT_TRUE(opt_public_key);
  EXPECT_EQ(*opt_public_key, HexDecode(kEcDerPublicKey));
}

TEST_F(CryptoUtilityTest, EccKeyToSubjectPublicKeyInfoBytesFailWithNullptr) {
  EXPECT_FALSE(EccKeyToSubjectPublicKeyInfoBytes(nullptr));
}

}  // namespace utility
}  // namespace hwsec_foundation

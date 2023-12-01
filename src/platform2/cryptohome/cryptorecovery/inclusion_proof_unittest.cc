// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/cryptorecovery/inclusion_proof.h"

#include <optional>
#include <string>
#include <vector>

#include <base/base64url.h>
#include <base/strings/string_number_conversions.h>
#include <brillo/secure_blob.h>
#include <gtest/gtest.h>
#include <libhwsec-foundation/crypto/big_num_util.h>
#include <libhwsec-foundation/crypto/elliptic_curve.h>

#include "cryptohome/cryptorecovery/inclusion_proof_test_util.h"
#include "cryptohome/cryptorecovery/recovery_crypto.h"
#include "cryptohome/cryptorecovery/recovery_crypto_util.h"

using ::hwsec_foundation::CreateBigNumContext;
using ::hwsec_foundation::EllipticCurve;
using ::hwsec_foundation::ScopedBN_CTX;

namespace cryptohome {
namespace cryptorecovery {

namespace {

// Hard-coded development ledger info, including the public key, name and key
// hash. It mirrors the value from the server.
constexpr char kDevLedgerName[] = "ChromeOSLedgerOwnerPrototype";
constexpr uint32_t kDevLedgerPublicKeyHash = 2517252912;
constexpr char kDevLedgerPublicKey[] =
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEUL2cKW4wHEdyWDjjJktxkijFOKJZ8rflR-Sfb-"
    "ToowJtLyNOBh6wj0anP4kP4llXK4HMZoJDKy9texKJl2UOog==";

// Hardcoded inclusion proof data, generated on the server using the dev ledger
// info.
constexpr char kFakePublicLedgerEntryHex[] =
    "A46E6C6F675F656E7472795F686173685820CC1CAB36511F9D6BFFB6456F69C1711021F8CC"
    "BB57D6699496A1FFCF634B1AFD707075626C69635F74696D657374616D701A6302C7006B72"
    "65636F766572795F6964784035306161633730663632343064343031333266366335336233"
    "66643036373533326336323331336537626162316136323531656261363964643432386266"
    "35356E736368656D615F76657273696F6E01";
constexpr char kFakePrivateLogEntryHex[] =
    "A6746F6E626F617264696E675F6D6574615F64617461A86A626F6172645F6E616D656A6661"
    "6B655F626F6172646F63727970746F686F6D655F7573657275313233343536373839303132"
    "3334353637383930317463727970746F686F6D655F757365725F74797065016E6465766963"
    "655F757365725F69647366616B655F6465766963655F757365725F69646B666F726D5F6661"
    "63746F727066616B655F666F726D5F666163746F726B7265636F766572795F696478403530"
    "61616337306636323430643430313332663663353362336664303637353332633632333133"
    "6537626162316136323531656261363964643432386266353568726C7A5F636F64656D6661"
    "6B655F726C7A5F636F64656E736368656D615F76657273696F6E01707075626C69635F7469"
    "6D657374616D701A6302C7006E726571756573746F725F757365726073726571756573746F"
    "725F757365725F74797065006E736368656D615F76657273696F6E016974696D657374616D"
    "701A630353B2";
constexpr char kFakeCheckpointNote[] =
    "4368726F6D654F535265636F766572794C65646765723A300A35353232390A4E5666354534"
    "7A784673415053346C4345387830636253576C7A41624E5131466A66784F33725861336F51"
    "3D0A0AE28094204368726F6D654F534C65646765724F776E657250726F746F74797065206C"
    "676F374D444245416941454C6269427164463049477A375175322B43597A42317443595131"
    "7531372B4E4242327A34507652596967496747562B574A4A5A5749386E674F594855326366"
    "536B4A7A6A68596E653644684266617A4C52414A535363493D0A";
const char* kFakeInclusionProof[] = {
    "F734AB286204006B2E5C952DAB4BFC837ED17875951792D3E86461001441D399",
    "671BBA77614BCD7691C54BFC54D08D03EEC359BB1CF54F625A1000D2510F1366",
    "674E325245DE026F05108D2946A5DF171FF956C5CEABCC08861A078AABD3F0E7",
    "92480585A66FE91C79A8A9AC8F63D264B3578932FD40C08F9C7EE6C7A2092546",
    "3C053DAF88CE9F704D9262C931BF67D90C0BBAB40A70F45876B50A473A5DBECB",
    "66ED0FE23561B763E01067565A033745298C6E5CD42E3BB4C040AE216436D0B7",
    "2F24697A3C1E07ADF113A7E3E3B44E9715FEAB348A597531EE9228BFEBDCBBA9",
    "50A2C261699FCA0945111D791EE3517278A08F40C3B0FBF9FE71D431074B1A85",
    "6FF294619FF205B18BA3CA72DE41A6A7C02B7004535B98B87F376886D79E3445",
    "BE3AA0DAFC1996A14A342F39A6CF0947E6E6DFB07FB59CBDF7A6A8E2AC68171D",
    "8608FB09D409AF849A9074D306A4FF5A3ABBE2DBACF0EE9EDC540854C3437EA9"};
constexpr uint64_t kFakeLeafIndex = 55228;

bool HexStringToBlob(const std::string& hex, brillo::Blob* blob) {
  std::string str;
  if (!base::HexStringToString(hex, &str)) {
    return false;
  }
  *blob = brillo::BlobFromString(str);
  return true;
}

// Generate ledger signed proof, using the hardcoded data which was generated on
// the server. Can be verified using the dev ledger info.
bool GetDevLedgerSignedProof(LedgerSignedProof* ledger_signed_proof) {
  LoggedRecord logged_record;
  if (!HexStringToBlob(kFakePublicLedgerEntryHex,
                       &logged_record.public_ledger_entry)) {
    LOG(ERROR) << "Failed to convert fake public ledger entry hex to Blob";
    return false;
  }
  if (!HexStringToBlob(kFakePrivateLogEntryHex,
                       &logged_record.private_log_entry)) {
    LOG(ERROR) << "Failed to convert fake private log entry hex to Blob";
    return false;
  }
  logged_record.leaf_index = kFakeLeafIndex;

  if (!HexStringToBlob(kFakeCheckpointNote,
                       &ledger_signed_proof->checkpoint_note)) {
    LOG(ERROR) << "Failed to convert fake checkpoint note hex to Blob";
    return false;
  }
  for (const std::string& hex_string : kFakeInclusionProof) {
    brillo::Blob blob;
    if (!HexStringToBlob(hex_string, &blob)) {
      LOG(ERROR) << "Failed to convert fake inclusion proof hex to Blob";
      return false;
    }
    ledger_signed_proof->inclusion_proof.push_back(blob);
  }

  ledger_signed_proof->logged_record = logged_record;
  return true;
}

LedgerInfo GetDevLedgerInfo() {
  return LedgerInfo{.name = kDevLedgerName,
                    .key_hash = kDevLedgerPublicKeyHash,
                    .public_key = brillo::SecureBlob(kDevLedgerPublicKey)};
}

crypto::ScopedEC_KEY GenerateKeyPair() {
  ScopedBN_CTX context = CreateBigNumContext();
  if (!context.get()) {
    LOG(ERROR) << "Failed to allocate BN_CTX structure";
    return nullptr;
  }
  std::optional<EllipticCurve> ec =
      EllipticCurve::Create(RecoveryCrypto::kCurve, context.get());
  if (!ec) {
    LOG(ERROR) << "Failed to create EllipticCurve";
    return nullptr;
  }
  return ec->GenerateKey(context.get());
}

// Encode the `key` to the DER-encoded X.509 SubjectPublicKeyInfo format, and
// apply base 64 url encoding afterwards.
bool GetLedgerPublicKeyEncoded(const crypto::ScopedEC_KEY& key,
                               brillo::SecureBlob* result) {
  ScopedBN_CTX context = CreateBigNumContext();
  if (!context.get()) {
    LOG(ERROR) << "Failed to allocate BN_CTX structure";
    return false;
  }
  std::optional<EllipticCurve> ec =
      EllipticCurve::Create(RecoveryCrypto::kCurve, context.get());
  if (!ec) {
    LOG(ERROR) << "Failed to create EllipticCurve";
    return false;
  }
  brillo::SecureBlob spki_der;
  if (!ec->EncodeToSpkiDer(key, &spki_der, context.get())) {
    LOG(ERROR) << "Failed to encode EC_POINT to SubjectPublicKeyInfo";
    return false;
  }
  std::string encoded;
  base::Base64UrlEncode(spki_der.to_string(),
                        base::Base64UrlEncodePolicy::INCLUDE_PADDING, &encoded);
  *result = brillo::SecureBlob(encoded);
  return true;
}

}  // namespace

TEST(InclusionProofTest, SuccessFromGeneratedData) {
  auto generated_ledger_keys = GenerateKeyPair();
  brillo::SecureBlob public_key;
  ASSERT_TRUE(GetLedgerPublicKeyEncoded(generated_ledger_keys, &public_key));
  LedgerInfo info{.name = "fake-ledger-name",
                  .key_hash = 1234567890,
                  .public_key = public_key};
  LedgerSignedProof generated_proof;
  ASSERT_TRUE(GenerateFakeLedgerSignedProofForTesting(
      {generated_ledger_keys.get()}, info, &generated_proof));
  EXPECT_TRUE(VerifyInclusionProof(generated_proof, info));
}

TEST(InclusionProofTest, FailedWithWrongSignature) {
  auto generated_ledger_keys = GenerateKeyPair();
  brillo::SecureBlob public_key;
  ASSERT_TRUE(GetLedgerPublicKeyEncoded(generated_ledger_keys, &public_key));
  LedgerInfo info{.name = "fake-ledger-name",
                  .key_hash = 1234567890,
                  .public_key = public_key};
  LedgerSignedProof generated_proof;
  ASSERT_TRUE(GenerateFakeLedgerSignedProofForTesting(
      {generated_ledger_keys.get()}, info, &generated_proof));
  EXPECT_FALSE(VerifyInclusionProof(
      generated_proof, LedgerInfo{.name = "different-fake-ledger-name",
                                  .key_hash = info.key_hash,
                                  .public_key = info.public_key}));

  EXPECT_FALSE(VerifyInclusionProof(generated_proof,
                                    LedgerInfo{.name = info.name,
                                               .key_hash = 9876543210,
                                               .public_key = info.public_key}));

  auto different_generated_ledger_keys = GenerateKeyPair();
  brillo::SecureBlob different_public_key;
  ASSERT_TRUE(GetLedgerPublicKeyEncoded(different_generated_ledger_keys,
                                        &different_public_key));
  EXPECT_FALSE(VerifyInclusionProof(
      generated_proof, LedgerInfo{.name = info.name,
                                  .key_hash = info.key_hash,
                                  .public_key = different_public_key}));
}

// Can successfully verify inclusion proof if it's signed with multiple keys.
TEST(InclusionProofTest, SuccessWithMultipleSignatures) {
  auto old_generated_ledger_keys = GenerateKeyPair();
  brillo::SecureBlob old_public_key;
  ASSERT_TRUE(
      GetLedgerPublicKeyEncoded(old_generated_ledger_keys, &old_public_key));

  auto new_generated_ledger_keys = GenerateKeyPair();
  brillo::SecureBlob new_public_key;
  ASSERT_TRUE(
      GetLedgerPublicKeyEncoded(new_generated_ledger_keys, &new_public_key));

  LedgerInfo info{.name = "fake-ledger-name",
                  .key_hash = 1234567890,
                  .public_key = new_public_key};
  // Not verifiable signature followed by verifiable signature.
  {
    LedgerSignedProof generated_proof;
    ASSERT_TRUE(GenerateFakeLedgerSignedProofForTesting(
        {old_generated_ledger_keys.get(), new_generated_ledger_keys.get()},
        info, &generated_proof));
    EXPECT_TRUE(VerifyInclusionProof(generated_proof, info));
  }
  // Verifiable signature followed by not verifiable signature.
  {
    LedgerSignedProof generated_proof;
    ASSERT_TRUE(GenerateFakeLedgerSignedProofForTesting(
        {new_generated_ledger_keys.get(), old_generated_ledger_keys.get()},
        info, &generated_proof));
    EXPECT_TRUE(VerifyInclusionProof(generated_proof, info));
  }
}

TEST(InclusionProofTest, SuccessFromHardcodedData) {
  LedgerSignedProof proof;
  ASSERT_TRUE(GetDevLedgerSignedProof(&proof));
  EXPECT_TRUE(VerifyInclusionProof(proof, GetDevLedgerInfo()));
}

}  // namespace cryptorecovery
}  // namespace cryptohome

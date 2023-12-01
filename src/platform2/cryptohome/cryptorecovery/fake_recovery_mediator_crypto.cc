// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/cryptorecovery/fake_recovery_mediator_crypto.h"

#include <algorithm>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/logging.h>
#include <base/memory/ptr_util.h>
#include <base/stl_util.h>
#include <brillo/secure_blob.h>
#include <libhwsec-foundation/crypto/aes.h>
#include <libhwsec-foundation/crypto/big_num_util.h>
#include <libhwsec-foundation/crypto/ecdh_hkdf.h>
#include <libhwsec-foundation/crypto/elliptic_curve.h>
#include <libhwsec-foundation/crypto/error_util.h>
#include <libhwsec-foundation/crypto/rsa.h>
#include <libhwsec-foundation/crypto/secure_blob_util.h>

#include "cryptohome/cryptohome_common.h"
#include "cryptohome/cryptorecovery/recovery_crypto.h"
#include "cryptohome/cryptorecovery/recovery_crypto_hsm_cbor_serialization.h"
#include "cryptohome/cryptorecovery/recovery_crypto_util.h"

using ::hwsec_foundation::AesGcmDecrypt;
using ::hwsec_foundation::AesGcmEncrypt;
using ::hwsec_foundation::CreateBigNumContext;
using ::hwsec_foundation::CreateSecureRandomBlob;
using ::hwsec_foundation::EllipticCurve;
using ::hwsec_foundation::GenerateEcdhHkdfSymmetricKey;
using ::hwsec_foundation::kAesGcm256KeySize;
using ::hwsec_foundation::ScopedBN_CTX;
using ::hwsec_foundation::SecureBlobToBigNum;
using ::hwsec_foundation::VerifyRsaSignatureSha256;

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

static const char kFakePublicLedgerEntryHex[] =
    "A46E6C6F675F656E7472795F686173685820CC1CAB36511F9D6BFFB6456F69C1711021F8CC"
    "BB57D6699496A1FFCF634B1AFD707075626C69635F74696D657374616D701A6302C7006B72"
    "65636F766572795F6964784035306161633730663632343064343031333266366335336233"
    "66643036373533326336323331336537626162316136323531656261363964643432386266"
    "35356E736368656D615F76657273696F6E01";
static const char kFakePrivateLogEntryHex[] =
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
static const char kFakeCheckpointNote[] =
    "4368726F6D654F535265636F766572794C65646765723A300A35353232390A4E5666354534"
    "7A784673415053346C4345387830636253576C7A41624E5131466A66784F33725861336F51"
    "3D0A0AE28094204368726F6D654F534C65646765724F776E657250726F746F74797065206C"
    "676F374D444245416941454C6269427164463049477A375175322B43597A42317443595131"
    "7531372B4E4242327A34507652596967496747562B574A4A5A5749386E674F594855326366"
    "536B4A7A6A68596E653644684266617A4C52414A535363493D0A";
static const std::vector<std::string> kFakeInclusionProof = {
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

brillo::SecureBlob GetMediatorShareHkdfInfo() {
  return brillo::SecureBlob(RecoveryCrypto::kMediatorShareHkdfInfoValue);
}

brillo::SecureBlob GetRequestPayloadPlainTextHkdfInfo() {
  return brillo::SecureBlob(
      RecoveryCrypto::kRequestPayloadPlainTextHkdfInfoValue);
}

brillo::SecureBlob GetResponsePayloadPlainTextHkdfInfo() {
  return brillo::SecureBlob(
      RecoveryCrypto::kResponsePayloadPlainTextHkdfInfoValue);
}

bool GetRecoveryRequestFromProto(
    const CryptoRecoveryRpcRequest& recovery_request_proto,
    RecoveryRequest* recovery_request) {
  if (!recovery_request_proto.has_cbor_cryptorecoveryrequest()) {
    LOG(ERROR)
        << "No cbor_cryptorecoveryrequest field in recovery_request_proto";
    return false;
  }
  brillo::SecureBlob recovery_request_cbor(
      recovery_request_proto.cbor_cryptorecoveryrequest().begin(),
      recovery_request_proto.cbor_cryptorecoveryrequest().end());
  if (!DeserializeRecoveryRequestFromCbor(recovery_request_cbor,
                                          recovery_request)) {
    LOG(ERROR) << "Unable to deserialize Recovery Request";
    return false;
  }
  return true;
}

bool GenerateRecoveryRequestProto(
    const ResponsePayload& response,
    CryptoRecoveryRpcResponse* recovery_response) {
  brillo::SecureBlob recovery_response_cbor;
  if (!SerializeResponsePayloadToCbor(response, &recovery_response_cbor)) {
    LOG(ERROR) << "Failed to serialize Recovery Response to cbor";
    return false;
  }
  recovery_response->set_protocol_version(1);
  recovery_response->set_cbor_cryptorecoveryresponse(
      recovery_response_cbor.data(), recovery_response_cbor.size());
  return true;
}

bool HexStringToBlob(const std::string& input, brillo::Blob* output) {
  brillo::SecureBlob secure_blob;
  if (!brillo::SecureBlob::HexStringToSecureBlob(input, &secure_blob)) {
    LOG(ERROR) << "Failed to convert hex to SecureBlob";
    return false;
  }
  std::string str = secure_blob.to_string();
  *output = brillo::Blob(str.begin(), str.end());
  return true;
}

bool CreateFakeLedgerSignedProof(LedgerSignedProof* ledger_signed_proof) {
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
  logged_record.leaf_index = 55228;

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

}  // namespace

// Hardcoded fake mediator and epoch public and private keys. Do not use them in
// production! Keys were generated at random using
// EllipticCurve::GenerateKeysAsSecureBlobs method and converted to hex.
static const char kFakeMediatorPublicKeyHex[] =
    "3059301306072A8648CE3D020106082A8648CE3D030107034200041C66FD08151D1C34EA50"
    "03F7C24557D2E4802535AA4F65EDBE3CD495CFE060387D00D5D25D859B26C5134F1AD00F22"
    "30EAB72A47F46DF23407CF68FB18C509DE";
static const char kFakeMediatorPrivateKeyHex[] =
    "B7A01DA624ECF448D9F7E1B07236EA2930A17C9A31AD60E43E01A8FEA934AB1C";
static const char kFakeEpochPrivateKeyHex[] =
    "2DC064DBE7473CE2E617C689E3D1D71568E1B09EA6CEC5CB4463A66C06F1B535";
static const char kFakeEpochPublicKeyHex[] =
    "3059301306072A8648CE3D020106082A8648CE3D030107034200045D8393CDEF671228CB0D"
    "8454BBB6F2AAA18E05834BB6DBBD05721FC81ED3BED33D08A8EFD44F6786CAE7ADEB8E26A3"
    "55CD9714F59C78F063A3CA3A7D74877A8A";

std::unique_ptr<FakeRecoveryMediatorCrypto>
FakeRecoveryMediatorCrypto::Create() {
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
  return base::WrapUnique(new FakeRecoveryMediatorCrypto(std::move(*ec)));
}

FakeRecoveryMediatorCrypto::FakeRecoveryMediatorCrypto(EllipticCurve ec)
    : ec_(std::move(ec)) {}

// static
LedgerInfo FakeRecoveryMediatorCrypto::GetLedgerInfo() {
  return LedgerInfo{.name = kDevLedgerName,
                    .key_hash = kDevLedgerPublicKeyHash,
                    .public_key = brillo::SecureBlob(kDevLedgerPublicKey)};
}

// static
bool FakeRecoveryMediatorCrypto::GetFakeMediatorPublicKey(
    brillo::SecureBlob* mediator_pub_key) {
  if (!brillo::SecureBlob::HexStringToSecureBlob(kFakeMediatorPublicKeyHex,
                                                 mediator_pub_key)) {
    LOG(ERROR) << "Failed to convert hex to SecureBlob";
    return false;
  }
  return true;
}

// static
bool FakeRecoveryMediatorCrypto::GetFakeMediatorPrivateKey(
    brillo::SecureBlob* mediator_priv_key) {
  if (!brillo::SecureBlob::HexStringToSecureBlob(kFakeMediatorPrivateKeyHex,
                                                 mediator_priv_key)) {
    LOG(ERROR) << "Failed to convert hex to SecureBlob";
    return false;
  }
  return true;
}

// static
bool FakeRecoveryMediatorCrypto::GetFakeEpochPublicKey(
    brillo::SecureBlob* epoch_pub_key) {
  if (!brillo::SecureBlob::HexStringToSecureBlob(kFakeEpochPublicKeyHex,
                                                 epoch_pub_key)) {
    LOG(ERROR) << "Failed to convert hex to SecureBlob";
    return false;
  }
  return true;
}

// static
bool FakeRecoveryMediatorCrypto::GetFakeEpochPrivateKey(
    brillo::SecureBlob* epoch_priv_key) {
  if (!brillo::SecureBlob::HexStringToSecureBlob(kFakeEpochPrivateKeyHex,
                                                 epoch_priv_key)) {
    LOG(ERROR) << "Failed to convert hex to SecureBlob";
    return false;
  }
  return true;
}

// static
bool FakeRecoveryMediatorCrypto::GetFakeEpochResponse(
    CryptoRecoveryEpochResponse* epoch_response) {
  brillo::SecureBlob epoch_pub_key;
  if (!GetFakeEpochPublicKey(&epoch_pub_key)) {
    LOG(ERROR) << "Failed to get fake epoch public key";
    return false;
  }
  brillo::SecureBlob epoch_metadata_cbor;
  cbor::Value::MapValue meta_data_cbor;
  meta_data_cbor.emplace("meta_data_cbor_key", "meta_data_cbor_value");
  if (!SerializeCborForTesting(cbor::Value(meta_data_cbor),
                               &epoch_metadata_cbor)) {
    LOG(ERROR) << "Failed to create epoch_metadata_cbor";
    return false;
  }
  epoch_response->set_protocol_version(1);
  epoch_response->set_epoch_pub_key(epoch_pub_key.data(), epoch_pub_key.size());
  epoch_response->set_epoch_meta_data(epoch_metadata_cbor.data(),
                                      epoch_metadata_cbor.size());
  return true;
}

bool FakeRecoveryMediatorCrypto::DecryptHsmPayloadPlainText(
    const brillo::SecureBlob& mediator_priv_key,
    const HsmPayload& hsm_payload,
    brillo::SecureBlob* plain_text) const {
  ScopedBN_CTX context = CreateBigNumContext();
  if (!context.get()) {
    LOG(ERROR) << "Failed to allocate BN_CTX structure";
    return false;
  }

  brillo::SecureBlob publisher_pub_key_blob;
  if (!GetBytestringValueFromCborMapByKeyForTesting(hsm_payload.associated_data,
                                                    kPublisherPublicKey,
                                                    &publisher_pub_key_blob)) {
    LOG(ERROR) << "Unable to deserialize publisher_pub_key from hsm_payload";
    return false;
  }
  crypto::ScopedBIGNUM mediator_priv_key_bn =
      SecureBlobToBigNum(mediator_priv_key);
  if (!mediator_priv_key_bn) {
    LOG(ERROR) << "Failed to convert mediator_priv_key to BIGNUM";
    return false;
  }
  crypto::ScopedEC_POINT publisher_pub_key =
      ec_.DecodeFromSpkiDer(publisher_pub_key_blob, context.get());
  if (!publisher_pub_key) {
    LOG(ERROR) << "Failed to convert publisher_pub_key_blob to EC_POINT";
    return false;
  }
  crypto::ScopedEC_POINT shared_secret_point = ComputeEcdhSharedSecretPoint(
      ec_, *publisher_pub_key, *mediator_priv_key_bn);
  if (!shared_secret_point) {
    LOG(ERROR) << "Failed to compute shared_secret_point";
    return false;
  }
  brillo::SecureBlob aes_gcm_key;
  if (!GenerateEcdhHkdfSymmetricKey(
          ec_, *shared_secret_point, publisher_pub_key_blob,
          GetMediatorShareHkdfInfo(),
          /*hkdf_salt=*/brillo::SecureBlob(), RecoveryCrypto::kHkdfHash,
          kAesGcm256KeySize, &aes_gcm_key)) {
    LOG(ERROR) << "Failed to generate ECDH+HKDF recipient key for HSM "
                  "plaintext decryption";
    return false;
  }

  if (!AesGcmDecrypt(hsm_payload.cipher_text, hsm_payload.associated_data,
                     hsm_payload.tag, aes_gcm_key, hsm_payload.iv,
                     plain_text)) {
    LOG(ERROR) << "Failed to perform AES-GCM decryption";
    return false;
  }

  return true;
}

bool FakeRecoveryMediatorCrypto::DecryptRequestPayloadPlainText(
    const brillo::SecureBlob& epoch_priv_key,
    const RequestPayload& request_payload,
    brillo::SecureBlob* plain_text) const {
  ScopedBN_CTX context = CreateBigNumContext();
  if (!context.get()) {
    LOG(ERROR) << "Failed to allocate BN_CTX structure";
    return false;
  }

  brillo::SecureBlob salt;
  if (!GetBytestringValueFromCborMapByKeyForTesting(
          request_payload.associated_data, kRequestPayloadSalt, &salt)) {
    LOG(ERROR) << "Unable to deserialize salt from request_payload";
    return false;
  }
  HsmPayload hsm_payload;
  if (!GetHsmPayloadFromRequestAdForTesting(request_payload.associated_data,
                                            &hsm_payload)) {
    LOG(ERROR) << "Unable to deserialize hsm_payload from request_payload";
    return false;
  }
  brillo::SecureBlob channel_pub_key_blob;
  if (!GetBytestringValueFromCborMapByKeyForTesting(hsm_payload.associated_data,
                                                    kChannelPublicKey,
                                                    &channel_pub_key_blob)) {
    LOG(ERROR) << "Unable to deserialize channel_pub_key from "
                  "hsm_payload.associated_data";
    return false;
  }

  crypto::ScopedBIGNUM epoch_priv_key_bn = SecureBlobToBigNum(epoch_priv_key);
  if (!epoch_priv_key_bn) {
    LOG(ERROR) << "Failed to convert epoch_priv_key to BIGNUM";
    return false;
  }
  crypto::ScopedEC_POINT channel_pub_key =
      ec_.DecodeFromSpkiDer(channel_pub_key_blob, context.get());
  if (!channel_pub_key) {
    LOG(ERROR) << "Failed to convert channel_pub_key_blob to EC_POINT";
    return false;
  }
  crypto::ScopedEC_POINT shared_secret_point =
      ComputeEcdhSharedSecretPoint(ec_, *channel_pub_key, *epoch_priv_key_bn);
  if (!shared_secret_point) {
    LOG(ERROR) << "Failed to compute shared_secret_point";
    return false;
  }
  brillo::SecureBlob aes_gcm_key;
  if (!GenerateEcdhHkdfSymmetricKey(
          ec_, *shared_secret_point, channel_pub_key_blob,
          GetRequestPayloadPlainTextHkdfInfo(), salt, RecoveryCrypto::kHkdfHash,
          kAesGcm256KeySize, &aes_gcm_key)) {
    LOG(ERROR) << "Failed to generate ECDH+HKDF recipient key for request "
                  "payload decryption";
    return false;
  }

  if (!AesGcmDecrypt(request_payload.cipher_text,
                     request_payload.associated_data, request_payload.tag,
                     aes_gcm_key, request_payload.iv, plain_text)) {
    LOG(ERROR) << "Failed to perform AES-GCM decryption of request_payload";
    return false;
  }

  return true;
}

bool FakeRecoveryMediatorCrypto::MediateHsmPayload(
    const brillo::SecureBlob& mediator_priv_key,
    const brillo::SecureBlob& epoch_pub_key,
    const brillo::SecureBlob& epoch_priv_key,
    const brillo::SecureBlob& ephemeral_pub_inv_key,
    const HsmPayload& hsm_payload,
    CryptoRecoveryRpcResponse* recovery_response_proto) const {
  ScopedBN_CTX context = CreateBigNumContext();
  if (!context.get()) {
    LOG(ERROR) << "Failed to allocate BN_CTX structure";
    return false;
  }

  brillo::SecureBlob hsm_plain_text_cbor;
  if (!DecryptHsmPayloadPlainText(mediator_priv_key, hsm_payload,
                                  &hsm_plain_text_cbor)) {
    LOG(ERROR) << "Unable to decrypt hsm_plain_text_cbor in hsm_payload";
    return false;
  }

  HsmPlainText hsm_plain_text;
  if (!DeserializeHsmPlainTextFromCbor(hsm_plain_text_cbor, &hsm_plain_text)) {
    LOG(ERROR) << "Unable to deserialize hsm_plain_text_cbor";
    return false;
  }

  crypto::ScopedBIGNUM mediator_share_bn =
      SecureBlobToBigNum(hsm_plain_text.mediator_share);
  if (!mediator_share_bn) {
    LOG(ERROR) << "Failed to convert SecureBlob to BIGNUM";
    return false;
  }
  crypto::ScopedEC_POINT dealer_pub_point =
      ec_.DecodeFromSpkiDer(hsm_plain_text.dealer_pub_key, context.get());
  if (!dealer_pub_point) {
    LOG(ERROR) << "Failed to convert SecureBlob to EC_POINT";
    return false;
  }
  // Performs scalar multiplication of dealer_pub_key and mediator_share.
  brillo::SecureBlob mediator_dh;
  crypto::ScopedEC_POINT mediator_dh_point =
      ec_.Multiply(*dealer_pub_point, *mediator_share_bn, context.get());
  if (!mediator_dh_point) {
    LOG(ERROR) << "Failed to perform scalar multiplication";
    return false;
  }
  // Perform addition of mediator_dh_point and ephemeral_pub_inv_key.
  crypto::ScopedEC_POINT ephemeral_pub_inv_point =
      ec_.DecodeFromSpkiDer(ephemeral_pub_inv_key, context.get());
  if (!ephemeral_pub_inv_point) {
    LOG(ERROR) << "Failed to convert SecureBlob to EC_POINT";
    return false;
  }
  crypto::ScopedEC_POINT mediated_point =
      ec_.Add(*mediator_dh_point, *ephemeral_pub_inv_point, context.get());
  if (!mediated_point) {
    LOG(ERROR) << "Failed to add mediator_dh_point and ephemeral_pub_inv_point";
    return false;
  }
  crypto::ScopedEC_KEY mediated_key = ec_.PointToEccKey(*mediated_point);
  if (!ec_.EncodeToSpkiDer(mediated_key, &mediator_dh, context.get())) {
    LOG(ERROR) << "Failed to encode EC_POINT to SubjectPublicKeyInfo";
    return false;
  }

  brillo::SecureBlob salt =
      CreateSecureRandomBlob(RecoveryCrypto::kHkdfSaltLength);
  ResponsePayload response_payload;
  HsmResponseAssociatedData response_ad;
  response_ad.response_payload_salt = salt;
  if (!CreateFakeLedgerSignedProof(&response_ad.ledger_signed_proof)) {
    LOG(ERROR) << "Unable to create fake ledger signed proof";
    return false;
  }
  if (!SerializeHsmResponseAssociatedDataToCbor(
          response_ad, &response_payload.associated_data)) {
    LOG(ERROR) << "Unable to serialize response payload associated data";
    return false;
  }

  brillo::SecureBlob response_plain_text_cbor;
  HsmResponsePlainText response_plain_text;
  response_plain_text.mediated_point = mediator_dh;
  response_plain_text.dealer_pub_key = hsm_plain_text.dealer_pub_key;
  response_plain_text.key_auth_value = hsm_plain_text.key_auth_value;
  if (!SerializeHsmResponsePlainTextToCbor(response_plain_text,
                                           &response_plain_text_cbor)) {
    LOG(ERROR) << "Unable to serialize response plain text";
    return false;
  }

  brillo::SecureBlob channel_pub_key_blob;
  if (!GetBytestringValueFromCborMapByKeyForTesting(hsm_payload.associated_data,
                                                    kChannelPublicKey,
                                                    &channel_pub_key_blob)) {
    LOG(ERROR) << "Unable to deserialize channel_pub_key from hsm_payload";
    return false;
  }

  crypto::ScopedBIGNUM epoch_priv_key_bn = SecureBlobToBigNum(epoch_priv_key);
  if (!epoch_priv_key_bn) {
    LOG(ERROR) << "Failed to convert epoch_priv_key to BIGNUM";
    return false;
  }
  crypto::ScopedEC_POINT channel_pub_key =
      ec_.DecodeFromSpkiDer(channel_pub_key_blob, context.get());
  if (!channel_pub_key) {
    LOG(ERROR) << "Failed to convert channel_pub_key_blob to EC_POINT";
    return false;
  }
  crypto::ScopedEC_POINT shared_secret_point =
      ComputeEcdhSharedSecretPoint(ec_, *channel_pub_key, *epoch_priv_key_bn);
  if (!shared_secret_point) {
    LOG(ERROR) << "Failed to compute shared_secret_point";
    return false;
  }
  brillo::SecureBlob aes_gcm_key;
  // The static nature of `channel_pub_key` (G*s) and `epoch_pub_key` (G*r)
  // requires the need to utilize a randomized salt value in the HKDF
  // computation.
  if (!GenerateEcdhHkdfSymmetricKey(ec_, *shared_secret_point, epoch_pub_key,
                                    GetResponsePayloadPlainTextHkdfInfo(), salt,
                                    RecoveryCrypto::kHkdfHash,
                                    kAesGcm256KeySize, &aes_gcm_key)) {
    LOG(ERROR)
        << "Failed to generate ECDH+HKDF recipient key for Recovery Request "
           "plaintext encryption";
    return false;
  }

  if (!AesGcmEncrypt(response_plain_text_cbor, response_payload.associated_data,
                     aes_gcm_key, &response_payload.iv, &response_payload.tag,
                     &response_payload.cipher_text)) {
    LOG(ERROR) << "Failed to perform AES-GCM encryption of response_payload";
    return false;
  }

  ResponsePayload recovery_response;
  recovery_response = std::move(response_payload);
  if (!GenerateRecoveryRequestProto(recovery_response,
                                    recovery_response_proto)) {
    LOG(ERROR) << "Failed to generate Recovery Response proto";
    return false;
  }
  return true;
}

bool FakeRecoveryMediatorCrypto::MediateRequestPayload(
    const brillo::SecureBlob& epoch_pub_key,
    const brillo::SecureBlob& epoch_priv_key,
    const brillo::SecureBlob& mediator_priv_key,
    const CryptoRecoveryRpcRequest& recovery_request_proto,
    CryptoRecoveryRpcResponse* recovery_response_proto) const {
  ScopedBN_CTX context = CreateBigNumContext();
  if (!context.get()) {
    LOG(ERROR) << "Failed to allocate BN_CTX structure";
    return false;
  }
  // Parse out the rsa_signature in Recovery Request
  RecoveryRequest recovery_request;
  if (!GetRecoveryRequestFromProto(recovery_request_proto, &recovery_request)) {
    LOG(ERROR) << "Couldn't get recovery request from recovery_request_proto";
    return false;
  }
  // Parse out the rsa_public_key, which is in Hsm Associated Data. Hsm
  // Associated Data is in Hsm Payload, and it is in the Associated Data of
  // Request Payload
  RequestPayload request_payload;
  if (!DeserializeRecoveryRequestPayloadFromCbor(
          recovery_request.request_payload, &request_payload)) {
    LOG(ERROR) << "Failed to deserialize Request payload.";
    return false;
  }
  HsmPayload hsm_payload;
  if (!GetHsmPayloadFromRequestAdForTesting(request_payload.associated_data,
                                            &hsm_payload)) {
    LOG(ERROR) << "Unable to extract hsm_payload from request_payload";
    return false;
  }
  HsmAssociatedData hsm_associated_data;
  if (!DeserializeHsmAssociatedDataFromCbor(hsm_payload.associated_data,
                                            &hsm_associated_data)) {
    LOG(ERROR) << "Unable to deserialize hsm_associated_data_cbor";
    return false;
  }

  // If the recovery request is sent from devices with TPM2.0, no RSA signature
  // is attached to be verified and the public key wrapped in AD1 would be
  // empty.
  if (!hsm_associated_data.rsa_public_key.empty() ||
      !recovery_request.rsa_signature.empty()) {
    // Verify RSA signature with RSA public key and request payload
    if (!VerifyRsaSignatureSha256(recovery_request.request_payload,
                                  recovery_request.rsa_signature,
                                  hsm_associated_data.rsa_public_key)) {
      LOG(ERROR)
          << "Unable to initiate verifying rsa signature in request_payload";
      return false;
    }
  }

  brillo::SecureBlob request_plain_text_cbor;
  if (!DecryptRequestPayloadPlainText(epoch_priv_key, request_payload,
                                      &request_plain_text_cbor)) {
    LOG(ERROR) << "Unable to decrypt plain text in request_payload";
    return false;
  }

  RecoveryRequestPlainText plain_text;
  if (!DeserializeRecoveryRequestPlainTextFromCbor(request_plain_text_cbor,
                                                   &plain_text)) {
    LOG(ERROR)
        << "Unable to deserialize Recovery Request request_plain_text_cbor";
    return false;
  }

  if (!MediateHsmPayload(mediator_priv_key, epoch_pub_key, epoch_priv_key,
                         plain_text.ephemeral_pub_inv_key, hsm_payload,
                         recovery_response_proto)) {
    LOG(ERROR) << "Unable to mediate hsm_payload";
    return false;
  }

  return true;
}

}  // namespace cryptorecovery
}  // namespace cryptohome

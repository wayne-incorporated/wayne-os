// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/cryptorecovery/recovery_crypto_hsm_cbor_serialization.h"

#include <string>
#include <optional>
#include <utility>
#include <vector>

#include <base/logging.h>
#include <brillo/secure_blob.h>
#include <chromeos/cbor/reader.h>
#include <chromeos/cbor/values.h>
#include <chromeos/cbor/writer.h>

#include "cryptohome/cryptorecovery/recovery_crypto_util.h"

namespace cryptohome {
namespace cryptorecovery {

namespace {

bool SerializeCborMap(const cbor::Value::MapValue& cbor_map,
                      brillo::SecureBlob* blob_cbor) {
  std::optional<std::vector<uint8_t>> serialized =
      cbor::Writer::Write(cbor::Value(std::move(cbor_map)));
  if (!serialized) {
    LOG(ERROR) << "Failed to serialize CBOR Map.";
    return false;
  }
  blob_cbor->assign(serialized.value().begin(), serialized.value().end());
  return true;
}

std::optional<cbor::Value> ReadCborMap(const brillo::SecureBlob& map_cbor) {
  cbor::Reader::DecoderError error_code;
  cbor::Reader::Config config;
  config.error_code_out = &error_code;
  config.allow_and_canonicalize_out_of_order_keys = true;
  std::optional<cbor::Value> cbor_response =
      cbor::Reader::Read(map_cbor, config);
  if (!cbor_response) {
    LOG(ERROR) << "Unable to create CBOR reader: "
               << cbor::Reader::ErrorCodeToString(error_code);
    return std::nullopt;
  }
  if (error_code != cbor::Reader::DecoderError::CBOR_NO_ERROR) {
    LOG(ERROR) << "Error when parsing CBOR input: "
               << cbor::Reader::ErrorCodeToString(error_code);
    return std::nullopt;
  }
  if (!cbor_response->is_map()) {
    LOG(ERROR) << "CBOR input is not a map.";
    return std::nullopt;
  }
  return cbor_response;
}

template <typename Alloc>
bool FindBytestringValueInCborMap(const cbor::Value::MapValue& map,
                                  const std::string& key,
                                  std::vector<uint8_t, Alloc>* blob) {
  const auto entry = map.find(cbor::Value(key));
  if (entry == map.end()) {
    LOG(ERROR) << "No `" << key << "` entry in the CBOR map.";
    return false;
  }
  if (!entry->second.is_bytestring()) {
    LOG(ERROR) << "Wrongly formatted `" << key
               << "` entry in the CBOR map (expected bytestring).";
    return false;
  }

  blob->assign(entry->second.GetBytestring().begin(),
               entry->second.GetBytestring().end());
  return true;
}

bool FindStringValueInCborMap(const cbor::Value::MapValue& map,
                              const std::string& key,
                              std::string* result) {
  const auto entry = map.find(cbor::Value(key));
  if (entry == map.end()) {
    LOG(ERROR) << "No `" << key << "` entry in the CBOR map.";
    return false;
  }
  if (!entry->second.is_string()) {
    LOG(ERROR) << "Wrongly formatted `" << key
               << "` entry in the CBOR map (expected string).";
    return false;
  }

  *result = entry->second.GetString();
  return true;
}

cbor::Value::MapValue ConvertAeadPayloadToCborMap(const AeadPayload& payload) {
  cbor::Value::MapValue result;

  result.emplace(kAeadCipherText, payload.cipher_text);
  result.emplace(kAeadAd, payload.associated_data);
  result.emplace(kAeadIv, payload.iv);
  result.emplace(kAeadTag, payload.tag);

  return result;
}

bool ConvertCborMapToAeadPayload(const cbor::Value::MapValue& aead_payload_map,
                                 AeadPayload* aead_payload) {
  brillo::SecureBlob cipher_text;
  if (!FindBytestringValueInCborMap(aead_payload_map, kAeadCipherText,
                                    &cipher_text)) {
    LOG(ERROR) << "Failed to get cipher text from the AEAD CBOR map.";
    return false;
  }

  brillo::SecureBlob associated_data;
  if (!FindBytestringValueInCborMap(aead_payload_map, kAeadAd,
                                    &associated_data)) {
    LOG(ERROR) << "Failed to get associated data from the AEAD CBOR map.";
    return false;
  }

  brillo::SecureBlob iv;
  if (!FindBytestringValueInCborMap(aead_payload_map, kAeadIv, &iv)) {
    LOG(ERROR) << "Failed to get iv from the AEAD CBOR map.";
    return false;
  }

  brillo::SecureBlob tag;
  if (!FindBytestringValueInCborMap(aead_payload_map, kAeadTag, &tag)) {
    LOG(ERROR) << "Failed to get tag from the AEAD CBOR map.";
    return false;
  }

  aead_payload->cipher_text = std::move(cipher_text);
  aead_payload->associated_data = std::move(associated_data);
  aead_payload->iv = std::move(iv);
  aead_payload->tag = std::move(tag);
  return true;
}

bool ConvertCborMapToOnboardingMetadata(
    const cbor::Value::MapValue& metadata_map, OnboardingMetadata* metadata) {
  const auto user_type_entry =
      metadata_map.find(cbor::Value(kCryptohomeUserType));
  if (user_type_entry == metadata_map.end()) {
    LOG(ERROR) << "No " << kCryptohomeUserType << " entry in the CBOR map.";
    return false;
  }
  if (!user_type_entry->second.is_integer()) {
    LOG(ERROR) << "Wrongly formatted " << kCryptohomeUserType
               << " entry in the CBOR map.";
    return false;
  }
  UserType user_type;
  switch (user_type_entry->second.GetInteger()) {
    case static_cast<int>(UserType::kGaiaId):
      user_type = UserType::kGaiaId;
      break;
    default:
      LOG(ERROR) << "User Type is unknown: "
                 << user_type_entry->second.GetInteger();
      user_type = UserType::kUnknown;
      break;
  }

  std::string cryptohome_user;
  if (!FindStringValueInCborMap(metadata_map, kCryptohomeUser,
                                &cryptohome_user)) {
    LOG(ERROR) << "Failed to get cryptohome user from the onboarding metadata "
                  "CBOR map.";
    return false;
  }
  std::string device_user_id;
  if (!FindStringValueInCborMap(metadata_map, kDeviceUserId, &device_user_id)) {
    LOG(ERROR) << "Failed to get device user id from the onboarding metadata "
                  "CBOR map.";
    return false;
  }
  std::string board_name;
  if (!FindStringValueInCborMap(metadata_map, kBoardName, &board_name)) {
    LOG(ERROR)
        << "Failed to get board name from the onboarding metadata CBOR map.";
    return false;
  }
  std::string form_factor;
  if (!FindStringValueInCborMap(metadata_map, kFormFactor, &form_factor)) {
    LOG(ERROR)
        << "Failed to get form factor from the onboarding metadata CBOR map.";
    return false;
  }
  std::string rlz_code;
  if (!FindStringValueInCborMap(metadata_map, kRlzCode, &rlz_code)) {
    LOG(ERROR)
        << "Failed to get rlz code from the onboarding metadata CBOR map.";
    return false;
  }
  std::string recovery_id;
  if (!FindStringValueInCborMap(metadata_map, kRecoveryId, &recovery_id)) {
    LOG(ERROR)
        << "Failed to get recovery id from the onboarding metadata CBOR map.";
    return false;
  }

  metadata->cryptohome_user_type = user_type;
  metadata->cryptohome_user = cryptohome_user;
  metadata->device_user_id = device_user_id;
  metadata->board_name = board_name;
  metadata->form_factor = form_factor;
  metadata->rlz_code = rlz_code;
  metadata->recovery_id = recovery_id;
  return true;
}

cbor::Value::MapValue ConvertRequestMetadataToCborMap(
    const RequestMetadata& metadata) {
  cbor::Value::MapValue auth_claim;
  auth_claim.emplace(kGaiaAccessToken, metadata.auth_claim.gaia_access_token);
  auth_claim.emplace(kGaiaReauthProofToken,
                     metadata.auth_claim.gaia_reauth_proof_token);

  cbor::Value::MapValue request_meta_data;
  request_meta_data.emplace(kSchemaVersion, kRequestMetaDataSchemaVersion);
  request_meta_data.emplace(kAuthClaim, std::move(auth_claim));
  request_meta_data.emplace(kRequestorUser, metadata.requestor_user_id);
  request_meta_data.emplace(kRequestorUserType,
                            static_cast<int>(metadata.requestor_user_id_type));
  return request_meta_data;
}

cbor::Value::MapValue ConvertHsmMetadataToCborMap(
    const HsmMetaData& hsm_meta_data) {
  cbor::Value::MapValue hsm_meta_data_map;

  hsm_meta_data_map.emplace(kSchemaVersion, kHsmMetaDataSchemaVersion);

  return hsm_meta_data_map;
}

std::vector<cbor::Value> ConvertInclusionProofToVectorValue(
    const std::vector<brillo::Blob>& inclusion_proof) {
  std::vector<cbor::Value> result;
  for (const brillo::Blob& element : inclusion_proof) {
    result.push_back(cbor::Value(element));
  }
  return result;
}

cbor::Value::MapValue ConvertLedgerSignedProofToCborMap(
    const LedgerSignedProof& ledger_signed_proof) {
  cbor::Value::MapValue logged_record_map;
  logged_record_map.emplace(kSchemaVersion, kLoggedRecordSchemaVersion);
  logged_record_map.emplace(
      kPublicLedgerEntryProof,
      ledger_signed_proof.logged_record.public_ledger_entry);
  logged_record_map.emplace(
      kPrivateLogEntryProof,
      ledger_signed_proof.logged_record.private_log_entry);
  logged_record_map.emplace(
      kLeafIndex, cbor::Value(ledger_signed_proof.logged_record.leaf_index));

  cbor::Value::MapValue ledger_signed_proof_map;
  ledger_signed_proof_map.emplace(kSchemaVersion, kHsmMetaDataSchemaVersion);
  ledger_signed_proof_map.emplace(kCheckpointNote,
                                  ledger_signed_proof.checkpoint_note);
  ledger_signed_proof_map.emplace(
      kInclusionProof,
      ConvertInclusionProofToVectorValue(ledger_signed_proof.inclusion_proof));
  ledger_signed_proof_map.emplace(kLoggedRecord, std::move(logged_record_map));

  return ledger_signed_proof_map;
}

bool ConvertCborMapToLoggedRecord(
    const cbor::Value::MapValue& logged_record_map,
    LoggedRecord* logged_record) {
  brillo::Blob public_ledger_entry;
  if (!FindBytestringValueInCborMap(logged_record_map, kPublicLedgerEntryProof,
                                    &public_ledger_entry)) {
    LOG(ERROR)
        << "Failed to get public ledger entry from the logged record map.";
    return false;
  }

  brillo::Blob private_log_entry;
  if (!FindBytestringValueInCborMap(logged_record_map, kPrivateLogEntryProof,
                                    &private_log_entry)) {
    LOG(ERROR) << "Failed to get private log entry from the logged record map.";
    return false;
  }

  const auto leaf_index_entry = logged_record_map.find(cbor::Value(kLeafIndex));
  if (leaf_index_entry == logged_record_map.end()) {
    LOG(ERROR) << "No " << kLeafIndex << " entry in the logged record map.";
    return false;
  }
  if (!leaf_index_entry->second.is_integer()) {
    LOG(ERROR) << "Wrongly formatted " << kLeafIndex
               << " entry in the logged record map.";
    return false;
  }

  logged_record->public_ledger_entry = public_ledger_entry;
  logged_record->private_log_entry = private_log_entry;
  logged_record->leaf_index = leaf_index_entry->second.GetInteger();
  return true;
}

bool ConvertCborMapToLedgerSignedProof(
    const cbor::Value::MapValue& ledger_signed_proof_map,
    LedgerSignedProof* ledger_signed_proof) {
  brillo::Blob checkpoint_note;
  if (!FindBytestringValueInCborMap(ledger_signed_proof_map, kCheckpointNote,
                                    &checkpoint_note)) {
    LOG(ERROR) << "Failed to get checkpoint note from the logged record map.";
    return false;
  }

  const auto inclusion_proof_entry =
      ledger_signed_proof_map.find(cbor::Value(kInclusionProof));
  if (inclusion_proof_entry == ledger_signed_proof_map.end()) {
    LOG(ERROR) << "No " << kLeafIndex
               << " entry in the ledger signed proof map.";
    return false;
  }
  if (!inclusion_proof_entry->second.is_array()) {
    LOG(ERROR) << "Wrongly formatted " << kLeafIndex
               << " entry in the ledger signed proof map.";
    return false;
  }
  std::vector<brillo::Blob> inclusion_proof;
  for (const auto& element : inclusion_proof_entry->second.GetArray()) {
    if (!element.is_bytestring()) {
      LOG(ERROR) << "Wrongly formatted element in the inclusion proof entry.";
      return false;
    }
    inclusion_proof.push_back(element.GetBytestring());
  }

  const auto logged_record_entry =
      ledger_signed_proof_map.find(cbor::Value(kLoggedRecord));
  if (logged_record_entry == ledger_signed_proof_map.end()) {
    LOG(ERROR) << "No " << kLoggedRecord
               << " entry in the ledger signed proof map.";
    return false;
  }
  if (!logged_record_entry->second.is_map()) {
    LOG(ERROR) << "Wrongly formatted " << kLoggedRecord
               << " entry in the ledger signed proof map.";
    return false;
  }
  LoggedRecord logged_record;
  if (!ConvertCborMapToLoggedRecord(logged_record_entry->second.GetMap(),
                                    &logged_record)) {
    LOG(ERROR) << "Failed to deserialize logged record from CBOR.";
    return false;
  }

  ledger_signed_proof->checkpoint_note = checkpoint_note;
  ledger_signed_proof->inclusion_proof = inclusion_proof;
  ledger_signed_proof->logged_record = logged_record;
  return true;
}

}  // namespace

// !!! DO NOT MODIFY !!!
// All the consts below are used as keys in the CBOR blog exchanged with the
// server and must be synced with the server/HSM implementation (or the other
// party will not be able to decrypt the data).
const char kSchemaVersion[] = "schema_version";
const char kMediatorShare[] = "mediator_share";
const char kMediatedShare[] = "mediated_share";
const char kKeyAuthValue[] = "key_auth_value";
const char kDealerPublicKey[] = "dealer_pub_key";
const char kPublisherPublicKey[] = "publisher_pub_key";
const char kChannelPublicKey[] = "channel_pub_key";
const char kRsaPublicKey[] = "rsa_pub_key";
const char kOnboardingMetaData[] = "onboarding_meta_data";
const char kHsmAead[] = "hsm_aead";
const char kAeadCipherText[] = "ct";
const char kAeadAd[] = "ad";
const char kAeadIv[] = "iv";
const char kAeadTag[] = "tag";
const char kRequestMetaData[] = "request_meta_data";
const char kRequestAead[] = "req_aead";
const char kRequestRsaSignature[] = "rsa_signature";
const char kEphemeralPublicInvKey[] = "ephemeral_pub_inv_key";
const char kRequestPayloadSalt[] = "request_salt";
const char kResponseHsmMetaData[] = "hsm_meta_data";
const char kResponsePayloadSalt[] = "response_salt";
const char kPublicLedgerEntryProof[] = "public_ledger_entry";
const char kPrivateLogEntryProof[] = "private_log_entry";
const char kLeafIndex[] = "leaf_index";
const char kCheckpointNote[] = "checkpoint_note";
const char kInclusionProof[] = "inclusion_proof";
const char kLoggedRecord[] = "logged_record";
const char kLedgerSignedProof[] = "ledger_signed_proof";
const char kCryptohomeUser[] = "cryptohome_user";
const char kCryptohomeUserType[] = "cryptohome_user_type";
const char kDeviceUserId[] = "device_user_id";
const char kBoardName[] = "board_name";
const char kFormFactor[] = "form_factor";
const char kRlzCode[] = "rlz_code";
const char kRecoveryId[] = "recovery_id";
const char kAuthClaim[] = "auth_claim";
const char kRequestorUser[] = "requestor_user";
const char kRequestorUserType[] = "requestor_user_type";
const char kGaiaAccessToken[] = "gaia_access_token";
const char kGaiaReauthProofToken[] = "gaia_reauth_proof_token";
const char kEpochMetaData[] = "epoch_meta_data";

const int kHsmAssociatedDataSchemaVersion = 1;
const int kOnboardingMetaDataSchemaVersion = 1;
const int kRequestMetaDataSchemaVersion = 1;
const int kHsmMetaDataSchemaVersion = 1;
const int kLoggedRecordSchemaVersion = 1;
const int kLedgerSignedProofSchemaVersion = 1;

bool SerializeRecoveryRequestPayloadToCbor(
    const RequestPayload& request_payload,
    brillo::SecureBlob* request_payload_cbor) {
  cbor::Value::MapValue request_payload_map =
      ConvertAeadPayloadToCborMap(request_payload);

  if (!SerializeCborMap(request_payload_map, request_payload_cbor)) {
    LOG(ERROR) << "Failed to serialize Recovery Request payload to CBOR";
    return false;
  }
  return true;
}

bool SerializeRecoveryRequestToCbor(const RecoveryRequest& request,
                                    brillo::SecureBlob* request_cbor) {
  cbor::Value::MapValue request_map;

  request_map.emplace(kRequestAead, request.request_payload);

  // Attach rsa_signature if a signature is generated
  if (!request.rsa_signature.empty()) {
    request_map.emplace(kRequestRsaSignature, request.rsa_signature);
  }

  if (!SerializeCborMap(request_map, request_cbor)) {
    LOG(ERROR) << "Failed to serialize Recovery Request to CBOR";
    return false;
  }
  return true;
}

cbor::Value::MapValue ConvertOnboardingMetadataToCborMap(
    const OnboardingMetadata& args) {
  cbor::Value::MapValue map;

  map.emplace(kSchemaVersion, kOnboardingMetaDataSchemaVersion);
  map.emplace(kCryptohomeUser, args.cryptohome_user);
  map.emplace(kCryptohomeUserType, static_cast<int>(args.cryptohome_user_type));
  map.emplace(kDeviceUserId, args.device_user_id);
  map.emplace(kBoardName, args.board_name);
  map.emplace(kFormFactor, args.form_factor);
  map.emplace(kRlzCode, args.rlz_code);
  map.emplace(kRecoveryId, args.recovery_id);

  return map;
}

bool SerializeHsmAssociatedDataToCbor(const HsmAssociatedData& args,
                                      brillo::SecureBlob* ad_cbor) {
  cbor::Value::MapValue ad_map;

  ad_map.emplace(kSchemaVersion, kHsmAssociatedDataSchemaVersion);
  ad_map.emplace(kPublisherPublicKey, args.publisher_pub_key);
  ad_map.emplace(kChannelPublicKey, args.channel_pub_key);
  // Attach rsa_public_key if a public key is generated
  if (!args.rsa_public_key.empty()) {
    ad_map.emplace(kRsaPublicKey, args.rsa_public_key);
  }

  ad_map.emplace(kOnboardingMetaData,
                 ConvertOnboardingMetadataToCborMap(args.onboarding_meta_data));

  if (!SerializeCborMap(ad_map, ad_cbor)) {
    LOG(ERROR) << "Failed to serialize HSM Associated Data to CBOR";
    return false;
  }
  return true;
}

bool SerializeRecoveryRequestAssociatedDataToCbor(
    const RecoveryRequestAssociatedData& args,
    brillo::SecureBlob* request_ad_cbor) {
  cbor::Value::MapValue ad_map;

  ad_map.emplace(kHsmAead, ConvertAeadPayloadToCborMap(args.hsm_payload));
  ad_map.emplace(kRequestPayloadSalt, args.request_payload_salt);

  ad_map.emplace(kRequestMetaData,
                 ConvertRequestMetadataToCborMap(args.request_meta_data));
  ad_map.emplace(kEpochMetaData, args.epoch_meta_data.meta_data_cbor.Clone());

  if (!SerializeCborMap(ad_map, request_ad_cbor)) {
    LOG(ERROR)
        << "Failed to serialize Recovery Request Associated Data to CBOR";
    return false;
  }
  return true;
}

bool SerializeHsmResponseAssociatedDataToCbor(
    const HsmResponseAssociatedData& response_ad,
    brillo::SecureBlob* response_ad_cbor) {
  cbor::Value::MapValue ad_map;

  ad_map.emplace(kResponseHsmMetaData,
                 ConvertHsmMetadataToCborMap(response_ad.hsm_meta_data));
  ad_map.emplace(kResponsePayloadSalt, response_ad.response_payload_salt);
  ad_map.emplace(kLedgerSignedProof, ConvertLedgerSignedProofToCborMap(
                                         response_ad.ledger_signed_proof));

  if (!SerializeCborMap(ad_map, response_ad_cbor)) {
    LOG(ERROR) << "Failed to serialize HSM Response Associated Data to CBOR";
    return false;
  }
  return true;
}

bool SerializeHsmPlainTextToCbor(const HsmPlainText& plain_text,
                                 brillo::SecureBlob* plain_text_cbor) {
  cbor::Value::MapValue pt_map;

  pt_map.emplace(kDealerPublicKey, plain_text.dealer_pub_key);
  pt_map.emplace(kMediatorShare, plain_text.mediator_share);
  // Attach key_auth_value only if it's generated
  if (!plain_text.key_auth_value.empty()) {
    pt_map.emplace(kKeyAuthValue, plain_text.key_auth_value);
  }
  if (!SerializeCborMap(pt_map, plain_text_cbor)) {
    LOG(ERROR) << "Failed to serialize HSM plain text to CBOR";
    return false;
  }
  return true;
}

bool SerializeRecoveryRequestPlainTextToCbor(
    const RecoveryRequestPlainText& plain_text,
    brillo::SecureBlob* plain_text_cbor) {
  cbor::Value::MapValue pt_map;

  pt_map.emplace(kEphemeralPublicInvKey, plain_text.ephemeral_pub_inv_key);

  if (!SerializeCborMap(pt_map, plain_text_cbor)) {
    LOG(ERROR) << "Failed to serialize Recovery Request plain text to CBOR";
    return false;
  }
  return true;
}

bool SerializeResponsePayloadToCbor(const ResponsePayload& response,
                                    brillo::SecureBlob* response_cbor) {
  if (!SerializeCborMap(ConvertAeadPayloadToCborMap(response), response_cbor)) {
    LOG(ERROR) << "Failed to serialize Recovery Response to CBOR";
    return false;
  }
  return true;
}

bool SerializeHsmResponsePlainTextToCbor(const HsmResponsePlainText& plain_text,
                                         brillo::SecureBlob* response_cbor) {
  cbor::Value::MapValue pt_map;

  pt_map.emplace(kDealerPublicKey, plain_text.dealer_pub_key);
  pt_map.emplace(kMediatedShare, plain_text.mediated_point);
  pt_map.emplace(kKeyAuthValue, plain_text.key_auth_value);
  if (!SerializeCborMap(pt_map, response_cbor)) {
    LOG(ERROR) << "Failed to serialize HSM responce payload to CBOR";
    return false;
  }
  return true;
}

bool SerializeHsmPayloadToCbor(const HsmPayload& hsm_payload,
                               brillo::SecureBlob* serialized_cbor) {
  cbor::Value::MapValue hsm_payload_map =
      ConvertAeadPayloadToCborMap(hsm_payload);

  if (!SerializeCborMap(hsm_payload_map, serialized_cbor)) {
    LOG(ERROR) << "Failed to serialize HSM payload to CBOR";
    return false;
  }
  return true;
}

bool DeserializeHsmPayloadFromCbor(const brillo::SecureBlob& serialized_cbor,
                                   HsmPayload* hsm_payload) {
  const auto& cbor = ReadCborMap(serialized_cbor);
  if (!cbor) {
    return false;
  }

  if (!ConvertCborMapToAeadPayload(cbor->GetMap(), hsm_payload)) {
    LOG(ERROR) << "Failed to deserialize HSM payload from CBOR.";
    return false;
  }
  return true;
}

bool DeserializeHsmPlainTextFromCbor(
    const brillo::SecureBlob& hsm_plain_text_cbor,
    HsmPlainText* hsm_plain_text) {
  const auto& cbor = ReadCborMap(hsm_plain_text_cbor);
  if (!cbor) {
    return false;
  }

  const cbor::Value::MapValue& response_map = cbor->GetMap();
  brillo::SecureBlob dealer_pub_key;
  if (!FindBytestringValueInCborMap(response_map, kDealerPublicKey,
                                    &dealer_pub_key)) {
    LOG(ERROR) << "Failed to get dealer public key from the HSM response map.";
    return false;
  }
  brillo::SecureBlob mediator_share;
  if (!FindBytestringValueInCborMap(response_map, kMediatorShare,
                                    &mediator_share)) {
    LOG(ERROR) << "Failed to get mediator share from the HSM response map.";
    return false;
  }
  // Parse out key_auth_value if it is attached.
  if (response_map.contains(cbor::Value(kKeyAuthValue))) {
    brillo::SecureBlob key_auth_value;
    if (!FindBytestringValueInCborMap(response_map, kKeyAuthValue,
                                      &key_auth_value)) {
      LOG(ERROR) << "Failed to get key auth value from the HSM response map.";
      return false;
    }
    hsm_plain_text->key_auth_value = std::move(key_auth_value);
  }

  hsm_plain_text->dealer_pub_key = std::move(dealer_pub_key);
  hsm_plain_text->mediator_share = std::move(mediator_share);
  return true;
}

bool DeserializeHsmAssociatedDataFromCbor(
    const brillo::SecureBlob& hsm_associated_data_cbor,
    HsmAssociatedData* hsm_associated_data) {
  const auto& cbor = ReadCborMap(hsm_associated_data_cbor);
  if (!cbor) {
    return false;
  }

  const cbor::Value::MapValue& response_map = cbor->GetMap();

  const auto onboarding_meta_data_entry =
      response_map.find(cbor::Value(kOnboardingMetaData));
  if (onboarding_meta_data_entry == response_map.end()) {
    LOG(ERROR) << "No " << kOnboardingMetaData
               << " entry in the HSM associated data map.";
    return false;
  }
  if (!onboarding_meta_data_entry->second.is_map()) {
    LOG(ERROR) << "Wrongly formatted " << kOnboardingMetaData
               << " entry in the HSM associated data map.";
    return false;
  }
  if (!ConvertCborMapToOnboardingMetadata(
          onboarding_meta_data_entry->second.GetMap(),
          &hsm_associated_data->onboarding_meta_data)) {
    LOG(ERROR) << "Failed to deserialize Onboarding metadata from CBOR.";
    return false;
  }

  brillo::SecureBlob publisher_pub_key;
  if (!FindBytestringValueInCborMap(response_map, kPublisherPublicKey,
                                    &publisher_pub_key)) {
    LOG(ERROR) << "Failed to get publisher public key from the HSM associated "
                  "data map.";
    return false;
  }
  brillo::SecureBlob channel_pub_key;
  if (!FindBytestringValueInCborMap(response_map, kChannelPublicKey,
                                    &channel_pub_key)) {
    LOG(ERROR)
        << "Failed to get Channel public key from the HSM associated data map.";
    return false;
  }

  // Parse out rsa_public_key if it is attached
  const auto rsa_public_key_entry =
      response_map.find(cbor::Value(kRsaPublicKey));
  if (rsa_public_key_entry != response_map.end()) {
    brillo::SecureBlob rsa_public_key;
    if (!FindBytestringValueInCborMap(response_map, kRsaPublicKey,
                                      &rsa_public_key)) {
      LOG(ERROR)
          << "Failed to get RSA public key from the HSM associated data map.";
      return false;
    }
    hsm_associated_data->rsa_public_key = std::move(rsa_public_key);
  }

  hsm_associated_data->publisher_pub_key = std::move(publisher_pub_key);
  hsm_associated_data->channel_pub_key = std::move(channel_pub_key);
  return true;
}

bool DeserializeRecoveryRequestPlainTextFromCbor(
    const brillo::SecureBlob& request_plain_text_cbor,
    RecoveryRequestPlainText* request_plain_text) {
  const auto& cbor = ReadCborMap(request_plain_text_cbor);
  if (!cbor) {
    return false;
  }

  const cbor::Value::MapValue& request_map = cbor->GetMap();
  brillo::SecureBlob ephemeral_pub_inv_key;
  if (!FindBytestringValueInCborMap(request_map, kEphemeralPublicInvKey,
                                    &ephemeral_pub_inv_key)) {
    LOG(ERROR) << "Failed to get ephemeral public inverse key from the "
                  "Recovery Request map.";
    return false;
  }

  request_plain_text->ephemeral_pub_inv_key = std::move(ephemeral_pub_inv_key);
  return true;
}

bool DeserializeRecoveryRequestFromCbor(
    const brillo::SecureBlob& recovery_request_cbor,
    RecoveryRequest* recovery_request) {
  const auto& cbor = ReadCborMap(recovery_request_cbor);
  if (!cbor) {
    return false;
  }

  const cbor::Value::MapValue& cbor_map = cbor->GetMap();
  // Parse out request_payload SecureBlob
  brillo::SecureBlob request_payload;
  if (!FindBytestringValueInCborMap(cbor_map, kRequestAead, &request_payload)) {
    LOG(ERROR) << "Failed to get request payload from Recovery Request map.";
    return false;
  }
  recovery_request->request_payload = std::move(request_payload);

  // Parse out rsa_signature if it is attached
  const auto rsa_signature_entry =
      cbor_map.find(cbor::Value(kRequestRsaSignature));
  if (rsa_signature_entry != cbor_map.end()) {
    brillo::SecureBlob rsa_signature;
    if (!FindBytestringValueInCborMap(cbor_map, kRequestRsaSignature,
                                      &rsa_signature)) {
      LOG(ERROR) << "Failed to get RSA signature from the recovery request.";
      return false;
    }
    recovery_request->rsa_signature = std::move(rsa_signature);
  }
  return true;
}

bool DeserializeRecoveryRequestPayloadFromCbor(
    const brillo::SecureBlob& serialized_cbor,
    RequestPayload* request_payload) {
  const auto& cbor = ReadCborMap(serialized_cbor);
  if (!cbor) {
    return false;
  }

  if (!ConvertCborMapToAeadPayload(cbor->GetMap(), request_payload)) {
    LOG(ERROR) << "Failed to deserialize Recovery Request payload from CBOR.";
    return false;
  }

  return true;
}

bool DeserializeHsmResponsePlainTextFromCbor(
    const brillo::SecureBlob& response_payload_cbor,
    HsmResponsePlainText* response_payload) {
  const auto& cbor = ReadCborMap(response_payload_cbor);
  if (!cbor) {
    return false;
  }

  const cbor::Value::MapValue& response_map = cbor->GetMap();
  brillo::SecureBlob dealer_pub_key;
  if (!FindBytestringValueInCborMap(response_map, kDealerPublicKey,
                                    &dealer_pub_key)) {
    LOG(ERROR) << "Failed to get dealer public key from the HSM response map.";
    return false;
  }
  brillo::SecureBlob mediated_point;
  if (!FindBytestringValueInCborMap(response_map, kMediatedShare,
                                    &mediated_point)) {
    LOG(ERROR) << "Failed to get mediated point from the HSM response map.";
    return false;
  }
  // Key Auth Value is optional.
  brillo::SecureBlob key_auth_value;
  const auto key_auth_value_entry =
      response_map.find(cbor::Value(kKeyAuthValue));
  if (key_auth_value_entry != response_map.end()) {
    if (!key_auth_value_entry->second.is_bytestring()) {
      LOG(ERROR) << "Wrongly formatted `" << kKeyAuthValue
                 << "` entry in the Response plain text CBOR map.";
      return false;
    }

    key_auth_value.assign(key_auth_value_entry->second.GetBytestring().begin(),
                          key_auth_value_entry->second.GetBytestring().end());
  }

  response_payload->dealer_pub_key = std::move(dealer_pub_key);
  response_payload->mediated_point = std::move(mediated_point);
  response_payload->key_auth_value = std::move(key_auth_value);
  return true;
}

bool DeserializeHsmResponseAssociatedDataFromCbor(
    const brillo::SecureBlob& response_ad_cbor,
    HsmResponseAssociatedData* response_ad) {
  const auto& cbor = ReadCborMap(response_ad_cbor);
  if (!cbor) {
    return false;
  }

  const cbor::Value::MapValue& response_map = cbor->GetMap();
  brillo::SecureBlob response_payload_salt;
  if (!FindBytestringValueInCborMap(response_map, kResponsePayloadSalt,
                                    &response_payload_salt)) {
    LOG(ERROR) << "Failed to get response payload salt from the HSM response "
                  "associated data map.";
    return false;
  }

  const auto hsm_meta_data_entry =
      response_map.find(cbor::Value(kResponseHsmMetaData));
  if (hsm_meta_data_entry == response_map.end()) {
    LOG(ERROR) << "No " << kResponseHsmMetaData
               << " entry in the HSM Response associated data map.";
    return false;
  }
  if (!hsm_meta_data_entry->second.is_map()) {
    LOG(ERROR) << "Wrongly formatted " << kResponseHsmMetaData
               << " entry in the HSM Response associated data map.";
    return false;
  }

  const auto ledger_signed_proof_entry =
      response_map.find(cbor::Value(kLedgerSignedProof));
  if (ledger_signed_proof_entry == response_map.end()) {
    LOG(ERROR) << "No " << kLedgerSignedProof
               << " entry in the HSM Response associated data map.";
    return false;
  }
  if (!ledger_signed_proof_entry->second.is_map()) {
    LOG(ERROR) << "Wrongly formatted " << kLedgerSignedProof
               << " entry in the HSM Response associated data map.";
    return false;
  }
  LedgerSignedProof ledger_signed_proof;
  if (!ConvertCborMapToLedgerSignedProof(
          ledger_signed_proof_entry->second.GetMap(), &ledger_signed_proof)) {
    LOG(ERROR) << "Failed to deserialize Response payload from CBOR.";
    return false;
  }

  response_ad->response_payload_salt = std::move(response_payload_salt);
  response_ad->ledger_signed_proof = std::move(ledger_signed_proof);
  return true;
}

bool DeserializeResponsePayloadFromCbor(const brillo::SecureBlob& response_cbor,
                                        ResponsePayload* response) {
  const auto& cbor = ReadCborMap(response_cbor);
  if (!cbor) {
    return false;
  }

  if (!ConvertCborMapToAeadPayload(cbor->GetMap(), response)) {
    LOG(ERROR) << "Failed to deserialize Response payload from CBOR.";
    return false;
  }
  return true;
}

bool DeserializeEpochMetadataFromCbor(
    const brillo::SecureBlob& epoch_metadata_cbor,
    EpochMetadata* epoch_metadata) {
  auto cbor = ReadCborMap(epoch_metadata_cbor);
  if (!cbor) {
    return false;
  }

  epoch_metadata->meta_data_cbor = std::move(cbor.value());
  return true;
}

bool GetValueFromCborMapByKeyForTesting(const brillo::SecureBlob& input_cbor,
                                        const std::string& map_key,
                                        cbor::Value* value) {
  const auto& cbor = ReadCborMap(input_cbor);
  if (!cbor) {
    return false;
  }

  const cbor::Value::MapValue& map = cbor->GetMap();
  const auto entry = map.find(cbor::Value(map_key));
  if (entry == map.end()) {
    LOG(ERROR) << "No `" << map_key << "` entry in the CBOR map.";
    return false;
  }

  *value = entry->second.Clone();
  return true;
}

bool GetBytestringValueFromCborMapByKeyForTesting(
    const brillo::SecureBlob& input_cbor,
    const std::string& map_key,
    brillo::SecureBlob* value) {
  const auto& cbor = ReadCborMap(input_cbor);
  if (!cbor) {
    return false;
  }

  if (!FindBytestringValueInCborMap(cbor->GetMap(), map_key, value)) {
    LOG(ERROR) << "Failed to get keyed entry from cbor map.";
    return false;
  }

  return true;
}

bool GetHsmPayloadFromRequestAdForTesting(
    const brillo::SecureBlob& request_payload_cbor, HsmPayload* hsm_payload) {
  const auto& cbor = ReadCborMap(request_payload_cbor);
  if (!cbor) {
    return false;
  }

  const cbor::Value::MapValue& cbor_map = cbor->GetMap();
  const auto hsm_payload_entry = cbor_map.find(cbor::Value(kHsmAead));
  if (hsm_payload_entry == cbor_map.end()) {
    LOG(ERROR) << "No HSM payload entry in the Request cbor map.";
    return false;
  }
  if (!hsm_payload_entry->second.is_map()) {
    LOG(ERROR)
        << "HSM payload entry in the Request cbor map has a wrong format.";
    return false;
  }

  const cbor::Value::MapValue& hsm_map = hsm_payload_entry->second.GetMap();

  brillo::SecureBlob cipher_text;
  if (!FindBytestringValueInCborMap(hsm_map, kAeadCipherText, &cipher_text)) {
    LOG(ERROR) << "Failed to get cipher text from the HSM payload map.";
    return false;
  }
  brillo::SecureBlob associated_data;
  if (!FindBytestringValueInCborMap(hsm_map, kAeadAd, &associated_data)) {
    LOG(ERROR) << "Failed to get associated data from the HSM payload map.";
    return false;
  }
  brillo::SecureBlob iv;
  if (!FindBytestringValueInCborMap(hsm_map, kAeadIv, &iv)) {
    LOG(ERROR) << "Failed to get iv from the HSM payload map.";
    return false;
  }
  brillo::SecureBlob tag;
  if (!FindBytestringValueInCborMap(hsm_map, kAeadTag, &tag)) {
    LOG(ERROR) << "Failed to get tag from the HSM payload map.";
    return false;
  }

  hsm_payload->cipher_text = std::move(cipher_text);
  hsm_payload->associated_data = std::move(associated_data);
  hsm_payload->iv = std::move(iv);
  hsm_payload->tag = std::move(tag);
  return true;
}

int GetCborMapSize(const brillo::SecureBlob& input_cbor) {
  const auto& cbor = ReadCborMap(input_cbor);
  if (!cbor) {
    return -1;
  }

  return cbor->GetMap().size();
}

bool SerializeCborForTesting(const cbor::Value& cbor,
                             brillo::SecureBlob* serialized_cbor) {
  std::optional<std::vector<uint8_t>> serialized = cbor::Writer::Write(cbor);
  if (!serialized) {
    LOG(ERROR) << "Failed to serialize CBOR Map.";
    return false;
  }

  serialized_cbor->assign(serialized.value().begin(), serialized.value().end());
  return true;
}

}  // namespace cryptorecovery
}  // namespace cryptohome

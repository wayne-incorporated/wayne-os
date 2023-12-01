// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_CRYPTORECOVERY_RECOVERY_CRYPTO_HSM_CBOR_SERIALIZATION_H_
#define CRYPTOHOME_CRYPTORECOVERY_RECOVERY_CRYPTO_HSM_CBOR_SERIALIZATION_H_

#include <string>

#include <brillo/secure_blob.h>
#include <chromeos/cbor/values.h>

#include "cryptohome/cryptorecovery/recovery_crypto_util.h"

namespace cryptohome {
namespace cryptorecovery {

// Constants that will be used as keys in the CBOR map.
extern const char kSchemaVersion[];
extern const char kMediatorShare[];
extern const char kMediatedShare[];
extern const char kKeyAuthValue[];
extern const char kDealerPublicKey[];
extern const char kPublisherPublicKey[];
extern const char kChannelPublicKey[];
extern const char kRsaPublicKey[];
extern const char kOnboardingMetaData[];
extern const char kHsmAead[];
extern const char kAeadCipherText[];
extern const char kAeadAd[];
extern const char kAeadIv[];
extern const char kAeadTag[];
extern const char kEphemeralPublicInvKey[];
extern const char kRequestMetaData[];
extern const char kRequestAead[];
extern const char kRequestRsaSignature[];
extern const char kEpochPublicKey[];
extern const char kRequestPayloadSalt[];
extern const char kResponseHsmMetaData[];
extern const char kResponsePayloadSalt[];
extern const char kPublicLedgerEntryProof[];
extern const char kPrivateLogEntryProof[];
extern const char kLeafIndex[];
extern const char kCheckpointNote[];
extern const char kInclusionProof[];
extern const char kLoggedRecord[];
extern const char kLedgerSignedProof[];
extern const char kCryptohomeUser[];
extern const char kCryptohomeUserType[];
extern const char kDeviceUserId[];
extern const char kBoardName[];
extern const char kFormFactor[];
extern const char kRlzCode[];
extern const char kRecoveryId[];
extern const char kAuthClaim[];
extern const char kRequestorUser[];
extern const char kRequestorUserType[];
extern const char kGaiaAccessToken[];
extern const char kGaiaReauthProofToken[];
extern const char kEpochMetaData[];

// Mediation protocol version.
extern const int kHsmAssociatedDataSchemaVersion;
extern const int kOnboardingMetaDataSchemaVersion;
extern const int kRequestMetaDataSchemaVersion;
extern const int kHsmMetaDataSchemaVersion;
extern const int kLoggedRecordSchemaVersion;
extern const int kLedgerSignedProofSchemaVersion;

// Constructs cbor-encoded binary blob for the Recovery Request payload.
[[nodiscard]] bool SerializeRecoveryRequestPayloadToCbor(
    const RequestPayload& request_payload,
    brillo::SecureBlob* request_payload_cbor);

// Constructs cbor-encoded binary blob for the Recovery Request.
[[nodiscard]] bool SerializeRecoveryRequestToCbor(
    const RecoveryRequest& request, brillo::SecureBlob* request_cbor);

// Constructs cbor-encoded binary blob with HSM associated data.
[[nodiscard]] bool SerializeHsmAssociatedDataToCbor(
    const HsmAssociatedData& ad, brillo::SecureBlob* ad_cbor);

// Constructs cbor-encoded binary blob with associated data for request payload.
[[nodiscard]] bool SerializeRecoveryRequestAssociatedDataToCbor(
    const RecoveryRequestAssociatedData& request_ad,
    brillo::SecureBlob* request_ad_cbor);

// Constructs cbor-encoded binary blob with associated data for response
// payload.
[[nodiscard]] bool SerializeHsmResponseAssociatedDataToCbor(
    const HsmResponseAssociatedData& response_ad,
    brillo::SecureBlob* response_ad_cbor);

// Constructs cbor-encoded binary blob from plain text of data that will
// be subsequently encrypted and in HSM payload.
[[nodiscard]] bool SerializeHsmPlainTextToCbor(
    const HsmPlainText& plain_text, brillo::SecureBlob* plain_text_cbor);

// Constructs cbor-encoded binary blob from plain text of data that will
// be subsequently encrypted and in Request payload.
[[nodiscard]] bool SerializeRecoveryRequestPlainTextToCbor(
    const RecoveryRequestPlainText& plain_text,
    brillo::SecureBlob* plain_text_cbor);

// Constructs cbor-encoded binary blob for the Recovery Response.
[[nodiscard]] bool SerializeResponsePayloadToCbor(
    const ResponsePayload& response, brillo::SecureBlob* response_cbor);

// Constructs cbor-encoded binary blob from plain text of data that will
// be subsequently encrypted and in response payload.
[[nodiscard]] bool SerializeHsmResponsePlainTextToCbor(
    const HsmResponsePlainText& plain_text,
    brillo::SecureBlob* plain_text_cbor);

// Constructs cbor-encoded binary blob from HsmPayload to be saved on the
// device.
[[nodiscard]] bool SerializeHsmPayloadToCbor(
    const HsmPayload& hsm_payload, brillo::SecureBlob* serialized_cbor);

// Extracts data from HSM payload cbor.
[[nodiscard]] bool DeserializeHsmPayloadFromCbor(
    const brillo::SecureBlob& serialized_cbor, HsmPayload* hsm_payload);

// Extracts data from HSM plain text cbor.
[[nodiscard]] bool DeserializeHsmPlainTextFromCbor(
    const brillo::SecureBlob& hsm_plain_text_cbor,
    HsmPlainText* hsm_plain_text);

// Extracts data from HSM associated data cbor.
[[nodiscard]] bool DeserializeHsmAssociatedDataFromCbor(
    const brillo::SecureBlob& hsm_associated_data_cbor,
    HsmAssociatedData* hsm_associated_data);

// Extracts data from Recovery Request plain text cbor.
[[nodiscard]] bool DeserializeRecoveryRequestPlainTextFromCbor(
    const brillo::SecureBlob& request_plain_text_cbor,
    RecoveryRequestPlainText* request_plain_text);

// Extracts data from Recovery Request cbor.
[[nodiscard]] bool DeserializeRecoveryRequestFromCbor(
    const brillo::SecureBlob& recovery_request_cbor,
    RecoveryRequest* recovery_request);

// Extracts data from Recovery Request payload cbor.
[[nodiscard]] bool DeserializeRecoveryRequestPayloadFromCbor(
    const brillo::SecureBlob& serialized_cbor, RequestPayload* request_payload);

// Extracts data from response plain text cbor.
[[nodiscard]] bool DeserializeHsmResponsePlainTextFromCbor(
    const brillo::SecureBlob& response_payload_cbor,
    HsmResponsePlainText* response_payload);

// Extracts data from HSM Response associated data cbor.
[[nodiscard]] bool DeserializeHsmResponseAssociatedDataFromCbor(
    const brillo::SecureBlob& response_ad_cbor,
    HsmResponseAssociatedData* response_ad);

// Extracts data from Recovery Response cbor.
[[nodiscard]] bool DeserializeResponsePayloadFromCbor(
    const brillo::SecureBlob& response_cbor, ResponsePayload* response);

// Extracts data from Epoch Metadata cbor.
[[nodiscard]] bool DeserializeEpochMetadataFromCbor(
    const brillo::SecureBlob& epoch_metadata_cbor,
    EpochMetadata* epoch_metadata);

//============================================================================
// The methods below are for testing only.
//============================================================================

bool GetValueFromCborMapByKeyForTesting(const brillo::SecureBlob& input_cbor,
                                        const std::string& map_key,
                                        cbor::Value* value);

bool GetBytestringValueFromCborMapByKeyForTesting(
    const brillo::SecureBlob& input_cbor,
    const std::string& map_key,
    brillo::SecureBlob* value);

bool GetHsmPayloadFromRequestAdForTesting(
    const brillo::SecureBlob& request_payload_cbor, HsmPayload* hsm_payload);

// Returns number of values in CBOR map. Returns -1 if provided blob is not a
// CBOR map.
int GetCborMapSize(const brillo::SecureBlob& input_cbor);

// Serialize cbor::Value to SecureBlob.
bool SerializeCborForTesting(const cbor::Value& cbor,
                             brillo::SecureBlob* serialized_cbor);

}  // namespace cryptorecovery
}  // namespace cryptohome

#endif  // CRYPTOHOME_CRYPTORECOVERY_RECOVERY_CRYPTO_HSM_CBOR_SERIALIZATION_H_

// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_FIDO_FIDO_CONSTANTS_H_
#define CRYPTOHOME_FIDO_FIDO_CONSTANTS_H_

#include <stdint.h>

#include <array>
#include <vector>

#include "base/component_export.h"
#include "base/time/time.h"

namespace cryptohome {
namespace fido_device {

// Length of the U2F challenge parameter:
// https://goo.gl/y75WrX#registration-request-message---u2f_register
inline constexpr size_t kU2fChallengeParamLength = 32;

// Length of the U2F application parameter:
// https://goo.gl/y75WrX#registration-request-message---u2f_register
inline constexpr size_t kU2fApplicationParamLength = 32;

// Offset of the length of the U2F registration key handle:
// https://goo.gl/y75WrX#registration-response-message-success
inline constexpr size_t kU2fKeyHandleLengthOffset = 66;

// Offset of the U2F registration key handle:
// https://goo.gl/y75WrX#registration-response-message-success
inline constexpr size_t kU2fKeyHandleOffset = 67;

// Length of the SHA-256 hash of the JSON-serialized client data:
// https://www.w3.org/TR/webauthn/#collectedclientdata-hash-of-the-serialized-client-data
inline constexpr size_t kClientDataHashLength = 32;

// Length of the SHA-256 hash of the RP ID associated with the credential:
// https://www.w3.org/TR/webauthn/#sec-authenticator-data
inline constexpr size_t kRpIdHashLength = 32;

// Max length for the user handle:
// https://www.w3.org/TR/webauthn/#user-handle
inline constexpr size_t kUserHandleMaxLength = 64;

static_assert(kU2fApplicationParamLength == kRpIdHashLength,
              "kU2fApplicationParamLength must be equal to kRpIdHashLength.");

// Length of the flags:
// https://www.w3.org/TR/webauthn/#sec-authenticator-data
inline constexpr size_t kFlagsLength = 1;

// Length of the signature counter, 32-bit unsigned big-endian integer:
// https://www.w3.org/TR/webauthn/#sec-authenticator-data
inline constexpr size_t kSignCounterLength = 4;

// Length of the AAGUID of the authenticator:
// https://www.w3.org/TR/webauthn/#sec-attested-credential-data
inline constexpr size_t kAaguidLength = 16;

// Length of the byte length L of Credential ID, 16-bit unsigned big-endian
// integer: https://www.w3.org/TR/webauthn/#sec-attested-credential-data
inline constexpr size_t kCredentialIdLengthLength = 2;

// Relevant LE Discoverable Mode bits. Reference:
// Bluetooth Core Specification Supplement, Part A, section 1.3
inline constexpr uint8_t kLeLimitedDiscoverableModeBit = 0;
inline constexpr uint8_t kLeGeneralDiscoverableModeBit = 1;

// Fido Service Data Flags as specified in
// https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-client-to-authenticator-protocol-v2.0-id-20180227.html#ble-pairing-authnr-considerations
enum class FidoServiceDataFlags : uint8_t {
  kPairingMode = 0x80,
  kPasskeyEntry = 0x40,
};

enum class CoseAlgorithmIdentifier : int { kCoseEs256 = -7 };

// Enumerates the two types of application parameter values used: the
// "primary" value is the hash of the relying party ID[1] and is always
// provided. The "alternative" value is the hash of a U2F AppID, specified in
// an extension[2], for compatibility with keys that were registered with the
// old API.
//
// [1] https://w3c.github.io/webauthn/#rp-id
// [2] https://w3c.github.io/webauthn/#sctn-appid-extension
enum class ApplicationParameterType {
  kPrimary,
  kAlternative,
};

// String used as Relying Party ID to check for user presence.
inline constexpr char kDummyRpID[] = ".dummy";

// String key values for CTAP request optional parameters and
// AuthenticatorGetInfo response.
extern const char kResidentKeyMapKey[];
extern const char kUserVerificationMapKey[];
extern const char kUserPresenceMapKey[];
extern const char kClientPinMapKey[];
extern const char kPlatformDeviceMapKey[];
extern const char kEntityIdMapKey[];
extern const char kEntityNameMapKey[];
extern const char kDisplayNameMapKey[];
extern const char kIconUrlMapKey[];
extern const char kCredentialTypeMapKey[];
extern const char kCredentialAlgorithmMapKey[];
extern const char kCredentialManagementMapKey[];
extern const char kCredentialManagementPreviewMapKey[];
extern const char kBioEnrollmentMapKey[];
extern const char kBioEnrollmentPreviewMapKey[];
extern const char kUvTokenMapKey[];

// U2F APDU encoding constants, as specified in
// https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html#bib-U2FHeader
inline constexpr size_t kU2fMaxResponseSize = 65536;

// Control byte used for check-only setting. The check-only command is used to
// determine if the provided key handle was originally created by this token
// and whether it was created for the provided application parameter.
inline constexpr uint8_t kP1CheckOnly = 0x07;

// Indicates that an individual attestation certificate is acceptable to
// return with this registration.
inline constexpr uint8_t kP1IndividualAttestation = 0x80;
inline constexpr size_t kMaxKeyHandleLength = 255;

// Maximum wait time before client error outs on device.
extern const base::TimeDelta kDeviceTimeout;

// Wait time before polling device for U2F register/sign operation again when
// device times out waiting for user presence.
extern const base::TimeDelta kU2fRetryDelay;

// String key values for attestation object as a response to MakeCredential
// request.
extern const char kFormatKey[];
extern const char kAttestationStatementKey[];
extern const char kAuthDataKey[];
extern const char kNoneAttestationValue[];

// String representation of public key credential enum.
// https://w3c.github.io/webauthn/#credentialType
// #include "cryptohome/fido/fido_constants.h"

extern const char kPublicKey[];

// Values used to construct/validate handshake messages for Cable handshake
// protocol.
extern const char kCableHandshakeKeyInfo[];
// #include "cryptohome/fido/fido_constants.h"

extern const std::array<uint8_t, 24> kCableDeviceEncryptionKeyInfo;
// #include "cryptohome/fido/fido_constants.h"

extern const char kCableAuthenticatorHelloMessage[];
extern const char kCableClientHelloMessage[];

// TODO(hongjunchoi): Add url to the official spec once it's standardized.
extern const char kCtap2Version[];
extern const char kU2fVersion[];

extern const char kExtensionHmacSecret[];
extern const char kExtensionCredProtect[];

// Maximum number of seconds the browser waits for Bluetooth authenticator to
// send packets that advertises that the device is in pairing mode before
// setting pairing mode to false. The interval time is set to 2 seconds, which
// is equivalent to the maximum Bluetooth error wait interval set by the CTAP
// spec.
// https://fidoalliance.org/specs/fido-v2.0-rd-20170927/fido-client-to-authenticator-protocol-v2.0-rd-20170927.html#BTCORE
// #include "cryptohome/fido/fido_constants.h"

extern const base::TimeDelta kBleDevicePairingModeWaitingInterval;

// CredProtect enumerates the levels of credential protection specified by the
// `credProtect` CTAP2 extension.
enum class CredProtect : uint8_t {
  kUVOrCredIDRequired = 2,
  kUVRequired = 3,
};

}  // namespace fido_device
}  // namespace cryptohome

#endif  // CRYPTOHOME_FIDO_FIDO_CONSTANTS_H_

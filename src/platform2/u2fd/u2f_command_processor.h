// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef U2FD_U2F_COMMAND_PROCESSOR_H_
#define U2FD_U2F_COMMAND_PROCESSOR_H_

#include <optional>
#include <vector>

#include <brillo/dbus/dbus_method_response.h>
#include <brillo/secure_blob.h>

#include "u2fd/webauthn_handler.h"

namespace u2f {

// The public key structure. cbor is the public key encoded in cbor format,
// which is what the WebAuthn protocol expects from the authenticator. However,
// WebAuthn is backward compatible with the U2F protocol, and for U2F
// attestation another public key format is expected, see:
// https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#public-key-representation-formats.
// Thus, it has another field |raw| that is the raw representation of U2F public
// keys. It will be empty if the public key isn't from a U2F authenticator.
struct CredentialPublicKey {
  std::vector<uint8_t> cbor;
  std::vector<uint8_t> raw;
};

// Provides an interface to process U2F commands, including the 3 main commands
// U2fGenerate, U2fSign, and U2fSignCheckOnly we used in WebAuthn. Devices with
// different TPMs have different implementations of these commands.
class U2fCommandProcessor {
 public:
  virtual ~U2fCommandProcessor() = default;

  // Create a new pair of signing key, store key-related data in |credential_id|
  // and the public key in |credential_public_key_*|. |rp_id_hash| must be
  // exactly 32 bytes.
  // |credential_public_key_cbor| is the public key encoded in cbor format. This
  // is what the WebAuthn protocol expects from the authenticator. However,
  // WebAuthn is backward compatible with the U2F protocol, and for U2F
  // attestation another public key format is expected, see:
  // https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#public-key-representation-formats.
  // Thus, we have another output field |credential_public_key_raw| for U2F
  // authenticators to fill public key represented in raw format.
  virtual MakeCredentialResponse::MakeCredentialStatus U2fGenerate(
      const std::vector<uint8_t>& rp_id_hash,
      const brillo::SecureBlob& credential_secret,
      PresenceRequirement presence_requirement,
      bool uv_compatible,
      const brillo::Blob* auth_time_secret_hash,
      std::vector<uint8_t>* credential_id,
      CredentialPublicKey* credential_public_key,
      std::vector<uint8_t>* credential_key_blob) = 0;

  // Check that credential_id is valid, and if so,
  // sign |hash_to_sign| and store the signature in |signature|.
  // |rp_id_hash| must be exactly 32 bytes.
  virtual GetAssertionResponse::GetAssertionStatus U2fSign(
      const std::vector<uint8_t>& rp_id_hash,
      const std::vector<uint8_t>& hash_to_sign,
      const std::vector<uint8_t>& credential_id,
      const brillo::SecureBlob& credential_secret,
      const std::vector<uint8_t>* credential_key_blob,
      PresenceRequirement presence_requirement,
      std::vector<uint8_t>* signature) = 0;

  // Check that credential_id is valid and tied to |rp_id_hash|.
  virtual HasCredentialsResponse::HasCredentialsStatus U2fSignCheckOnly(
      const std::vector<uint8_t>& rp_id_hash,
      const std::vector<uint8_t>& credential_id,
      const brillo::SecureBlob& credential_secret,
      const std::vector<uint8_t>* credential_key_blob) = 0;

  // Sign data using the attestation certificate.
  virtual MakeCredentialResponse::MakeCredentialStatus G2fAttest(
      const std::vector<uint8_t>& rp_id_hash,
      const brillo::SecureBlob& credential_secret,
      const std::vector<uint8_t>& challenge,
      const std::vector<uint8_t>& credential_public_key,
      const std::vector<uint8_t>& credential_id,
      std::vector<uint8_t>* cert_out,
      std::vector<uint8_t>* signature_out) = 0;

  // Use a random software key to sign the data.
  virtual bool G2fSoftwareAttest(
      const std::vector<uint8_t>& rp_id_hash,
      const std::vector<uint8_t>& challenge,
      const std::vector<uint8_t>& credential_public_key,
      const std::vector<uint8_t>& credential_id,
      std::vector<uint8_t>* cert_out,
      std::vector<uint8_t>* signature_out) = 0;

  // Return the algorithm type of the key pair U2fGenerate generates.
  virtual CoseAlgorithmIdentifier GetAlgorithm() = 0;
};

}  // namespace u2f

#endif  // U2FD_U2F_COMMAND_PROCESSOR_H_

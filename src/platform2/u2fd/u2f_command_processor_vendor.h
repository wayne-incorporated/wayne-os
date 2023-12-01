// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef U2FD_U2F_COMMAND_PROCESSOR_VENDOR_H_
#define U2FD_U2F_COMMAND_PROCESSOR_VENDOR_H_

#include <functional>
#include <memory>
#include <optional>
#include <vector>

#include <base/containers/span.h>
#include <brillo/dbus/dbus_method_response.h>
#include <brillo/secure_blob.h>
#include <libhwsec/frontend/u2fd/vendor_frontend.h>
#include <u2f/proto_bindings/u2f_interface.pb.h>

#include "u2fd/client/user_state.h"
#include "u2fd/u2f_command_processor.h"
#include "u2fd/webauthn_handler.h"

namespace u2f {

class U2fCommandProcessorVendor : public U2fCommandProcessor {
 public:
  // |u2f_frontend| - libhwsec class to deal with U2f vendor commands.
  // |request_presence| - callback for performing other platform tasks when
  // expecting the user to press the power button.
  U2fCommandProcessorVendor(
      std::unique_ptr<const hwsec::U2fVendorFrontend> u2f_frontend,
      std::function<void()> request_presence);

  U2fCommandProcessorVendor(const U2fCommandProcessorVendor&) = delete;
  U2fCommandProcessorVendor& operator=(const U2fCommandProcessorVendor&) =
      delete;

  ~U2fCommandProcessorVendor() override {}

  // Runs a U2F_GENERATE command to create a new key handle, and stores the key
  // handle in |credential_id| and the public key in |credential_public_key|.
  // The flag in the U2F_GENERATE command is set according to
  // |presence_requirement|.
  MakeCredentialResponse::MakeCredentialStatus U2fGenerate(
      const std::vector<uint8_t>& rp_id_hash,
      const brillo::SecureBlob& credential_secret,
      PresenceRequirement presence_requirement,
      bool uv_compatible,
      const brillo::Blob* auth_time_secret_hash,
      std::vector<uint8_t>* credential_id,
      CredentialPublicKey* credential_public_key,
      std::vector<uint8_t>* credential_key_blob) override;

  // Runs a U2F_SIGN command to check that credential_id is valid, and if so,
  // sign |hash_to_sign| and store the signature in |signature|.
  // The flag in the U2F_SIGN command is set according to
  // |presence_requirement|.
  // |rp_id_hash| must be exactly 32 bytes.
  GetAssertionResponse::GetAssertionStatus U2fSign(
      const std::vector<uint8_t>& rp_id_hash,
      const std::vector<uint8_t>& hash_to_sign,
      const std::vector<uint8_t>& credential_id,
      const brillo::SecureBlob& credential_secret,
      const std::vector<uint8_t>* credential_key_blob,
      PresenceRequirement presence_requirement,
      std::vector<uint8_t>* signature) override;

  // Runs a U2F_SIGN command with "check only" flag to check whether
  // |credential_id| is a key handle owned by this device tied to |rp_id_hash|.
  HasCredentialsResponse::HasCredentialsStatus U2fSignCheckOnly(
      const std::vector<uint8_t>& rp_id_hash,
      const std::vector<uint8_t>& credential_id,
      const brillo::SecureBlob& credential_secret,
      const std::vector<uint8_t>* credential_key_blob) override;

  // Run a U2F_ATTEST command to sign data using the cr50 individual attestation
  // certificate.
  MakeCredentialResponse::MakeCredentialStatus G2fAttest(
      const std::vector<uint8_t>& rp_id_hash,
      const brillo::SecureBlob& credential_secret,
      const std::vector<uint8_t>& challenge,
      const std::vector<uint8_t>& credential_public_key,
      const std::vector<uint8_t>& credential_id,
      std::vector<uint8_t>* cert_out,
      std::vector<uint8_t>* signature_out) override;

  // Use a random software key to sign the data.
  bool G2fSoftwareAttest(const std::vector<uint8_t>& rp_id_hash,
                         const std::vector<uint8_t>& challenge,
                         const std::vector<uint8_t>& credential_public_key,
                         const std::vector<uint8_t>& credential_id,
                         std::vector<uint8_t>* cert_out,
                         std::vector<uint8_t>* signature_out) override;

  CoseAlgorithmIdentifier GetAlgorithm() override;

  hwsec::StatusOr<int> CallAndWaitForPresenceForTest(
      std::function<hwsec::StatusOr<int>()> fn);

 private:
  friend class U2fCommandProcessorVendorTest;

  // Repeatedly sends u2f_generate request to the TPM if there's no presence.
  MakeCredentialResponse::MakeCredentialStatus SendU2fGenerateWaitForPresence(
      bool is_up_only,
      const std::vector<uint8_t>& rp_id_hash,
      const brillo::SecureBlob& credential_secret,
      const std::optional<std::vector<uint8_t>>& auth_time_secret_hash,
      std::vector<uint8_t>* credential_id,
      CredentialPublicKey* credential_public_key);

  // Repeatedly sends u2f_sign request to the TPM if there's no presence.
  GetAssertionResponse::GetAssertionStatus SendU2fSignWaitForPresence(
      bool is_up_only,
      const std::vector<uint8_t>& rp_id_hash,
      const brillo::SecureBlob& credential_secret,
      const std::optional<brillo::SecureBlob>& auth_time_secret,
      const std::vector<uint8_t>& hash_to_sign,
      const std::vector<uint8_t>& key_handle,
      std::vector<uint8_t>* signature);

  // Prompts the user for presence through |request_presence_| and calls |fn|
  // repeatedly until success or timeout.
  template <typename T, typename F>
  hwsec::StatusOr<T> CallAndWaitForPresence(F fn);

  static std::vector<uint8_t> EncodeCredentialPublicKeyInCBOR(
      base::span<const uint8_t> x, base::span<const uint8_t> y);

  std::optional<std::vector<uint8_t>> GetG2fCert();

  hwsec::StatusOr<hwsec::u2f::Config> GetConfig();

  std::optional<hwsec::u2f::Config> config_ = std::nullopt;
  std::unique_ptr<const hwsec::U2fVendorFrontend> u2f_frontend_;
  std::function<void()> request_presence_;
};

}  // namespace u2f

#endif  // U2FD_U2F_COMMAND_PROCESSOR_VENDOR_H_

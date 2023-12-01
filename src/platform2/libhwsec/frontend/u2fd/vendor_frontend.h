// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FRONTEND_U2FD_VENDOR_FRONTEND_H_
#define LIBHWSEC_FRONTEND_U2FD_VENDOR_FRONTEND_H_

#include <brillo/secure_blob.h>

#include "libhwsec/backend/u2f.h"
#include "libhwsec/backend/vendor.h"
#include "libhwsec/frontend/frontend.h"
#include "libhwsec/status.h"
#include "libhwsec/structures/u2f.h"

namespace hwsec {

class U2fVendorFrontend : public Frontend {
 public:
  using RwVersion = Vendor::RwVersion;

  ~U2fVendorFrontend() override = default;

  // Is the U2F commands enabled or not.
  virtual StatusOr<bool> IsEnabled() const = 0;

  // Generates a user-presence-only U2F credential.
  //
  // A user-presence-only U2F credential can't be used to prove user
  // verification during signing.
  //
  // |app_id| is the identifier of the relying party requesting the credential
  //     generation, which is often the domain name or its hash.
  // |user_secret| is a secret provided from userland to the TPM, to separate
  //     access to credentials of different users on the same device.
  // |consume| is whether user presence should be consumed (usually meaning
  //     the power button touch state is reset) after processing this command.
  // |up_required| is whether user presence is required (usually meaning the
  //     the power button is touched recently) to process this command.
  //
  // On success, returns the GenerateResult which contains the key handle and
  // public key of the generated credential.
  virtual StatusOr<u2f::GenerateResult> GenerateUserPresenceOnly(
      const brillo::Blob& app_id,
      const brillo::SecureBlob& user_secret,
      u2f::ConsumeMode consume_mode,
      u2f::UserPresenceMode up_mode) const = 0;

  // Generates a U2F credential.
  //
  // A U2F credential can be used to prove either user presence or user
  // verification during signing based on the caller's request.
  //
  // |app_id| is the identifier of the relying party requesting the credential
  //     generation, which is often the domain name or its hash.
  // |user_secret| is a secret provided from userland to the TPM, to separate
  //     access to credentials of different users on the same device.
  // |consume| is whether user presence should be consumed (usually meaning
  //     the power button touch state is reset) after processing this command.
  // |up_required| is whether user presence is required (usually meaning the
  //     the power button is touched recently) to process this command.
  // |auth_time_secret_hash| is a hash used for checking user verification
  //     during signing time.
  //
  // On success, returns the GenerateResult which contains the key handle and
  // public key of the generated credential.
  virtual StatusOr<u2f::GenerateResult> Generate(
      const brillo::Blob& app_id,
      const brillo::SecureBlob& user_secret,
      u2f::ConsumeMode consume_mode,
      u2f::UserPresenceMode up_mode,
      const brillo::Blob& auth_time_secret_hash) const = 0;

  // Signs the hash using a user-presence-only U2F credential.
  //
  // A user-presence-only U2F credential can't be used to prove user
  // verification during signing.
  //
  // |app_id| is the identifier of the relying party requesting the credential
  //     generation, which is often the domain name or its hash.
  // |user_secret| is a secret provided from userland to the TPM, to separate
  //     access to credentials of different users on the same device.
  // |hash_to_sign| is the hash to sign.
  // |consume| is whether user presence should be consumed (usually meaning
  //     the power button touch state is reset) after processing this command.
  // |up_required| is whether user presence is required (usually meaning the
  //     the power button is touched recently) to process this command.
  // |key_handle| is the key handle of the credential to sign the hash with.
  //
  // On success, returns the signature.
  virtual StatusOr<u2f::Signature> SignUserPresenceOnly(
      const brillo::Blob& app_id,
      const brillo::SecureBlob& user_secret,
      const brillo::Blob& hash_to_sign,
      u2f::ConsumeMode consume_mode,
      u2f::UserPresenceMode up_mode,
      const brillo::Blob& key_handle) const = 0;

  // Signs the hash using a U2F credential.
  //
  // A U2F credential can be used to prove either user presence or user
  // verification during signing based on the caller's request.
  //
  // |app_id| is the identifier of the relying party requesting the credential
  //     generation, which is often the domain name or its hash.
  // |user_secret| is a secret provided from userland to the TPM, to separate
  //     access to credentials of different users on the same device.
  // |auth_time_secret| is a secret that corresponds to the
  //     |auth_time_secret_hash| passed during credential generation. If
  //     provided the U2F authenticator will verify it, which can be used to
  //     provide user verification authentication.
  // |hash_to_sign| is the hash to sign.
  // |consume| is whether user presence should be consumed (usually meaning
  //     the power button touch state is reset) after processing this command.
  // |up_required| is whether user presence is required (usually meaning the
  //     the power button is touched recently) to process this command.
  // |key_handle| is the key handle of the credential to sign the hash with.
  //
  // On success, returns the signature.
  virtual StatusOr<u2f::Signature> Sign(
      const brillo::Blob& app_id,
      const brillo::SecureBlob& user_secret,
      const std::optional<brillo::SecureBlob>& auth_time_secret,
      const brillo::Blob& hash_to_sign,
      u2f::ConsumeMode consume_mode,
      u2f::UserPresenceMode up_mode,
      const brillo::Blob& key_handle) const = 0;

  // Checks whether a user-presence-only U2F credential is valid.
  //
  // A user-presence-only U2F credential can't be used to prove user
  // verification during signing.
  //
  // |app_id| is the identifier of the relying party requesting the credential
  //     generation, which is often the domain name or its hash.
  // |user_secret| is a secret provided from userland to the TPM, to separate
  //     access to credentials of different users on the same device.
  // |key_handle| is the key handle of the credential to sign the hash with.
  //
  // On success, returns the OK status.
  virtual Status CheckUserPresenceOnly(
      const brillo::Blob& app_id,
      const brillo::SecureBlob& user_secret,
      const brillo::Blob& key_handle) const = 0;

  // Like `CheckUserPresenceOnly`, but checks a normal U2F credential.
  virtual Status Check(const brillo::Blob& app_id,
                       const brillo::SecureBlob& user_secret,
                       const brillo::Blob& key_handle) const = 0;

  // Attests a G2F format message using the TPM's G2F key.
  //
  // |app_id| is the identifier of the relying party requesting the credential
  //     generation, which is often the domain name or its hash.
  // |user_secret| is a secret provided from userland to the TPM, to separate
  //     access to credentials of different users on the same device.
  // |challenge| is the challenge of the attestation message.
  // |key_handle| is the key handle of the credential to attest.
  // |public_key| is the public key of the credential to attest.
  //
  // On success, returns the signature.
  virtual StatusOr<u2f::Signature> G2fAttest(
      const brillo::Blob& app_id,
      const brillo::SecureBlob& user_secret,
      const brillo::Blob& challenge,
      const brillo::Blob& key_handle,
      const brillo::Blob& public_key) const = 0;

  // Gets a G2F format attestation data.
  //
  // This is used for generating the attestation data without asking the U2F
  // authenticator to attest it. This is useful when the caller wants to do a
  // software attestation.
  //
  // |app_id| is the identifier of the relying party requesting the credential
  //     generation, which is often the domain name or its hash.
  // |challenge| is the challenge of the attestation message.
  // |key_handle| is the key handle of the credential to attest.
  // |public_key| is the public key of the credential to attest.
  //
  // On success, returns the attestation data.
  virtual StatusOr<brillo::Blob> GetG2fAttestData(
      const brillo::Blob& app_id,
      const brillo::Blob& challenge,
      const brillo::Blob& key_handle,
      const brillo::Blob& public_key) const = 0;

  // Attests a corp format message using the TPM's G2F key.
  //
  // |app_id| is the identifier of the relying party requesting the credential
  //     generation, which is often the domain name or its hash.
  // |user_secret| is a secret provided from userland to the TPM, to separate
  //     access to credentials of different users on the same device.
  // |challenge| is the challenge of the attestation message.
  // |key_handle| is the key handle of the credential to attest.
  // |public_key| is the public key of the credential to attest.
  // |salt| is the salt of the attestation statement.
  //
  // On success, returns the signature.
  virtual StatusOr<u2f::Signature> CorpAttest(
      const brillo::Blob& app_id,
      const brillo::SecureBlob& user_secret,
      const brillo::Blob& challenge,
      const brillo::Blob& key_handle,
      const brillo::Blob& public_key,
      const brillo::Blob& salt) const = 0;

  virtual StatusOr<brillo::Blob> GetG2fCert() const = 0;

  virtual StatusOr<RwVersion> GetRwVersion() const = 0;

  virtual StatusOr<u2f::Config> GetConfig() const = 0;
};

}  // namespace hwsec

#endif  // LIBHWSEC_FRONTEND_U2FD_VENDOR_FRONTEND_H_

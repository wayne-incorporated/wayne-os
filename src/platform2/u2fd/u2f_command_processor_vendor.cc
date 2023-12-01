// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "u2fd/u2f_command_processor_vendor.h"

#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/containers/span.h>
#include <base/time/time.h>
#include <brillo/dbus/dbus_method_response.h>
#include <brillo/secure_blob.h>
#include <chromeos/cbor/values.h>
#include <chromeos/cbor/writer.h>
#include <libhwsec-foundation/status/status_chain_macros.h>
#include <openssl/sha.h>
#include <u2f/proto_bindings/u2f_interface.pb.h>

#include "u2fd/client/user_state.h"
#include "u2fd/client/util.h"
#include "u2fd/u2f_command_processor.h"
#include "u2fd/webauthn_handler.h"

using hwsec::TPMError;
using hwsec::TPMRetryAction;
using GenerateResult = hwsec::u2f::GenerateResult;
using Signature = hwsec::u2f::Signature;
using ConsumeMode = hwsec::u2f::ConsumeMode;
using UserPresenceMode = hwsec::u2f::UserPresenceMode;

namespace u2f {

namespace {

// COSE key parameters.
// https://tools.ietf.org/html/rfc8152#section-7.1
const int kCoseKeyKtyLabel = 1;
const int kCoseKeyKtyEC2 = 2;
const int kCoseKeyAlgLabel = 3;
const int kCoseKeyAlgES256 = -7;

// Double coordinate curve parameters.
// https://tools.ietf.org/html/rfc8152#section-13.1.1
const int kCoseECKeyCrvLabel = -1;
const int kCoseECKeyXLabel = -2;
const int kCoseECKeyYLabel = -3;

constexpr base::TimeDelta kVerificationTimeout = base::Seconds(10);

}  // namespace

U2fCommandProcessorVendor::U2fCommandProcessorVendor(
    std::unique_ptr<const hwsec::U2fVendorFrontend> u2f_frontend,
    std::function<void()> request_presence)
    : u2f_frontend_(std::move(u2f_frontend)),
      request_presence_(request_presence) {
  CHECK(u2f_frontend_);
}

MakeCredentialResponse::MakeCredentialStatus
U2fCommandProcessorVendor::U2fGenerate(
    const std::vector<uint8_t>& rp_id_hash,
    const brillo::SecureBlob& credential_secret,
    PresenceRequirement presence_requirement,
    bool uv_compatible,
    const brillo::Blob* auth_time_secret_hash,
    std::vector<uint8_t>* credential_id,
    CredentialPublicKey* credential_public_key,
    std::vector<uint8_t>* /*unused*/) {
  if (uv_compatible) {
    if (!auth_time_secret_hash) {
      LOG(ERROR) << "No auth-time secret hash to use for u2f_generate.";
      return MakeCredentialResponse::INTERNAL_ERROR;
    }

    if (presence_requirement != PresenceRequirement::kPowerButton) {
      ASSIGN_OR_RETURN(
          const GenerateResult& result,
          u2f_frontend_->Generate(
              rp_id_hash, credential_secret, ConsumeMode::kNoConsume,
              UserPresenceMode::kNotRequired, *auth_time_secret_hash),
          _.WithStatus<TPMError>("Failed to generate U2F credential")
              .LogError()
              .As(MakeCredentialResponse::INTERNAL_ERROR));
      if (!result.public_key) {
        LOG(ERROR) << "No public key in generate result.";
        return MakeCredentialResponse::INTERNAL_ERROR;
      }

      credential_public_key->raw = result.public_key->raw();
      credential_public_key->cbor = EncodeCredentialPublicKeyInCBOR(
          result.public_key->x(), result.public_key->y());
      *credential_id = std::move(result.key_handle);
      return MakeCredentialResponse::SUCCESS;
    } else {
      return SendU2fGenerateWaitForPresence(
          /*is_up_only=*/false, rp_id_hash, credential_secret,
          *auth_time_secret_hash, credential_id, credential_public_key);
    }
  } else {
    // Non-versioned KH must be signed with power button press.
    if (presence_requirement != PresenceRequirement::kPowerButton)
      return MakeCredentialResponse::INTERNAL_ERROR;
    return SendU2fGenerateWaitForPresence(
        /*is_up_only=*/true, rp_id_hash, credential_secret, std::nullopt,
        credential_id, credential_public_key);
  }
}

GetAssertionResponse::GetAssertionStatus U2fCommandProcessorVendor::U2fSign(
    const std::vector<uint8_t>& rp_id_hash,
    const std::vector<uint8_t>& hash_to_sign,
    const std::vector<uint8_t>& credential_id,
    const brillo::SecureBlob& credential_secret,
    const std::vector<uint8_t>* /*unused*/,
    PresenceRequirement presence_requirement,
    std::vector<uint8_t>* signature) {
  ASSIGN_OR_RETURN(const hwsec::u2f::Config& config, GetConfig(),
                   _.WithStatus<TPMError>("Failed to get U2F config")
                       .LogError()
                       .As(GetAssertionResponse::INTERNAL_ERROR));

  if (credential_id.size() == config.kh_size) {
    if (presence_requirement != PresenceRequirement::kPowerButton) {
      ASSIGN_OR_RETURN(
          const Signature& sig,
          u2f_frontend_->Sign(rp_id_hash, credential_secret,
                              /*auth_time_secret=*/std::nullopt, hash_to_sign,
                              ConsumeMode::kNoConsume,
                              UserPresenceMode::kNotRequired, credential_id),
          _.WithStatus<TPMError>("Failed to sign using U2F credential")
              .LogError()
              .As(GetAssertionResponse::INTERNAL_ERROR));

      std::optional<std::vector<uint8_t>> opt_signature =
          util::SignatureToDerBytes(sig.r, sig.s);
      if (!opt_signature.has_value()) {
        return GetAssertionResponse::INTERNAL_ERROR;
      }
      *signature = *opt_signature;
      return GetAssertionResponse::SUCCESS;
    }

    return SendU2fSignWaitForPresence(
        /*is_up_only=*/false, rp_id_hash, credential_secret,
        /*auth_time_secret=*/std::nullopt, hash_to_sign, credential_id,
        signature);
  } else if (credential_id.size() == config.up_only_kh_size) {
    // Non-versioned KH must be signed with power button press.
    if (presence_requirement != PresenceRequirement::kPowerButton)
      return GetAssertionResponse::INTERNAL_ERROR;

    return SendU2fSignWaitForPresence(
        /*is_up_only=*/true, rp_id_hash, credential_secret,
        /*auth_time_secret=*/std::nullopt, hash_to_sign, credential_id,
        signature);
  } else {
    return GetAssertionResponse::UNKNOWN_CREDENTIAL_ID;
  }
}

HasCredentialsResponse::HasCredentialsStatus
U2fCommandProcessorVendor::U2fSignCheckOnly(
    const std::vector<uint8_t>& rp_id_hash,
    const std::vector<uint8_t>& credential_id,
    const brillo::SecureBlob& credential_secret,
    const std::vector<uint8_t>* /*unused*/) {
  ASSIGN_OR_RETURN(const hwsec::u2f::Config& config, GetConfig(),
                   _.WithStatus<TPMError>("Failed to get U2F config")
                       .LogError()
                       .As(HasCredentialsResponse::INTERNAL_ERROR));

  hwsec::Status sign_status;

  if (credential_id.size() == config.kh_size) {
    sign_status =
        u2f_frontend_->Check(rp_id_hash, credential_secret, credential_id);
  } else if (credential_id.size() == config.up_only_kh_size) {
    sign_status = u2f_frontend_->CheckUserPresenceOnly(
        rp_id_hash, credential_secret, credential_id);
  } else {
    return HasCredentialsResponse::UNKNOWN_CREDENTIAL_ID;
  }

  return sign_status.ok() ? HasCredentialsResponse::SUCCESS
                          : HasCredentialsResponse::UNKNOWN_CREDENTIAL_ID;
}

MakeCredentialResponse::MakeCredentialStatus
U2fCommandProcessorVendor::G2fAttest(
    const std::vector<uint8_t>& rp_id_hash,
    const brillo::SecureBlob& credential_secret,
    const std::vector<uint8_t>& challenge,
    const std::vector<uint8_t>& credential_public_key,
    const std::vector<uint8_t>& credential_id,
    std::vector<uint8_t>* cert_out,
    std::vector<uint8_t>* signature_out) {
  std::optional<std::vector<uint8_t>> cert = GetG2fCert();
  if (!cert.has_value()) {
    return MakeCredentialResponse::INTERNAL_ERROR;
  }

  ASSIGN_OR_RETURN(
      const Signature& signature,
      u2f_frontend_->G2fAttest(rp_id_hash, credential_secret, challenge,
                               credential_id, credential_public_key),
      _.WithStatus<TPMError>("Failed to attest U2F credential")
          .LogError()
          .As(MakeCredentialResponse::INTERNAL_ERROR));

  std::optional<std::vector<uint8_t>> sig_opt =
      util::SignatureToDerBytes(signature.r, signature.s);

  if (!sig_opt.has_value()) {
    LOG(ERROR) << "DER encoding of U2F_ATTEST signature failed.";
    return MakeCredentialResponse::INTERNAL_ERROR;
  }

  *cert_out = std::move(*cert);
  *signature_out = std::move(*sig_opt);

  return MakeCredentialResponse::SUCCESS;
}

bool U2fCommandProcessorVendor::G2fSoftwareAttest(
    const std::vector<uint8_t>& rp_id_hash,
    const std::vector<uint8_t>& challenge,
    const std::vector<uint8_t>& credential_public_key,
    const std::vector<uint8_t>& credential_id,
    std::vector<uint8_t>* cert_out,
    std::vector<uint8_t>* signature_out) {
  ASSIGN_OR_RETURN(
      const brillo::Blob& data,
      u2f_frontend_->GetG2fAttestData(rp_id_hash, challenge, credential_id,
                                      credential_public_key),
      _.WithStatus<TPMError>("Failed to get G2F attest data")
          .LogError()
          .As(false));
  return util::DoSoftwareAttest(data, cert_out, signature_out);
}

CoseAlgorithmIdentifier U2fCommandProcessorVendor::GetAlgorithm() {
  return CoseAlgorithmIdentifier::kEs256;
}

MakeCredentialResponse::MakeCredentialStatus
U2fCommandProcessorVendor::SendU2fGenerateWaitForPresence(
    bool is_up_only,
    const std::vector<uint8_t>& rp_id_hash,
    const brillo::SecureBlob& credential_secret,
    const std::optional<std::vector<uint8_t>>& auth_time_secret_hash,
    std::vector<uint8_t>* credential_id,
    CredentialPublicKey* credential_public_key) {
  if (!is_up_only) {
    DCHECK(auth_time_secret_hash.has_value());
  }

  auto generate_result = CallAndWaitForPresence<GenerateResult>(
      [this, is_up_only, rp_id_hash, credential_secret,
       auth_time_secret_hash]() {
        if (is_up_only) {
          return u2f_frontend_->GenerateUserPresenceOnly(
              rp_id_hash, credential_secret, ConsumeMode::kConsume,
              UserPresenceMode::kRequired);
        }
        return u2f_frontend_->Generate(
            rp_id_hash, credential_secret, ConsumeMode::kConsume,
            UserPresenceMode::kRequired, *auth_time_secret_hash);
      });

  if (!generate_result.ok()) {
    LOG(ERROR) << "U2F_GENERATE failed:" << generate_result.status() << ".";
    // TODO(b/235286980): Return suitable error depending on the generate_result
    // here.
    return MakeCredentialResponse::VERIFICATION_FAILED;
  }
  if (!generate_result->public_key) {
    LOG(ERROR) << "No public key in generate result.";
    return MakeCredentialResponse::INTERNAL_ERROR;
  }

  credential_public_key->raw = generate_result->public_key->raw();
  credential_public_key->cbor = EncodeCredentialPublicKeyInCBOR(
      generate_result->public_key->x(), generate_result->public_key->y());
  *credential_id = std::move(generate_result->key_handle);
  return MakeCredentialResponse::SUCCESS;
}

GetAssertionResponse::GetAssertionStatus
U2fCommandProcessorVendor::SendU2fSignWaitForPresence(
    bool is_up_only,
    const std::vector<uint8_t>& rp_id_hash,
    const brillo::SecureBlob& credential_secret,
    const std::optional<brillo::SecureBlob>& auth_time_secret,
    const std::vector<uint8_t>& hash_to_sign,
    const std::vector<uint8_t>& key_handle,
    std::vector<uint8_t>* signature) {
  auto sign_result = CallAndWaitForPresence<Signature>(
      [this, is_up_only, rp_id_hash, credential_secret, auth_time_secret,
       hash_to_sign, key_handle]() {
        if (is_up_only) {
          return u2f_frontend_->SignUserPresenceOnly(
              rp_id_hash, credential_secret, hash_to_sign,
              ConsumeMode::kConsume, UserPresenceMode::kRequired, key_handle);
        }
        return u2f_frontend_->Sign(
            rp_id_hash, credential_secret, auth_time_secret, hash_to_sign,
            ConsumeMode::kConsume, UserPresenceMode::kRequired, key_handle);
      });

  if (!sign_result.ok()) {
    LOG(ERROR) << "U2F_SIGN failed:" << sign_result.status() << ".";
    // TODO(b/235286980): Return suitable error depending on the sign_result
    // here.
    return GetAssertionResponse::VERIFICATION_FAILED;
  }

  std::optional<std::vector<uint8_t>> opt_signature =
      util::SignatureToDerBytes(sign_result->r, sign_result->s);
  if (!opt_signature.has_value()) {
    LOG(ERROR) << "Failed to parse U2f signature.";
    return GetAssertionResponse::INTERNAL_ERROR;
  }
  *signature = *opt_signature;
  return GetAssertionResponse::SUCCESS;
}

template <typename T, typename F>
hwsec::StatusOr<T> U2fCommandProcessorVendor::CallAndWaitForPresence(F fn) {
  hwsec::StatusOr<T> status = fn();
  base::TimeTicks verification_start = base::TimeTicks::Now();
  while (!status.ok() &&
         status.err_status()->ToTPMRetryAction() ==
             TPMRetryAction::kUserPresence &&
         base::TimeTicks::Now() - verification_start < kVerificationTimeout) {
    // We need user presence. Show a notification requesting it, and try again.
    // We have a delay in request_presence_, so we didn't need to sleep again.
    request_presence_();
    status = fn();
  }
  return status;
}

std::vector<uint8_t> U2fCommandProcessorVendor::EncodeCredentialPublicKeyInCBOR(
    base::span<const uint8_t> x, base::span<const uint8_t> y) {
  cbor::Value::MapValue cbor_map;
  cbor_map[cbor::Value(kCoseKeyKtyLabel)] = cbor::Value(kCoseKeyKtyEC2);
  cbor_map[cbor::Value(kCoseKeyAlgLabel)] = cbor::Value(kCoseKeyAlgES256);
  cbor_map[cbor::Value(kCoseECKeyCrvLabel)] = cbor::Value(1);
  cbor_map[cbor::Value(kCoseECKeyXLabel)] = cbor::Value(x);
  cbor_map[cbor::Value(kCoseECKeyYLabel)] = cbor::Value(y);
  return *cbor::Writer::Write(cbor::Value(std::move(cbor_map)));
}

std::optional<std::vector<uint8_t>> U2fCommandProcessorVendor::GetG2fCert() {
  ASSIGN_OR_RETURN(brillo::Blob cert, u2f_frontend_->GetG2fCert(),
                   _.WithStatus<TPMError>("Failed to get G2F cert")
                       .LogError()
                       .As(std::nullopt));

  if (!util::RemoveCertificatePadding(&cert)) {
    LOG(ERROR) << "Failed to remove padding from G2F certificate ";
    return std::nullopt;
  }

  return cert;
}

hwsec::StatusOr<hwsec::u2f::Config> U2fCommandProcessorVendor::GetConfig() {
  if (config_.has_value()) {
    return *config_;
  }
  ASSIGN_OR_RETURN(config_, u2f_frontend_->GetConfig());
  return *config_;
}

hwsec::StatusOr<int> U2fCommandProcessorVendor::CallAndWaitForPresenceForTest(
    std::function<hwsec::StatusOr<int>()> fn) {
  return CallAndWaitForPresence<int>(fn);
}

}  // namespace u2f

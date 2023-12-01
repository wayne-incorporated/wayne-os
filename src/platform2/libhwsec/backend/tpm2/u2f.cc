// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec/backend/tpm2/u2f.h"

#include <algorithm>
#include <cstdint>
#include <memory>
#include <optional>
#include <utility>

#include <brillo/secure_blob.h>
#include <libhwsec-foundation/status/status_chain_macros.h>
#include <openssl/sha.h>
#include <trunks/cr50_headers/u2f.h>
#include <trunks/tpm_utility.h>

#include "libhwsec/error/tpm2_error.h"
#include "libhwsec/status.h"

using hwsec_foundation::status::MakeStatus;

namespace hwsec {

using u2f::ConsumeMode;
using u2f::GenerateResult;
using u2f::Signature;
using u2f::UserPresenceMode;

namespace {

constexpr u2f::Config kConfigTpm2{
    .up_only_kh_size = U2F_V0_KH_SIZE,
    .kh_size = U2F_V1_KH_SIZE + SHA256_DIGEST_LENGTH,
};

constexpr uint32_t kCr50StatusNotAllowed = 0x507;
constexpr uint32_t kCr50StatusPasswordRequired = 0x50a;

// This two functions are needed for backward compatibility. Key handles
// that were already generated have inserted hash, so we continue to
// insert/remove them.
bool InsertAuthTimeSecretHashToKeyHandle(
    const brillo::Blob& auth_time_secret_hash, brillo::Blob& input) {
  if (input.size() != kConfigTpm2.kh_size - SHA256_DIGEST_LENGTH) {
    return false;
  }
  // The auth time secret hash should be inserted right after the header and
  // the authorization salt, before the authorization hmac.
  input.insert(
      input.cbegin() + offsetof(u2f_versioned_key_handle, authorization_hmac),
      auth_time_secret_hash.cbegin(), auth_time_secret_hash.cend());
  return true;
}

bool RemoveAuthTimeSecretHashFromCredentialId(brillo::Blob& input) {
  if (input.size() != kConfigTpm2.kh_size) {
    return false;
  }
  // The auth time secret hash is after the header and the authorization salt,
  // before the authorization hmac. Remove it so that the U2F authenticator
  // recognizes the key handle.
  const brillo::Blob::const_iterator remove_begin =
      input.cbegin() + offsetof(u2f_versioned_key_handle, authorization_hmac);
  input.erase(remove_begin, remove_begin + SHA256_DIGEST_LENGTH);
  return true;
}

class PublicKeyTpm2 : public u2f::PublicKey {
 public:
  static std::optional<PublicKeyTpm2> from_raw(brillo::Blob raw) {
    if (raw.size() != U2F_EC_POINT_SIZE) {
      return std::nullopt;
    }
    PublicKeyTpm2 ret;
    ret.data_ = std::move(raw);
    return ret;
  }

  base::span<const uint8_t> x() const override {
    return base::make_span(data_.data() + offsetof(u2f_ec_point, x),
                           static_cast<size_t>(U2F_EC_KEY_SIZE));
  }

  base::span<const uint8_t> y() const override {
    return base::make_span(data_.data() + offsetof(u2f_ec_point, y),
                           static_cast<size_t>(U2F_EC_KEY_SIZE));
  }

  const brillo::Blob& raw() const override { return data_; }

 private:
  PublicKeyTpm2() = default;

  brillo::Blob data_;
};

}  // namespace

StatusOr<bool> U2fTpm2::IsEnabled() {
  if (enabled_.has_value()) {
    return *enabled_;
  }

  // TODO(b/257335815): Add Ti50 case here after its tpm_version is separated
  // from Cr50.
  enabled_ = context_.GetTpmUtility().IsGsc();

  return *enabled_;
}

StatusOr<GenerateResult> U2fTpm2::GenerateUserPresenceOnly(
    const brillo::Blob& app_id,
    const brillo::SecureBlob& user_secret,
    ConsumeMode consume_mode,
    UserPresenceMode up_mode) {
  brillo::Blob public_key;
  brillo::Blob key_handle;

  if (auto status = MakeStatus<TPM2Error>(context_.GetTpmUtility().U2fGenerate(
          /*version=*/0, app_id, user_secret,
          consume_mode == ConsumeMode::kConsume,
          up_mode == UserPresenceMode::kRequired,
          /*auth_time_secret_hash=*/std::nullopt, &public_key, &key_handle));
      !status.ok() && status->ErrorCode() == kCr50StatusNotAllowed) {
    return MakeStatus<TPMError>("Failed to generate U2F credential",
                                TPMRetryAction::kUserPresence)
        .Wrap(std::move(status));
  } else if (!status.ok()) {
    return MakeStatus<TPMError>("Failed to generate U2F credential")
        .Wrap(std::move(status));
  }

  auto pub = PublicKeyTpm2::from_raw(std::move(public_key));
  if (!pub.has_value()) {
    return MakeStatus<TPMError>("Invalid public key", TPMRetryAction::kNoRetry);
  }

  return GenerateResult{
      .public_key = std::make_unique<PublicKeyTpm2>(*pub),
      .key_handle = key_handle,
  };
}

StatusOr<GenerateResult> U2fTpm2::Generate(
    const brillo::Blob& app_id,
    const brillo::SecureBlob& user_secret,
    ConsumeMode consume_mode,
    UserPresenceMode up_mode,
    const brillo::Blob& auth_time_secret_hash) {
  brillo::Blob public_key;
  brillo::Blob key_handle;

  if (auto status = MakeStatus<TPM2Error>(context_.GetTpmUtility().U2fGenerate(
          /*version=*/1, app_id, user_secret,
          consume_mode == ConsumeMode::kConsume,
          up_mode == UserPresenceMode::kRequired, auth_time_secret_hash,
          &public_key, &key_handle));
      !status.ok() && status->ErrorCode() == kCr50StatusNotAllowed) {
    return MakeStatus<TPMError>("Failed to generate U2F credential",
                                TPMRetryAction::kUserPresence)
        .Wrap(std::move(status));
  } else if (!status.ok()) {
    return MakeStatus<TPMError>("Failed to generate U2F credential")
        .Wrap(std::move(status));
  }

  if (!InsertAuthTimeSecretHashToKeyHandle(auth_time_secret_hash, key_handle)) {
    return MakeStatus<TPMError>("Invalid U2F key handle is generated",
                                TPMRetryAction::kNoRetry);
  }

  auto pub = PublicKeyTpm2::from_raw(std::move(public_key));
  if (!pub.has_value()) {
    return MakeStatus<TPMError>("Invalid public key", TPMRetryAction::kNoRetry);
  }

  return GenerateResult{
      .public_key = std::make_unique<PublicKeyTpm2>(*pub),
      .key_handle = key_handle,
  };
}

StatusOr<Signature> U2fTpm2::SignUserPresenceOnly(
    const brillo::Blob& app_id,
    const brillo::SecureBlob& user_secret,
    const brillo::Blob& hash_to_sign,
    ConsumeMode consume_mode,
    UserPresenceMode up_mode,
    const brillo::Blob& key_handle) {
  brillo::Blob sig_r;
  brillo::Blob sig_s;

  if (auto status = MakeStatus<TPM2Error>(context_.GetTpmUtility().U2fSign(
          /*version=*/0, app_id, user_secret, /*auth_time_secret=*/std::nullopt,
          hash_to_sign, /*check_only=*/false,
          consume_mode == ConsumeMode::kConsume,
          up_mode == UserPresenceMode::kRequired, key_handle, &sig_r, &sig_s));
      !status.ok() && status->ErrorCode() == kCr50StatusNotAllowed) {
    return MakeStatus<TPMError>("Failed to sign using U2F credential",
                                TPMRetryAction::kUserPresence)
        .Wrap(std::move(status));
  } else if (!status.ok() &&
             status->ErrorCode() == kCr50StatusPasswordRequired) {
    return MakeStatus<TPMError>("Failed to sign using U2F credential",
                                TPMRetryAction::kUserAuth)
        .Wrap(std::move(status));
  } else if (!status.ok()) {
    return MakeStatus<TPMError>("Failed to sign using U2F credential")
        .Wrap(std::move(status));
  }

  return Signature{
      .r = sig_r,
      .s = sig_s,
  };
}

StatusOr<Signature> U2fTpm2::Sign(
    const brillo::Blob& app_id,
    const brillo::SecureBlob& user_secret,
    const std::optional<brillo::SecureBlob>& auth_time_secret,
    const brillo::Blob& hash_to_sign,
    ConsumeMode consume_mode,
    UserPresenceMode up_mode,
    const brillo::Blob& key_handle) {
  brillo::Blob sig_r;
  brillo::Blob sig_s;

  brillo::Blob kh(key_handle);
  if (!RemoveAuthTimeSecretHashFromCredentialId(kh)) {
    return MakeStatus<TPMError>("Invalid U2F key handle",
                                TPMRetryAction::kNoRetry);
  }

  if (auto status = MakeStatus<TPM2Error>(context_.GetTpmUtility().U2fSign(
          /*version=*/1, app_id, user_secret, auth_time_secret, hash_to_sign,
          /*check_only=*/false, consume_mode == ConsumeMode::kConsume,
          up_mode == UserPresenceMode::kRequired, kh, &sig_r, &sig_s));
      !status.ok() && status->ErrorCode() == kCr50StatusNotAllowed) {
    return MakeStatus<TPMError>("Failed to sign using U2F credential",
                                TPMRetryAction::kUserPresence)
        .Wrap(std::move(status));
  } else if (!status.ok() &&
             status->ErrorCode() == kCr50StatusPasswordRequired) {
    return MakeStatus<TPMError>("Failed to sign using U2F credential",
                                TPMRetryAction::kUserAuth)
        .Wrap(std::move(status));
  } else if (!status.ok()) {
    return MakeStatus<TPMError>("Failed to sign using U2F credential")
        .Wrap(std::move(status));
  }

  return Signature{
      .r = sig_r,
      .s = sig_s,
  };
}

Status U2fTpm2::CheckUserPresenceOnly(const brillo::Blob& app_id,
                                      const brillo::SecureBlob& user_secret,
                                      const brillo::Blob& key_handle) {
  return MakeStatus<TPM2Error>(context_.GetTpmUtility().U2fSign(
      /*version=*/0, app_id, user_secret, std::nullopt, std::nullopt,
      /*check_only=*/true, /*consume=*/false,
      /*up_required=*/false, key_handle, /*sig_r=*/nullptr,
      /*sig_s=*/nullptr));
}

Status U2fTpm2::Check(const brillo::Blob& app_id,
                      const brillo::SecureBlob& user_secret,
                      const brillo::Blob& key_handle) {
  brillo::Blob kh(key_handle);
  if (!RemoveAuthTimeSecretHashFromCredentialId(kh)) {
    return MakeStatus<TPMError>("Invalid U2F key handle",
                                TPMRetryAction::kNoRetry);
  }

  return MakeStatus<TPM2Error>(context_.GetTpmUtility().U2fSign(
      /*version=*/1, app_id, user_secret, std::nullopt, std::nullopt,
      /*check_only=*/true, /*consume=*/false,
      /*up_required=*/false, kh, /*sig_r=*/nullptr,
      /*sig_s=*/nullptr));
}

StatusOr<Signature> U2fTpm2::G2fAttest(const brillo::Blob& app_id,
                                       const brillo::SecureBlob& user_secret,
                                       const brillo::Blob& challenge,
                                       const brillo::Blob& key_handle,
                                       const brillo::Blob& public_key) {
  ASSIGN_OR_RETURN(brillo::Blob data,
                   GetG2fAttestData(app_id, challenge, key_handle, public_key));

  if (user_secret.size() != U2F_USER_SECRET_SIZE) {
    return MakeStatus<TPMError>("Invalid parameters", TPMRetryAction::kNoRetry);
  }

  brillo::Blob sig_r;
  brillo::Blob sig_s;

  RETURN_IF_ERROR(
      MakeStatus<TPM2Error>(context_.GetTpmUtility().U2fAttest(
          user_secret, U2F_ATTEST_FORMAT_REG_RESP, data, &sig_r, &sig_s)))
      .WithStatus<TPMError>("Failed to attest U2F credential");

  return Signature{
      .r = sig_r,
      .s = sig_s,
  };
}

StatusOr<brillo::Blob> U2fTpm2::GetG2fAttestData(
    const brillo::Blob& app_id,
    const brillo::Blob& challenge,
    const brillo::Blob& key_handle,
    const brillo::Blob& public_key) {
  if (app_id.size() != U2F_APPID_SIZE || challenge.size() != U2F_CHAL_SIZE ||
      key_handle.size() != U2F_V0_KH_SIZE ||
      public_key.size() != U2F_EC_POINT_SIZE) {
    return MakeStatus<TPMError>("Invalid parameters", TPMRetryAction::kNoRetry);
  }

  g2f_register_msg_v0 msg{};
  msg.reserved = 0;
  std::copy(app_id.begin(), app_id.end(), msg.app_id);
  std::copy(challenge.begin(), challenge.end(), msg.challenge);
  memcpy(&msg.key_handle, key_handle.data(), key_handle.size());
  memcpy(&msg.public_key, public_key.data(), public_key.size());

  brillo::Blob data(sizeof(msg));
  memcpy(data.data(), &msg, sizeof(msg));
  return data;
}

StatusOr<Signature> U2fTpm2::CorpAttest(const brillo::Blob& app_id,
                                        const brillo::SecureBlob& user_secret,
                                        const brillo::Blob& challenge,
                                        const brillo::Blob& key_handle,
                                        const brillo::Blob& public_key,
                                        const brillo::Blob& salt) {
  if (app_id.size() != U2F_APPID_SIZE ||
      user_secret.size() != U2F_USER_SECRET_SIZE ||
      challenge.size() != CORP_CHAL_SIZE ||
      key_handle.size() != U2F_V0_KH_SIZE ||
      public_key.size() != U2F_EC_POINT_SIZE || salt.size() != CORP_SALT_SIZE) {
    return MakeStatus<TPMError>("Invalid parameters", TPMRetryAction::kNoRetry);
  }

  corp_register_msg_v0 msg{};
  auto* data = reinterpret_cast<corp_attest_data*>(&msg.data);

  std::copy(challenge.begin(), challenge.end(), data->challenge);
  memcpy(&data->public_key, public_key.data(), public_key.size());
  std::copy(salt.begin(), salt.end(), data->salt);
  std::copy(app_id.begin(), app_id.end(), msg.app_id);
  memcpy(&msg.key_handle, key_handle.data(), key_handle.size());

  brillo::Blob msg_blob(sizeof(msg));
  memcpy(msg_blob.data(), &msg, sizeof(msg));

  brillo::Blob sig_r;
  brillo::Blob sig_s;

  RETURN_IF_ERROR(
      MakeStatus<TPM2Error>(context_.GetTpmUtility().U2fAttest(
          user_secret, CORP_ATTEST_FORMAT_REG_RESP, msg_blob, &sig_r, &sig_s)))
      .WithStatus<TPMError>("Failed to attest U2F credential");

  return Signature{
      .r = sig_r,
      .s = sig_s,
  };
}

StatusOr<u2f::Config> U2fTpm2::GetConfig() {
  return kConfigTpm2;
}

}  // namespace hwsec

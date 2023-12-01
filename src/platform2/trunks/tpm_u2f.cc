// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "trunks/tpm_u2f.h"

#include <algorithm>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include <brillo/secure_blob.h>

#include "trunks/cr50_headers/u2f.h"
#include "trunks/error_codes.h"

namespace trunks {

TPM_RC Serialize_u2f_generate_t(
    uint8_t version,
    const brillo::Blob& app_id,
    const brillo::SecureBlob& user_secret,
    bool consume,
    bool up_required,
    const std::optional<brillo::Blob>& auth_time_secret_hash,
    std::string* buffer) {
  buffer->clear();

  if (app_id.size() != U2F_APPID_SIZE ||
      user_secret.size() != U2F_USER_SECRET_SIZE) {
    return SAPI_RC_BAD_PARAMETER;
  }

  u2f_generate_req req{};
  std::copy(app_id.begin(), app_id.end(), req.appId);
  std::copy(user_secret.begin(), user_secret.end(), req.userSecret);
  if (consume) {
    req.flags |= G2F_CONSUME;
  }
  if (up_required) {
    req.flags |= U2F_AUTH_FLAG_TUP;
  }

  if (version == 0) {
    if (auth_time_secret_hash.has_value()) {
      return SAPI_RC_BAD_PARAMETER;
    }
  } else if (version == 1) {
    if (!auth_time_secret_hash.has_value() ||
        auth_time_secret_hash->size() != SHA256_DIGEST_SIZE) {
      return SAPI_RC_BAD_PARAMETER;
    }
    req.flags |= U2F_UV_ENABLED_KH;
    std::copy(auth_time_secret_hash->begin(), auth_time_secret_hash->end(),
              req.authTimeSecretHash);
  } else {
    return SAPI_RC_BAD_PARAMETER;
  }

  buffer->resize(sizeof(req));
  memcpy(buffer->data(), &req, sizeof(req));

  return TPM_RC_SUCCESS;
}

TPM_RC
Serialize_u2f_sign_t(uint8_t version,
                     const brillo::Blob& app_id,
                     const brillo::SecureBlob& user_secret,
                     const std::optional<brillo::SecureBlob>& auth_time_secret,
                     const std::optional<brillo::Blob>& hash_to_sign,
                     bool check_only,
                     bool consume,
                     bool up_required,
                     const brillo::Blob& key_handle,
                     std::string* buffer) {
  buffer->clear();

  if (app_id.size() != U2F_APPID_SIZE ||
      user_secret.size() != U2F_USER_SECRET_SIZE) {
    return SAPI_RC_BAD_PARAMETER;
  }

  uint16_t flags = 0;
  if (check_only) {
    if (auth_time_secret.has_value() || hash_to_sign.has_value() || consume ||
        up_required) {
      return SAPI_RC_BAD_PARAMETER;
    }
    flags |= U2F_AUTH_CHECK_ONLY;
  } else {
    if (!hash_to_sign.has_value() || hash_to_sign->size() != U2F_P256_SIZE) {
      return SAPI_RC_BAD_PARAMETER;
    }
    if (version == 0 && auth_time_secret.has_value()) {
      return SAPI_RC_BAD_PARAMETER;
    }
    if (auth_time_secret.has_value() &&
        auth_time_secret->size() != U2F_AUTH_TIME_SECRET_SIZE) {
      return SAPI_RC_BAD_PARAMETER;
    }
  }
  if (consume) {
    flags |= G2F_CONSUME;
  }
  if (up_required) {
    flags |= U2F_AUTH_FLAG_TUP;
  }

  if (version == 0) {
    u2f_sign_req req{};

    if (key_handle.size() != U2F_V0_KH_SIZE) {
      return SAPI_RC_BAD_PARAMETER;
    }
    std::copy(app_id.begin(), app_id.end(), req.appId);
    std::copy(user_secret.begin(), user_secret.end(), req.userSecret);
    memcpy(&req.keyHandle, key_handle.data(), key_handle.size());
    if (hash_to_sign.has_value()) {
      std::copy(hash_to_sign->begin(), hash_to_sign->end(), req.hash);
    }
    req.flags = flags;

    buffer->resize(sizeof(req));
    memcpy(buffer->data(), &req, sizeof(req));
  } else if (version == 1) {
    u2f_sign_versioned_req req{};

    if (key_handle.size() != U2F_V1_KH_SIZE) {
      return SAPI_RC_BAD_PARAMETER;
    }
    std::copy(app_id.begin(), app_id.end(), req.appId);
    std::copy(user_secret.begin(), user_secret.end(), req.userSecret);
    if (auth_time_secret.has_value()) {
      std::copy(auth_time_secret->begin(), auth_time_secret->end(),
                req.authTimeSecret);
    }
    if (hash_to_sign.has_value()) {
      std::copy(hash_to_sign->begin(), hash_to_sign->end(), req.hash);
    }
    req.flags = flags;
    memcpy(&req.keyHandle, key_handle.data(), key_handle.size());

    buffer->resize(sizeof(req));
    memcpy(buffer->data(), &req, sizeof(req));
  } else {
    return SAPI_RC_BAD_PARAMETER;
  }

  return TPM_RC_SUCCESS;
}

TPM_RC Serialize_u2f_attest_t(const brillo::SecureBlob& user_secret,
                              uint8_t format,
                              const brillo::Blob& data,
                              std::string* buffer) {
  buffer->clear();

  if (user_secret.size() != U2F_USER_SECRET_SIZE ||
      data.size() > U2F_MAX_ATTEST_SIZE) {
    return SAPI_RC_BAD_PARAMETER;
  }

  u2f_attest_req req{};
  std::copy(user_secret.begin(), user_secret.end(), req.userSecret);
  req.format = format;
  req.dataLen = data.size();
  std::copy(data.begin(), data.end(), req.data);

  const size_t req_size = offsetof(u2f_attest_req, data) + data.size();
  buffer->resize(req_size);
  memcpy(buffer->data(), &req, req_size);

  return TPM_RC_SUCCESS;
}

TPM_RC Serialize_u2f_g2f_attest_t(const brillo::Blob& app_id,
                                  const brillo::SecureBlob& user_secret,
                                  const brillo::Blob& challenge,
                                  const brillo::Blob& key_handle,
                                  const brillo::Blob& public_key,
                                  std::string* buffer) {
  buffer->clear();

  if (app_id.size() != U2F_APPID_SIZE ||
      user_secret.size() != U2F_USER_SECRET_SIZE ||
      challenge.size() != U2F_CHAL_SIZE ||
      key_handle.size() != U2F_V0_KH_SIZE ||
      public_key.size() != U2F_EC_POINT_SIZE) {
    return SAPI_RC_BAD_PARAMETER;
  }

  u2f_attest_req req{};
  auto* msg = reinterpret_cast<g2f_register_msg_v0*>(req.data);

  std::copy(user_secret.begin(), user_secret.end(), req.userSecret);
  req.format = U2F_ATTEST_FORMAT_REG_RESP;
  req.dataLen = sizeof(g2f_register_msg_v0);
  msg->reserved = 0;
  std::copy(app_id.begin(), app_id.end(), msg->app_id);
  std::copy(challenge.begin(), challenge.end(), msg->challenge);
  memcpy(&msg->key_handle, key_handle.data(), key_handle.size());
  memcpy(&msg->public_key, public_key.data(), public_key.size());

  const size_t req_size =
      offsetof(u2f_attest_req, data) + sizeof(g2f_register_msg_v0);
  buffer->resize(req_size);
  memcpy(buffer->data(), &req, req_size);

  return TPM_RC_SUCCESS;
}

TPM_RC
Serialize_u2f_corp_attest_t(const brillo::Blob& app_id,
                            const brillo::SecureBlob& user_secret,
                            const brillo::Blob& challenge,
                            const brillo::Blob& key_handle,
                            const brillo::Blob& public_key,
                            const brillo::Blob& salt,
                            std::string* buffer) {
  buffer->clear();

  if (app_id.size() != U2F_APPID_SIZE ||
      user_secret.size() != U2F_USER_SECRET_SIZE ||
      challenge.size() != CORP_CHAL_SIZE ||
      key_handle.size() != U2F_V0_KH_SIZE ||
      public_key.size() != U2F_EC_POINT_SIZE || salt.size() != CORP_SALT_SIZE) {
    return SAPI_RC_BAD_PARAMETER;
  }

  u2f_attest_req req{};
  auto* msg = reinterpret_cast<corp_register_msg_v0*>(req.data);
  auto* data = reinterpret_cast<corp_attest_data*>(&msg->data);

  std::copy(user_secret.begin(), user_secret.end(), req.userSecret);
  req.format = CORP_ATTEST_FORMAT_REG_RESP;
  req.dataLen = sizeof(corp_register_msg_v0);
  std::copy(challenge.begin(), challenge.end(), data->challenge);
  memcpy(&data->public_key, public_key.data(), public_key.size());
  std::copy(salt.begin(), salt.end(), data->salt);
  std::copy(app_id.begin(), app_id.end(), msg->app_id);
  memcpy(&msg->key_handle, key_handle.data(), key_handle.size());

  const size_t req_size =
      offsetof(u2f_attest_req, data) + sizeof(corp_register_msg_v0);
  buffer->resize(req_size);
  memcpy(buffer->data(), &req, req_size);

  return TPM_RC_SUCCESS;
}

TPM_RC Parse_u2f_generate_t(const std::string& buffer,
                            uint8_t version,
                            brillo::Blob* public_key,
                            brillo::Blob* key_handle) {
  public_key->clear();
  key_handle->clear();

  if (version == 0) {
    if (buffer.length() != sizeof(u2f_generate_resp)) {
      return SAPI_RC_BAD_SIZE;
    }
    public_key->assign(buffer.cbegin() + offsetof(u2f_generate_resp, pubKey),
                       buffer.cbegin() + offsetof(u2f_generate_resp, pubKey) +
                           sizeof(u2f_generate_resp::pubKey));
    key_handle->assign(buffer.cbegin() + offsetof(u2f_generate_resp, keyHandle),
                       buffer.cbegin() +
                           offsetof(u2f_generate_resp, keyHandle) +
                           sizeof(u2f_generate_resp::keyHandle));
  } else if (version == 1) {
    if (buffer.length() != sizeof(u2f_generate_versioned_resp)) {
      return SAPI_RC_BAD_SIZE;
    }
    public_key->assign(
        buffer.cbegin() + offsetof(u2f_generate_versioned_resp, pubKey),
        buffer.cbegin() + offsetof(u2f_generate_versioned_resp, pubKey) +
            sizeof(u2f_generate_versioned_resp::pubKey));
    key_handle->assign(
        buffer.cbegin() + offsetof(u2f_generate_versioned_resp, keyHandle),
        buffer.cbegin() + offsetof(u2f_generate_versioned_resp, keyHandle) +
            sizeof(u2f_generate_versioned_resp::keyHandle));
  } else {
    return SAPI_RC_BAD_PARAMETER;
  }

  return TPM_RC_SUCCESS;
}

TPM_RC Parse_u2f_sign_t(const std::string& buffer,
                        brillo::Blob* sig_r,
                        brillo::Blob* sig_s) {
  sig_r->clear();
  sig_s->clear();

  if (buffer.length() != sizeof(u2f_sign_resp)) {
    return SAPI_RC_BAD_SIZE;
  }
  sig_r->assign(buffer.cbegin() + offsetof(u2f_sign_resp, sig_r),
                buffer.cbegin() + offsetof(u2f_sign_resp, sig_r) +
                    sizeof(u2f_sign_resp::sig_r));
  sig_s->assign(buffer.cbegin() + offsetof(u2f_sign_resp, sig_s),
                buffer.cbegin() + offsetof(u2f_sign_resp, sig_s) +
                    sizeof(u2f_sign_resp::sig_s));
  return TPM_RC_SUCCESS;
}

}  // namespace trunks

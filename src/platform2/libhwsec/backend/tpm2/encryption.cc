// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec/backend/tpm2/encryption.h"

#include <memory>
#include <string>

#include <base/functional/callback_helpers.h>
#include <brillo/secure_blob.h>
#include <libhwsec-foundation/status/status_chain_macros.h>
#include <trunks/openssl_utility.h>
#include <trunks/tpm_utility.h>

#include "libhwsec/error/tpm2_error.h"
#include "libhwsec/status.h"
#include "libhwsec/structures/no_default_init.h"

using brillo::BlobFromString;
using brillo::BlobToString;
using hwsec_foundation::status::MakeStatus;

namespace hwsec {

namespace {

struct SchemaDetail {
  NoDefault<trunks::TPM_ALG_ID> schema;
  NoDefault<trunks::TPM_ALG_ID> hash_alg;
};

StatusOr<SchemaDetail> GetSchemaDetail(
    const EncryptionTpm2::EncryptionOptions& options) {
  switch (options.schema) {
    case EncryptionTpm2::EncryptionOptions::Schema::kDefault:
      return SchemaDetail{
          .schema = trunks::TPM_ALG_OAEP,
          .hash_alg = trunks::TPM_ALG_SHA256,
      };
    case EncryptionTpm2::EncryptionOptions::Schema::kNull:
      return SchemaDetail{
          .schema = trunks::TPM_ALG_NULL,
          .hash_alg = trunks::TPM_ALG_NULL,
      };
    case EncryptionTpm2::EncryptionOptions::Schema::kRsaesSha1:
      return SchemaDetail{
          .schema = trunks::TPM_ALG_RSAES,
          .hash_alg = trunks::TPM_ALG_SHA1,
      };
    default:
      return MakeStatus<TPMError>("Unknown options", TPMRetryAction::kNoRetry);
  }
}

}  // namespace

StatusOr<brillo::Blob> EncryptionTpm2::Encrypt(
    Key key, const brillo::SecureBlob& plaintext, EncryptionOptions options) {
  ASSIGN_OR_RETURN(const KeyTpm2& key_data, key_management_.GetKeyData(key));

  ASSIGN_OR_RETURN(const SchemaDetail& schema, GetSchemaDetail(options));

  if (plaintext.size() > MAX_RSA_KEY_BYTES) {
    return MakeStatus<TPMError>("Plaintext too large",
                                TPMRetryAction::kNoRetry);
  }

  std::string data = plaintext.to_string();

  // Cleanup the data from secure blob.
  base::ScopedClosureRunner cleanup_data(base::BindOnce(
      brillo::SecureClearContainer<std::string>, std::ref(data)));

  ASSIGN_OR_RETURN(
      ConfigTpm2::TrunksSession session,
      config_.GetTrunksSession(key_data.cache.policy,
                               SessionSecuritySetting::kSaltAndEncrypted),
      _.WithStatus<TPMError>("Failed to get session for policy"));

  std::string tpm_ciphertext;

  RETURN_IF_ERROR(
      MakeStatus<TPM2Error>(context_.GetTpmUtility().AsymmetricEncrypt(
          key_data.key_handle, schema.schema, schema.hash_alg, data,
          session.delegate, &tpm_ciphertext)))
      .WithStatus<TPMError>("Failed to encrypt plaintext");

  return BlobFromString(tpm_ciphertext);
}

StatusOr<brillo::SecureBlob> EncryptionTpm2::Decrypt(
    Key key, const brillo::Blob& ciphertext, EncryptionOptions options) {
  ASSIGN_OR_RETURN(const KeyTpm2& key_data, key_management_.GetKeyData(key));

  ASSIGN_OR_RETURN(const SchemaDetail& schema, GetSchemaDetail(options));

  if (ciphertext.size() > MAX_RSA_KEY_BYTES) {
    return MakeStatus<TPMError>("Ciphertext too large",
                                TPMRetryAction::kNoRetry);
  }

  ASSIGN_OR_RETURN(
      ConfigTpm2::TrunksSession session,
      config_.GetTrunksSession(key_data.cache.policy,
                               SessionSecuritySetting::kNoEncrypted),
      _.WithStatus<TPMError>("Failed to get session for policy"));

  std::string tpm_plaintext;

  RETURN_IF_ERROR(
      MakeStatus<TPM2Error>(context_.GetTpmUtility().AsymmetricDecrypt(
          key_data.key_handle, schema.schema, schema.hash_alg,
          BlobToString(ciphertext), session.delegate, &tpm_plaintext)))
      .WithStatus<TPMError>("Failed to decrypt ciphertext");

  brillo::SecureBlob result(tpm_plaintext.begin(), tpm_plaintext.end());
  return result;
}

}  // namespace hwsec

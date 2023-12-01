// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec/backend/tpm1/encryption.h"

#include <cstdint>
#include <string>

#include <base/functional/callback_helpers.h>
#include <brillo/secure_blob.h>
#include <libhwsec-foundation/status/status_chain_macros.h>

#include "libhwsec/error/tpm1_error.h"
#include "libhwsec/overalls/overalls.h"
#include "libhwsec/status.h"
#include "libhwsec/tss_utils/scoped_tss_type.h"

using brillo::BlobFromString;
using brillo::BlobToString;
using hwsec_foundation::status::MakeStatus;

namespace hwsec {

StatusOr<brillo::Blob> EncryptionTpm1::Encrypt(
    Key key, const brillo::SecureBlob& plaintext, EncryptionOptions options) {
  if (options.schema != EncryptionOptions::Schema::kDefault &&
      options.schema != EncryptionOptions::Schema::kRsaesSha1) {
    return MakeStatus<TPMError>("Unsupported schema", TPMRetryAction::kNoRetry);
  }

  ASSIGN_OR_RETURN(const KeyTpm1& key_data, key_management_.GetKeyData(key));

  ASSIGN_OR_RETURN(TSS_HCONTEXT context, tss_helper_.GetTssContext());

  TSS_FLAG init_flags = TSS_ENCDATA_SEAL;
  ScopedTssKey enc_handle(overalls_, context);

  RETURN_IF_ERROR(
      MakeStatus<TPM1Error>(overalls_.Ospi_Context_CreateObject(
          context, TSS_OBJECT_TYPE_ENCDATA, init_flags, enc_handle.ptr())))
      .WithStatus<TPMError>("Failed to call Ospi_Context_CreateObject");

  brillo::SecureBlob mutable_plaintext = plaintext;

  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls_.Ospi_Data_Bind(
                      enc_handle, key_data.key_handle, mutable_plaintext.size(),
                      mutable_plaintext.data())))
      .WithStatus<TPMError>("Failed to call Ospi_Data_Bind");

  uint32_t length = 0;
  ScopedTssMemory buffer(overalls_, context);

  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls_.Ospi_GetAttribData(
                      enc_handle, TSS_TSPATTRIB_ENCDATA_BLOB,
                      TSS_TSPATTRIB_ENCDATABLOB_BLOB, &length, buffer.ptr())))
      .WithStatus<TPMError>("Failed to call Ospi_GetAttribData");

  return brillo::Blob(buffer.value(), buffer.value() + length);
}

StatusOr<brillo::SecureBlob> EncryptionTpm1::Decrypt(
    Key key, const brillo::Blob& ciphertext, EncryptionOptions options) {
  if (options.schema != EncryptionOptions::Schema::kDefault &&
      options.schema != EncryptionOptions::Schema::kRsaesSha1) {
    return MakeStatus<TPMError>("Unsupported schema", TPMRetryAction::kNoRetry);
  }

  ASSIGN_OR_RETURN(const KeyTpm1& key_data, key_management_.GetKeyData(key));

  ASSIGN_OR_RETURN(TSS_HCONTEXT context, tss_helper_.GetTssContext());

  brillo::Blob local_data = ciphertext;

  TSS_FLAG init_flags = TSS_ENCDATA_SEAL;
  ScopedTssKey enc_handle(overalls_, context);

  RETURN_IF_ERROR(
      MakeStatus<TPM1Error>(overalls_.Ospi_Context_CreateObject(
          context, TSS_OBJECT_TYPE_ENCDATA, init_flags, enc_handle.ptr())))
      .WithStatus<TPMError>("Failed to call Ospi_Context_CreateObject");

  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls_.Ospi_SetAttribData(
                      enc_handle, TSS_TSPATTRIB_ENCDATA_BLOB,
                      TSS_TSPATTRIB_ENCDATABLOB_BLOB, local_data.size(),
                      local_data.data())))
      .WithStatus<TPMError>("Failed to call Ospi_SetAttribData");

  ScopedTssSecureMemory buffer(overalls_, context);
  uint32_t length = 0;

  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls_.Ospi_Data_Unbind(
                      enc_handle, key_data.key_handle, &length, buffer.ptr())))
      .WithStatus<TPMError>("Failed to call Ospi_Data_Unbind");

  return brillo::SecureBlob(buffer.value(), buffer.value() + length);
}

}  // namespace hwsec

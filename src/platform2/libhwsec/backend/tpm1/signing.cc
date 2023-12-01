// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec/backend/tpm1/signing.h"

#include <brillo/secure_blob.h>
#include <libhwsec-foundation/crypto/sha.h>
#include <libhwsec-foundation/status/status_chain_macros.h>

#include "libhwsec/backend/digest_algorithms.h"
#include "libhwsec/error/tpm1_error.h"
#include "libhwsec/overalls/overalls.h"
#include "libhwsec/status.h"
#include "libhwsec/tss_utils/scoped_tss_type.h"

using brillo::BlobFromString;
using hwsec_foundation::Sha256;
using hwsec_foundation::status::MakeStatus;

namespace hwsec {

StatusOr<brillo::Blob> SigningTpm1::Sign(Key key,
                                         const brillo::Blob& data,
                                         const SigningOptions& options) {
  ASSIGN_OR_RETURN(const brillo::Blob& hashed_data,
                   DigestData(options.digest_algorithm, data));
  return RawSign(key, hashed_data, options);
}

StatusOr<brillo::Blob> SigningTpm1::RawSign(Key key,
                                            const brillo::Blob& data,
                                            const SigningOptions& options) {
  if (options.rsa_padding_scheme.value_or(
          SigningOptions::RsaPaddingScheme::kPkcs1v15) !=
      SigningOptions::RsaPaddingScheme::kPkcs1v15) {
    return MakeStatus<TPMError>("Unsupported mechanism for tpm1.2 key",
                                TPMRetryAction::kNoRetry);
  }

  ASSIGN_OR_RETURN(const KeyTpm1& key_data, key_management_.GetKeyData(key),
                   _.WithStatus<TPMError>("Failed to get the key data"));

  ASSIGN_OR_RETURN(TSS_HCONTEXT context, tss_helper_.GetTssContext());

  // Create a hash object to hold the input.
  ScopedTssObject<TSS_HHASH> hash_handle(overalls_, context);

  RETURN_IF_ERROR(
      MakeStatus<TPM1Error>(overalls_.Ospi_Context_CreateObject(
          context, TSS_OBJECT_TYPE_HASH, TSS_HASH_OTHER, hash_handle.ptr())))
      .WithStatus<TPMError>("Failed to create hash object");

  // Create the DER encoded input.
  ASSIGN_OR_RETURN(const brillo::Blob& der_header,
                   GetDigestAlgorithmEncoding(options.digest_algorithm));

  brillo::Blob der_encoded_input = brillo::CombineBlobs({der_header, data});

  RETURN_IF_ERROR(
      MakeStatus<TPM1Error>(overalls_.Ospi_Hash_SetHashValue(
          hash_handle, der_encoded_input.size(), der_encoded_input.data())))
      .WithStatus<TPMError>("Failed to set hash data");

  uint32_t length = 0;
  ScopedTssMemory buffer(overalls_, context);

  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls_.Ospi_Hash_Sign(
                      hash_handle, key_data.key_handle, &length, buffer.ptr())))
      .WithStatus<TPMError>("Failed to generate signature");

  return brillo::Blob(buffer.value(), buffer.value() + length);
}

Status SigningTpm1::Verify(Key key, const brillo::Blob& signed_data) {
  return MakeStatus<TPMError>("Unimplemented", TPMRetryAction::kNoRetry);
}

}  // namespace hwsec

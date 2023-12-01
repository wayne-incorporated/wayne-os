// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec/backend/tpm1/random.h"

#include <base/functional/callback_helpers.h>
#include <base/strings/stringprintf.h>
#include <libhwsec-foundation/status/status_chain_macros.h>

#include "libhwsec/error/tpm1_error.h"
#include "libhwsec/overalls/overalls.h"
#include "libhwsec/status.h"
#include "libhwsec/tss_utils/scoped_tss_type.h"

using brillo::BlobFromString;
using hwsec_foundation::status::MakeStatus;

namespace hwsec {

StatusOr<brillo::Blob> RandomTpm1::RandomBlob(size_t size) {
  ASSIGN_OR_RETURN(const brillo::SecureBlob& blob, RandomSecureBlob(size),
                   _.WithStatus<TPMError>("Failed to get random secure data"));

  return brillo::Blob(blob.begin(), blob.end());
}

StatusOr<brillo::SecureBlob> RandomTpm1::RandomSecureBlob(size_t size) {
  ASSIGN_OR_RETURN(TSS_HCONTEXT context, tss_helper_.GetTssContext());

  ASSIGN_OR_RETURN(TSS_HTPM tpm_handle, tss_helper_.GetUserTpmHandle());

  brillo::SecureBlob random(size);
  ScopedTssSecureMemory tpm_data(overalls_, context);

  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls_.Ospi_TPM_GetRandom(
                      tpm_handle, random.size(), tpm_data.ptr())))
      .WithStatus<TPMError>("Failed to call Ospi_TPM_GetRandom");

  memcpy(random.data(), tpm_data.value(), random.size());
  return random;
}

}  // namespace hwsec

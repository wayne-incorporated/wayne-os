// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec/backend/tpm2/random.h"

#include <string>

#include <base/functional/callback_helpers.h>
#include <base/strings/stringprintf.h>
#include <libhwsec-foundation/status/status_chain_macros.h>
#include <trunks/openssl_utility.h>
#include <trunks/tpm_utility.h>

#include "libhwsec/error/tpm2_error.h"
#include "libhwsec/status.h"

using brillo::BlobFromString;
using hwsec_foundation::status::MakeStatus;

namespace hwsec {

StatusOr<brillo::Blob> RandomTpm2::RandomBlob(size_t size) {
  ASSIGN_OR_RETURN(const brillo::SecureBlob& blob, RandomSecureBlob(size),
                   _.WithStatus<TPMError>("Failed to get random secure data"));

  return brillo::Blob(blob.begin(), blob.end());
}

StatusOr<brillo::SecureBlob> RandomTpm2::RandomSecureBlob(size_t size) {
  std::string random_data;

  // Cleanup the data for secure blob.
  base::ScopedClosureRunner cleanup_random_data(base::BindOnce(
      brillo::SecureClearContainer<std::string>, std::ref(random_data)));

  RETURN_IF_ERROR(MakeStatus<TPM2Error>(context_.GetTpmUtility().GenerateRandom(
                      size, /*delegate=*/nullptr, &random_data)))
      .WithStatus<TPMError>("Failed to get random data");

  if (random_data.size() != size) {
    return MakeStatus<TPMError>(
        base::StringPrintf(
            "Failed to get random data: requested size %zu, received size %zu",
            size, random_data.size()),
        TPMRetryAction::kNoRetry);
  }

  return brillo::SecureBlob(random_data.begin(), random_data.end());
}

}  // namespace hwsec

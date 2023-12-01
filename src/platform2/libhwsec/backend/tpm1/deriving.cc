// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec/backend/tpm1/deriving.h"

#include "libhwsec/status.h"

using brillo::Blob;
using brillo::SecureBlob;
using hwsec_foundation::status::MakeStatus;

namespace hwsec {

StatusOr<Blob> DerivingTpm1::Derive(Key key, const Blob& blob) {
  // For TPM1.2, the output of deriving should be the same as input.
  return blob;
}

StatusOr<SecureBlob> DerivingTpm1::SecureDerive(Key key,
                                                const SecureBlob& blob) {
  // For TPM1.2, the output of deriving should be the same as input.
  return blob;
}

}  // namespace hwsec

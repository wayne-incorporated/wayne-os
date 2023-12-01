// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_TPM1_DERIVING_H_
#define LIBHWSEC_BACKEND_TPM1_DERIVING_H_

#include <brillo/secure_blob.h>

#include "libhwsec/backend/deriving.h"
#include "libhwsec/status.h"

namespace hwsec {

class DerivingTpm1 : public Deriving {
 public:
  StatusOr<brillo::Blob> Derive(Key key, const brillo::Blob& blob) override;
  StatusOr<brillo::SecureBlob> SecureDerive(
      Key key, const brillo::SecureBlob& blob) override;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_TPM1_DERIVING_H_

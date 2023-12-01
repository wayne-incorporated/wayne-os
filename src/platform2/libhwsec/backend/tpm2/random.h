// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_TPM2_RANDOM_H_
#define LIBHWSEC_BACKEND_TPM2_RANDOM_H_

#include <brillo/secure_blob.h>

#include "libhwsec/backend/random.h"
#include "libhwsec/backend/tpm2/trunks_context.h"
#include "libhwsec/status.h"

namespace hwsec {

class RandomTpm2 : public Random {
 public:
  explicit RandomTpm2(TrunksContext& context) : context_(context) {}

  StatusOr<brillo::Blob> RandomBlob(size_t size) override;
  StatusOr<brillo::SecureBlob> RandomSecureBlob(size_t size) override;

 private:
  TrunksContext& context_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_TPM2_RANDOM_H_

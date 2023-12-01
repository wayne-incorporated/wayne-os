// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_TPM1_RANDOM_H_
#define LIBHWSEC_BACKEND_TPM1_RANDOM_H_

#include <brillo/secure_blob.h>

#include "libhwsec/backend/random.h"
#include "libhwsec/backend/tpm1/tss_helper.h"
#include "libhwsec/proxy/proxy.h"
#include "libhwsec/status.h"

namespace hwsec {

class RandomTpm1 : public Random {
 public:
  RandomTpm1(overalls::Overalls& overalls, TssHelper& tss_helper)
      : overalls_(overalls), tss_helper_(tss_helper) {}

  StatusOr<brillo::Blob> RandomBlob(size_t size) override;
  StatusOr<brillo::SecureBlob> RandomSecureBlob(size_t size) override;

 private:
  overalls::Overalls& overalls_;
  TssHelper& tss_helper_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_TPM1_RANDOM_H_

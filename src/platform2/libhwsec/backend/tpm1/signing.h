// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_TPM1_SIGNING_H_
#define LIBHWSEC_BACKEND_TPM1_SIGNING_H_

#include <brillo/secure_blob.h>

#include "libhwsec/backend/signing.h"
#include "libhwsec/backend/tpm1/key_management.h"
#include "libhwsec/backend/tpm1/tss_helper.h"
#include "libhwsec/proxy/proxy.h"
#include "libhwsec/status.h"

namespace hwsec {

class SigningTpm1 : public Signing {
 public:
  SigningTpm1(overalls::Overalls& overalls,
              TssHelper& tss_helper,
              KeyManagementTpm1& key_management)
      : overalls_(overalls),
        tss_helper_(tss_helper),
        key_management_(key_management) {}

  StatusOr<brillo::Blob> Sign(Key key,
                              const brillo::Blob& data,
                              const SigningOptions& options) override;
  StatusOr<brillo::Blob> RawSign(Key key,
                                 const brillo::Blob& data,
                                 const SigningOptions& options) override;
  Status Verify(Key key, const brillo::Blob& signed_data) override;

 private:
  overalls::Overalls& overalls_;
  TssHelper& tss_helper_;
  KeyManagementTpm1& key_management_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_TPM1_SIGNING_H_

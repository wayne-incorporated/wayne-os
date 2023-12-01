// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_TPM1_TSS_HELPER_H_
#define LIBHWSEC_BACKEND_TPM1_TSS_HELPER_H_

#include <cstdint>
#include <memory>
#include <optional>
#include <utility>

#include <brillo/secure_blob.h>

#include "libhwsec/proxy/proxy.h"
#include "libhwsec/status.h"
#include "libhwsec/tss_utils/scoped_tss_type.h"

namespace hwsec {

// The helper class for TSS context and objects.
class TssHelper {
 public:
  TssHelper(org::chromium::TpmManagerProxyInterface& tpm_manager,
            overalls::Overalls& overalls)
      : tpm_manager_(tpm_manager), overalls_(overalls) {}

  StatusOr<ScopedTssContext> GetScopedTssContext();
  StatusOr<TSS_HCONTEXT> GetTssContext();
  StatusOr<TSS_HTPM> GetUserTpmHandle();

  // The delegate TPM handle would not be cached to prevent leaking the delegate
  // permission.
  StatusOr<ScopedTssObject<TSS_HTPM>> GetDelegateTpmHandle();

 private:
  org::chromium::TpmManagerProxyInterface& tpm_manager_;
  overalls::Overalls& overalls_;

  std::optional<ScopedTssContext> tss_context_;
  std::optional<ScopedTssObject<TSS_HTPM>> user_tpm_handle_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_TPM1_TSS_HELPER_H_

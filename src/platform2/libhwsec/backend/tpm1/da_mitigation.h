// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_TPM1_DA_MITIGATION_H_
#define LIBHWSEC_BACKEND_TPM1_DA_MITIGATION_H_

#include "libhwsec/backend/da_mitigation.h"
#include "libhwsec/proxy/proxy.h"
#include "libhwsec/status.h"

namespace hwsec {

class DAMitigationTpm1 : public DAMitigation {
 public:
  explicit DAMitigationTpm1(
      org::chromium::TpmManagerProxyInterface& tpm_manager)
      : tpm_manager_(tpm_manager) {}

  StatusOr<bool> IsReady() override;
  StatusOr<DAMitigationStatus> GetStatus() override;
  Status Mitigate() override;

 private:
  org::chromium::TpmManagerProxyInterface& tpm_manager_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_TPM1_DA_MITIGATION_H_

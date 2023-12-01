// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_TPM2_RO_DATA_H_
#define LIBHWSEC_BACKEND_TPM2_RO_DATA_H_

#include <cstdint>

#include <brillo/secure_blob.h>

#include "libhwsec/backend/ro_data.h"
#include "libhwsec/proxy/proxy.h"
#include "libhwsec/status.h"

namespace hwsec {

class RoDataTpm2 : public RoData {
 public:
  explicit RoDataTpm2(org::chromium::TpmNvramProxyInterface& tpm_nvram)
      : tpm_nvram_(tpm_nvram) {}

  StatusOr<bool> IsReady(RoSpace space) override;
  StatusOr<brillo::Blob> Read(RoSpace space) override;
  StatusOr<brillo::Blob> Certify(RoSpace space, Key key) override;

 private:
  org::chromium::TpmNvramProxyInterface& tpm_nvram_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_TPM2_RO_DATA_H_

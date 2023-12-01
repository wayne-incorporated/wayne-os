// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_TPM1_STORAGE_H_
#define LIBHWSEC_BACKEND_TPM1_STORAGE_H_

#include <cstdint>

#include <absl/container/flat_hash_map.h>
#include <brillo/secure_blob.h>

#include "libhwsec/backend/storage.h"
#include "libhwsec/proxy/proxy.h"
#include "libhwsec/status.h"

namespace hwsec {

class StorageTpm1 : public Storage {
 public:
  StorageTpm1(org::chromium::TpmManagerProxyInterface& tpm_manager,
              org::chromium::TpmNvramProxyInterface& tpm_nvram)
      : tpm_manager_(tpm_manager), tpm_nvram_(tpm_nvram) {}

  StatusOr<ReadyState> IsReady(Space space) override;
  Status Prepare(Space space, uint32_t size) override;
  StatusOr<brillo::Blob> Load(Space space) override;
  Status Store(Space space, const brillo::Blob& blob) override;
  Status Lock(Space space, LockOptions options) override;
  Status Destroy(Space space) override;

 private:
  StatusOr<ReadyState> IsReadyInternal(Space space);

  org::chromium::TpmManagerProxyInterface& tpm_manager_;
  org::chromium::TpmNvramProxyInterface& tpm_nvram_;

  absl::flat_hash_map<Space, ReadyState> state_cache_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_TPM1_STORAGE_H_

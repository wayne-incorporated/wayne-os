// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FRONTEND_BOOTLOCKBOX_FRONTEND_IMPL_H_
#define LIBHWSEC_FRONTEND_BOOTLOCKBOX_FRONTEND_IMPL_H_

#include <optional>
#include <vector>

#include <brillo/secure_blob.h>

#include "libhwsec/frontend/bootlockbox/frontend.h"
#include "libhwsec/frontend/frontend_impl.h"
#include "libhwsec/status.h"

namespace hwsec {

class BootLockboxFrontendImpl : public BootLockboxFrontend,
                                public FrontendImpl {
 public:
  using FrontendImpl::FrontendImpl;
  ~BootLockboxFrontendImpl() override = default;

  StatusOr<StorageState> GetSpaceState() const override;
  Status PrepareSpace(uint32_t size) const override;
  StatusOr<brillo::Blob> LoadSpace() const override;
  Status StoreSpace(const brillo::Blob& blob) const override;
  Status LockSpace() const override;
  void WaitUntilReady(base::OnceCallback<void(Status)> callback) const override;
};

}  // namespace hwsec

#endif  // LIBHWSEC_FRONTEND_BOOTLOCKBOX_FRONTEND_IMPL_H_

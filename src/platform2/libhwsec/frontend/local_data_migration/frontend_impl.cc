// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec/frontend/local_data_migration/frontend_impl.h"

#include <brillo/secure_blob.h>

#include "libhwsec/backend/backend.h"
#include "libhwsec/middleware/middleware.h"
#include "libhwsec/status.h"

namespace hwsec {

StatusOr<brillo::SecureBlob> LocalDataMigrationFrontendImpl::Unseal(
    const brillo::Blob& sealed_data) const {
  return middleware_.CallSync<&Backend::Sealing::Unseal>(
      OperationPolicy{
          .permission =
              Permission{
                  .auth_value = brillo::SecureBlob(""),
              },
      },
      sealed_data, Sealing::UnsealOptions{});
}

}  // namespace hwsec

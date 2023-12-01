// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FRONTEND_LOCAL_DATA_MIGRATION_FRONTEND_IMPL_H_
#define LIBHWSEC_FRONTEND_LOCAL_DATA_MIGRATION_FRONTEND_IMPL_H_

#include <brillo/secure_blob.h>

#include "libhwsec/frontend/frontend_impl.h"
#include "libhwsec/frontend/local_data_migration/frontend.h"
#include "libhwsec/status.h"

namespace hwsec {

class LocalDataMigrationFrontendImpl : public LocalDataMigrationFrontend,
                                       public FrontendImpl {
 public:
  using FrontendImpl::FrontendImpl;
  ~LocalDataMigrationFrontendImpl() override = default;

  StatusOr<brillo::SecureBlob> Unseal(
      const brillo::Blob& sealed_data) const override;
};

}  // namespace hwsec

#endif  // LIBHWSEC_FRONTEND_LOCAL_DATA_MIGRATION_FRONTEND_IMPL_H_

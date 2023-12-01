// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FRONTEND_LOCAL_DATA_MIGRATION_MOCK_FRONTEND_H_
#define LIBHWSEC_FRONTEND_LOCAL_DATA_MIGRATION_MOCK_FRONTEND_H_

#include <brillo/secure_blob.h>
#include <gmock/gmock.h>

#include "libhwsec/frontend/local_data_migration/frontend.h"
#include "libhwsec/frontend/mock_frontend.h"
#include "libhwsec/status.h"

namespace hwsec {

class MockLocalDataMigrationFrontend : public MockFrontend,
                                       public LocalDataMigrationFrontend {
 public:
  MockLocalDataMigrationFrontend() = default;
  ~MockLocalDataMigrationFrontend() override = default;
  MOCK_METHOD(StatusOr<brillo::SecureBlob>,
              Unseal,
              (const brillo::Blob& sealed_data),
              (const override));
};

}  // namespace hwsec

#endif  // LIBHWSEC_FRONTEND_LOCAL_DATA_MIGRATION_MOCK_FRONTEND_H_

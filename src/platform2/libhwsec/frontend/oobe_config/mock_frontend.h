// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FRONTEND_OOBE_CONFIG_MOCK_FRONTEND_H_
#define LIBHWSEC_FRONTEND_OOBE_CONFIG_MOCK_FRONTEND_H_

#include <optional>
#include <vector>

#include <brillo/secure_blob.h>
#include <gmock/gmock.h>

#include "libhwsec/frontend/mock_frontend.h"
#include "libhwsec/frontend/oobe_config/frontend.h"
#include "libhwsec/status.h"

namespace hwsec {

class MockOobeConfigFrontend : public MockFrontend, public OobeConfigFrontend {
 public:
  MockOobeConfigFrontend() = default;
  ~MockOobeConfigFrontend() override = default;

  MOCK_METHOD(Status, IsRollbackSpaceReady, (), (const override));
  MOCK_METHOD(Status, ResetRollbackSpace, (), (const override));
  MOCK_METHOD(StatusOr<brillo::Blob>,
              Encrypt,
              (const brillo::SecureBlob& plain_data),
              (const override));
  MOCK_METHOD(StatusOr<brillo::SecureBlob>,
              Decrypt,
              (const brillo::Blob& encrypted_data),
              (const override));
};

}  // namespace hwsec

#endif  // LIBHWSEC_FRONTEND_OOBE_CONFIG_MOCK_FRONTEND_H_

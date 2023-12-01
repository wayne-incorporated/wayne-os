// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FRONTEND_U2FD_MOCK_FRONTEND_H_
#define LIBHWSEC_FRONTEND_U2FD_MOCK_FRONTEND_H_

#include <brillo/secure_blob.h>
#include <gmock/gmock.h>

#include "libhwsec/frontend/mock_frontend.h"
#include "libhwsec/frontend/u2fd/frontend.h"

namespace hwsec {

class MockU2fFrontend : public MockFrontend, public U2fFrontend {
 public:
  MockU2fFrontend() = default;
  ~MockU2fFrontend() override = default;

  MOCK_METHOD(StatusOr<bool>, IsEnabled, (), (const override));
  MOCK_METHOD(StatusOr<bool>, IsReady, (), (const override));
  MOCK_METHOD(StatusOr<CreateKeyResult>,
              GenerateRSASigningKey,
              (const brillo::SecureBlob& auth_value),
              (const override));
  MOCK_METHOD(StatusOr<RSAPublicInfo>,
              GetRSAPublicKey,
              (Key key),
              (const override));
  MOCK_METHOD(StatusOr<ScopedKey>,
              LoadKey,
              (const brillo::Blob& key_blob,
               const brillo::SecureBlob& auth_value),
              (const override));
  MOCK_METHOD(StatusOr<brillo::Blob>,
              RSASign,
              (Key key, const brillo::Blob& data),
              (const override));
};

}  // namespace hwsec

#endif  // LIBHWSEC_FRONTEND_U2FD_MOCK_FRONTEND_H_

// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_MOCK_SIGNING_H_
#define LIBHWSEC_BACKEND_MOCK_SIGNING_H_

#include <brillo/secure_blob.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libhwsec/backend/signing.h"
#include "libhwsec/status.h"
#include "libhwsec/structures/key.h"

namespace hwsec {

class MockSigning : public Signing {
 public:
  MockSigning() = default;
  explicit MockSigning(Signing* on_call) : default_(on_call) {
    using testing::Invoke;
    if (!default_)
      return;
    ON_CALL(*this, Sign).WillByDefault(Invoke(default_, &Signing::Sign));
    ON_CALL(*this, RawSign).WillByDefault(Invoke(default_, &Signing::RawSign));
    ON_CALL(*this, Verify).WillByDefault(Invoke(default_, &Signing::Verify));
  }

  MOCK_METHOD(StatusOr<brillo::Blob>,
              Sign,
              (Key key,
               const brillo::Blob& data,
               const SigningOptions& options),
              (override));
  MOCK_METHOD(StatusOr<brillo::Blob>,
              RawSign,
              (Key key,
               const brillo::Blob& data,
               const SigningOptions& options),
              (override));
  MOCK_METHOD(Status,
              Verify,
              (Key key, const brillo::Blob& signed_data),
              (override));

 private:
  Signing* default_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_MOCK_SIGNING_H_

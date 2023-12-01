// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_MOCK_DERIVING_H_
#define LIBHWSEC_BACKEND_MOCK_DERIVING_H_

#include <cstdint>

#include <brillo/secure_blob.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libhwsec/backend/deriving.h"
#include "libhwsec/status.h"
#include "libhwsec/structures/key.h"

namespace hwsec {

class MockDeriving : public Deriving {
 public:
  MockDeriving() = default;
  explicit MockDeriving(Deriving* on_call) : default_(on_call) {
    using testing::Invoke;
    if (!default_)
      return;
    ON_CALL(*this, Derive).WillByDefault(Invoke(default_, &Deriving::Derive));
    ON_CALL(*this, SecureDerive)
        .WillByDefault(Invoke(default_, &Deriving::SecureDerive));
  }

  MOCK_METHOD(StatusOr<brillo::Blob>,
              Derive,
              (Key key, const brillo::Blob& blob),
              (override));
  MOCK_METHOD(StatusOr<brillo::SecureBlob>,
              SecureDerive,
              (Key key, const brillo::SecureBlob& blob),
              (override));

 private:
  Deriving* default_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_MOCK_DERIVING_H_

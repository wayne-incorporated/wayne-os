// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_MOCK_RANDOM_H_
#define LIBHWSEC_BACKEND_MOCK_RANDOM_H_

#include <brillo/secure_blob.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libhwsec/backend/random.h"
#include "libhwsec/status.h"

namespace hwsec {

class MockRandom : public Random {
 public:
  MockRandom() = default;
  explicit MockRandom(Random* on_call) : default_(on_call) {
    using testing::Invoke;
    if (!default_)
      return;
    ON_CALL(*this, RandomBlob)
        .WillByDefault(Invoke(default_, &Random::RandomBlob));
    ON_CALL(*this, RandomSecureBlob)
        .WillByDefault(Invoke(default_, &Random::RandomSecureBlob));
  }

  MOCK_METHOD(StatusOr<brillo::Blob>, RandomBlob, (size_t size), (override));
  MOCK_METHOD(StatusOr<brillo::SecureBlob>,
              RandomSecureBlob,
              (size_t size),
              (override));

 private:
  Random* default_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_MOCK_RANDOM_H_

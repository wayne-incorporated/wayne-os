// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_MOCK_SEALING_H_
#define LIBHWSEC_BACKEND_MOCK_SEALING_H_

#include <optional>

#include <brillo/secure_blob.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libhwsec/backend/sealing.h"
#include "libhwsec/status.h"
#include "libhwsec/structures/key.h"
#include "libhwsec/structures/operation_policy.h"

namespace hwsec {

class MockSealing : public Sealing {
 public:
  MockSealing() = default;
  explicit MockSealing(Sealing* on_call) : default_(on_call) {
    using testing::Invoke;
    if (!default_)
      return;
    ON_CALL(*this, IsSupported)
        .WillByDefault(Invoke(default_, &Sealing::IsSupported));
    ON_CALL(*this, Seal).WillByDefault(Invoke(default_, &Sealing::Seal));
    ON_CALL(*this, PreloadSealedData)
        .WillByDefault(Invoke(default_, &Sealing::PreloadSealedData));
    ON_CALL(*this, Unseal).WillByDefault(Invoke(default_, &Sealing::Unseal));
  }

  MOCK_METHOD(StatusOr<bool>, IsSupported, (), (override));
  MOCK_METHOD(StatusOr<brillo::Blob>,
              Seal,
              (const OperationPolicySetting& policy,
               const brillo::SecureBlob& unsealed_data),
              (override));
  MOCK_METHOD(StatusOr<std::optional<ScopedKey>>,
              PreloadSealedData,
              (const OperationPolicy& policy, const brillo::Blob& sealed_data),
              (override));
  MOCK_METHOD(StatusOr<brillo::SecureBlob>,
              Unseal,
              (const OperationPolicy& policy,
               const brillo::Blob& sealed_data,
               UnsealOptions options),
              (override));

 private:
  Sealing* default_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_MOCK_SEALING_H_

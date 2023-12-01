// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_MOCK_STORAGE_H_
#define LIBHWSEC_BACKEND_MOCK_STORAGE_H_

#include <cstdint>

#include <brillo/secure_blob.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libhwsec/backend/storage.h"
#include "libhwsec/status.h"
#include "libhwsec/structures/space.h"

namespace hwsec {

class MockStorage : public Storage {
 public:
  MockStorage() = default;
  explicit MockStorage(Storage* on_call) : default_(on_call) {
    using testing::Invoke;
    if (!default_)
      return;
    ON_CALL(*this, IsReady).WillByDefault(Invoke(default_, &Storage::IsReady));
    ON_CALL(*this, Prepare).WillByDefault(Invoke(default_, &Storage::Prepare));
    ON_CALL(*this, Load).WillByDefault(Invoke(default_, &Storage::Load));
    ON_CALL(*this, Store).WillByDefault(Invoke(default_, &Storage::Store));
    ON_CALL(*this, Lock).WillByDefault(Invoke(default_, &Storage::Lock));
    ON_CALL(*this, Destroy).WillByDefault(Invoke(default_, &Storage::Destroy));
  }

  MOCK_METHOD(StatusOr<ReadyState>, IsReady, (Space space), (override));
  MOCK_METHOD(Status, Prepare, (Space space, uint32_t size), (override));
  MOCK_METHOD(StatusOr<brillo::Blob>, Load, (Space space), (override));
  MOCK_METHOD(Status,
              Store,
              (Space space, const brillo::Blob& blob),
              (override));
  MOCK_METHOD(Status, Lock, (Space space, LockOptions options), (override));
  MOCK_METHOD(Status, Destroy, (Space space), (override));

 private:
  Storage* default_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_MOCK_STORAGE_H_

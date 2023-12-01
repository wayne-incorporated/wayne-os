// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_MOCK_RO_DATA_H_
#define LIBHWSEC_BACKEND_MOCK_RO_DATA_H_

#include <brillo/secure_blob.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libhwsec/backend/ro_data.h"
#include "libhwsec/status.h"
#include "libhwsec/structures/key.h"
#include "libhwsec/structures/space.h"

namespace hwsec {

class MockRoData : public RoData {
 public:
  MockRoData() = default;
  explicit MockRoData(RoData* on_call) : default_(on_call) {
    using testing::Invoke;
    if (!default_)
      return;
    ON_CALL(*this, IsReady).WillByDefault(Invoke(default_, &RoData::IsReady));
    ON_CALL(*this, Read).WillByDefault(Invoke(default_, &RoData::Read));
    ON_CALL(*this, Certify).WillByDefault(Invoke(default_, &RoData::Certify));
  }

  MOCK_METHOD(StatusOr<bool>, IsReady, (RoSpace space), (override));
  MOCK_METHOD(StatusOr<brillo::Blob>, Read, (RoSpace space), (override));
  MOCK_METHOD(StatusOr<brillo::Blob>,
              Certify,
              (RoSpace space, Key key),
              (override));

 private:
  RoData* default_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_MOCK_RO_DATA_H_

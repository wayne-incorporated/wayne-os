// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FEATURED_MOCK_TMP_STORAGE_IMPL_H_
#define FEATURED_MOCK_TMP_STORAGE_IMPL_H_

#include <gmock/gmock.h>

#include "featured/tmp_storage_interface.h"

namespace featured {

class MockTmpStorageImpl : public TmpStorageInterface {
 public:
  MOCK_METHOD(void, SetUsedSeedDetails, (const SeedDetails&), (override));
  MOCK_METHOD(SeedDetails, GetUsedSeedDetails, (), (override));
};

}  // namespace featured

#endif  // FEATURED_MOCK_TMP_STORAGE_IMPL_H_

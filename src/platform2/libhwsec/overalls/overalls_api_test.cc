// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec/overalls/overalls_api.h"

#include <gtest/gtest.h>

#include "libhwsec/overalls/overalls_singleton.h"

namespace hwsec {

TEST(OverallsApiTest, GetOveralls) {
  overalls::Overalls* const expected_instance =
      overalls::OverallsSingleton::GetInstance();
  overalls::Overalls* const result_instance = overalls::GetOveralls();
  EXPECT_EQ(result_instance, expected_instance);
}

}  // namespace hwsec

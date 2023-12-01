// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec/overalls/overalls_singleton.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace {

using ::testing::NotNull;

}  // namespace

namespace hwsec {

TEST(OverallsSingletonTest, GetInstanceNotNull) {
  overalls::Overalls* const instance =
      overalls::OverallsSingleton::GetInstance();
  EXPECT_THAT(instance, NotNull());
}

// Tests if the instance calls |trousers|; it is not a complete proof that the
// defualt instanace callls |trousers| just comparing the return values; however
// it is still a strong evidence.
TEST(OverallsSingletonTest, SamebehaviorAsTrousers) {
  overalls::Overalls* const instance =
      overalls::OverallsSingleton::GetInstance();
  EXPECT_EQ(instance->Ospi_Context_Connect(0, 0), Tspi_Context_Connect(0, 0));
}

TEST(OverallsSingletonTest, SetInstance) {
  overalls::Overalls* const instance =
      overalls::OverallsSingleton::GetInstance();
  overalls::Overalls local_object;
  EXPECT_EQ(instance, overalls::OverallsSingleton::SetInstance(&local_object));
  EXPECT_EQ(&local_object, overalls::OverallsSingleton::GetInstance());

  // Replicates the same step so the original instance is restored.
  EXPECT_EQ(&local_object, overalls::OverallsSingleton::SetInstance(instance));
  EXPECT_EQ(instance, overalls::OverallsSingleton::GetInstance());
}

}  // namespace hwsec

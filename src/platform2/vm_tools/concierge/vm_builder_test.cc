// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/concierge/vm_builder.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace vm_tools::concierge {

TEST(VmBuilderTest, DefaultValuesSucceeds) {
  VmBuilder builder;
  EXPECT_FALSE(builder.BuildVmArgs().empty());
}

}  // namespace vm_tools::concierge

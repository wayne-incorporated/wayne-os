// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gtest/gtest.h>

#include "diagnostics/dpsl/internal/dpsl_global_context_impl.h"
#include "diagnostics/dpsl/public/dpsl_global_context.h"

namespace diagnostics {
namespace {

class DpslGlobalContextImplDeathTest : public testing::Test {
 public:
  ~DpslGlobalContextImplDeathTest() override {
    DpslGlobalContextImpl::CleanGlobalCounterForTesting();
  }
};

TEST_F(DpslGlobalContextImplDeathTest, CreateAndForget) {
  ASSERT_TRUE(DpslGlobalContext::Create());

  ASSERT_DEATH(DpslGlobalContext::Create(),
               "Duplicate DpslGlobalContext instances");
}

TEST_F(DpslGlobalContextImplDeathTest, CreateAndSave) {
  auto context = DpslGlobalContext::Create();
  ASSERT_TRUE(context);

  ASSERT_DEATH(DpslGlobalContext::Create(),
               "Duplicate DpslGlobalContext instances");
}

}  // namespace
}  // namespace diagnostics

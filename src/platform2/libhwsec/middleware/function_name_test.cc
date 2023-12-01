// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec/middleware/function_name.h"

#include <type_traits>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <libhwsec-foundation/error/testing_helper.h>

#include "libhwsec/backend/key_management.h"
#include "libhwsec/backend/state.h"

namespace {

int AnonymousFunction(int x) {
  return x;
}

}  // namespace

namespace hwsec {

using ::hwsec_foundation::error::testing::IsOk;
using ::hwsec_foundation::error::testing::NotOk;
using ::hwsec_foundation::status::MakeStatus;
using ::hwsec_foundation::status::StatusChain;

using FunctionNameTest = ::testing::Test;

namespace {

int AnonymousFunction2(int x) {
  return x;
}

}  // namespace

static void TestFunction() {}
static auto MagicTestLambda = []() {};

TEST_F(FunctionNameTest, HwsecFunctionName) {
  EXPECT_EQ(GetFuncName<&KeyManagement::LoadKey>(),
            "hwsec::KeyManagement::LoadKey");
  EXPECT_EQ(GetFuncName<&KeyManagement::Flush>(),
            "hwsec::KeyManagement::Flush");
  EXPECT_EQ(GetFuncName<&State::IsReady>(), "hwsec::State::IsReady");
  EXPECT_EQ(GetFuncName<&State::IsEnabled>(), "hwsec::State::IsEnabled");
  EXPECT_EQ(GetFuncName<&TestFunction>(), "hwsec::TestFunction");
}

TEST_F(FunctionNameTest, AnonymousFunctionName) {
  EXPECT_EQ(GetFuncName<&AnonymousFunction>(),
            "(anonymous namespace)::AnonymousFunction");
  EXPECT_EQ(GetFuncName<&AnonymousFunction2>(),
            "hwsec::(anonymous namespace)::AnonymousFunction2");
}

TEST_F(FunctionNameTest, LambdaFunctionName) {
  EXPECT_EQ(GetFuncName<&MagicTestLambda>(), "hwsec::MagicTestLambda");
}

}  // namespace hwsec

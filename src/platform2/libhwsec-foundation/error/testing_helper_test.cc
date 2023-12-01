// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec-foundation/error/testing_helper.h"
#include "libhwsec-foundation/status/status_chain.h"
#include "libhwsec-foundation/status/status_chain_macros.h"
#include "libhwsec-foundation/status/status_chain_or.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

using hwsec_foundation::error::testing::IsOk;
using hwsec_foundation::error::testing::IsOkAnd;
using hwsec_foundation::error::testing::IsOkAndHolds;
using hwsec_foundation::error::testing::NotOk;
using hwsec_foundation::error::testing::NotOkAnd;
using hwsec_foundation::error::testing::NotOkWith;
using testing::Eq;
using testing::Ge;

namespace hwsec_foundation::status {

namespace {

// Error definitions.

enum class ErrorCode {
  kErrorA,
  kErrorB,
  kErrorC,
};

class FakeError : public Error {
 public:
  using MakeStatusTrait = DefaultMakeStatus<FakeError>;
  using BaseErrorType = FakeError;

  FakeError(std::string message, ErrorCode code)
      : Error(message), code_(code) {}
  ~FakeError() override {}

  std::string ToString() const override {
    return "FakeError: " + Error::ToString();
  }

  ErrorCode code() const { return code_; }

 protected:
  ErrorCode code_;
};

using Status = StatusChain<FakeError>;

template <typename Type>
using StatusOr = StatusChainOr<Type, FakeError>;

// Target function.

StatusOr<int> Calc(int x) {
  if (x == 0) {
    return MakeStatus<FakeError>("Input zero", ErrorCode::kErrorA);
  }
  if (x < 0) {
    return MakeStatus<FakeError>("Negative Input", ErrorCode::kErrorB);
  }
  return x * x;
}

// Testing code.

class ErrorTestingHelperTest : public ::testing::Test {};

MATCHER_P(HasErrorCode, matcher, "") {
  if (arg.ok()) {
    return false;
  }
  return ExplainMatchResult(matcher, arg->code(), result_listener);
}

TEST_F(ErrorTestingHelperTest, IsOk) {
  StatusOr<int> result = Calc(1);
  ASSERT_OK(result);
  EXPECT_EQ(result.value(), 1);

  EXPECT_THAT(Calc(5), IsOkAndHolds(5 * 5));
  EXPECT_THAT(Calc(123), IsOkAndHolds(123 * 123));
  EXPECT_THAT(Calc(123), IsOkAnd(Ge(10000)));
}

TEST_F(ErrorTestingHelperTest, NotOk) {
  EXPECT_THAT(Calc(0), NotOk());
  EXPECT_THAT(Calc(-5), NotOk());
  EXPECT_THAT(Calc(0), NotOkWith("Input zero"));
  EXPECT_THAT(Calc(-10), NotOkWith("Negative Input"));
  EXPECT_THAT(Calc(0), NotOkAnd(HasErrorCode(Eq(ErrorCode::kErrorA))));
  EXPECT_THAT(Calc(-1), NotOkAnd(HasErrorCode(Eq(ErrorCode::kErrorB))));
}

}  // namespace

}  // namespace hwsec_foundation::status

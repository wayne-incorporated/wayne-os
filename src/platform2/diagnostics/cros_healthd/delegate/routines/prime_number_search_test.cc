// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstdint>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "diagnostics/cros_healthd/delegate/routines/prime_number_search.h"

namespace diagnostics {
namespace {

using ::testing::Return;

class MockPrimeNumberSearchTest : public PrimeNumberSearchDelegate {
 public:
  explicit MockPrimeNumberSearchTest(uint64_t max_num)
      : PrimeNumberSearchDelegate(max_num) {}
  MockPrimeNumberSearchTest(const MockPrimeNumberSearchTest&) = delete;
  MockPrimeNumberSearchTest& operator=(const MockPrimeNumberSearchTest&) =
      delete;
  ~MockPrimeNumberSearchTest() {}

  MOCK_METHOD(bool, IsPrime, (uint64_t num), (const, override));
};

// Tests if different numbers are prime by using the IsPrime() calculation.
TEST(PrimeNumberSearchTest, IsPrime) {
  PrimeNumberSearchDelegate prime_search(4);

  EXPECT_FALSE(prime_search.IsPrime(0));
  EXPECT_FALSE(prime_search.IsPrime(1));
  EXPECT_TRUE(prime_search.IsPrime(2));
  EXPECT_TRUE(prime_search.IsPrime(3));
  EXPECT_FALSE(prime_search.IsPrime(4));
  EXPECT_TRUE(prime_search.IsPrime(5));
  EXPECT_TRUE(prime_search.IsPrime(999983));
  EXPECT_FALSE(prime_search.IsPrime(999984));
  EXPECT_TRUE(prime_search.IsPrime(360289));
  EXPECT_FALSE(prime_search.IsPrime(360290));
  EXPECT_TRUE(prime_search.IsPrime(122477));
  EXPECT_FALSE(prime_search.IsPrime(122478));
  EXPECT_TRUE(prime_search.IsPrime(828587));
  EXPECT_FALSE(prime_search.IsPrime(828588));
  EXPECT_TRUE(prime_search.IsPrime(87119));
  EXPECT_FALSE(prime_search.IsPrime(87120));
}

// Test that all values under kMaxPrimeNumber are calculated correctly.
TEST(PrimeNumbersSearchTest, RunFull) {
  PrimeNumberSearchDelegate prime_search(
      PrimeNumberSearchDelegate::kMaxPrimeNumber);
  EXPECT_TRUE(prime_search.Run());
}

// Test Run() returns true when IsPrime() calculates
// correctly.
TEST(PrimeNumberSearchTest, RunPass) {
  MockPrimeNumberSearchTest prime_search(8);

  EXPECT_CALL(prime_search, IsPrime(2)).WillOnce(Return(true));
  EXPECT_CALL(prime_search, IsPrime(3)).WillOnce(Return(true));
  EXPECT_CALL(prime_search, IsPrime(4)).WillOnce(Return(false));
  EXPECT_CALL(prime_search, IsPrime(5)).WillOnce(Return(true));
  EXPECT_CALL(prime_search, IsPrime(6)).WillOnce(Return(false));
  EXPECT_CALL(prime_search, IsPrime(7)).WillOnce(Return(true));
  EXPECT_CALL(prime_search, IsPrime(8)).WillOnce(Return(false));

  EXPECT_TRUE(prime_search.Run());
}

// Test Run() returns false when IsPrime() miscalculates a prime number as
// nonprime.
TEST(PrimeNumberSearchTest,
     RunFailUnexpectedPrimeNumberFollowedWithNoMorePrime) {
  MockPrimeNumberSearchTest prime_search(6);

  EXPECT_CALL(prime_search, IsPrime(2)).WillOnce(Return(true));
  EXPECT_CALL(prime_search, IsPrime(3)).WillOnce(Return(true));
  EXPECT_CALL(prime_search, IsPrime(4)).WillOnce(Return(false));
  // 5 should be prime number and is miscalcuated here.
  EXPECT_CALL(prime_search, IsPrime(5)).WillOnce(Return(false));

  EXPECT_FALSE(prime_search.Run());
}

}  // namespace
}  // namespace diagnostics

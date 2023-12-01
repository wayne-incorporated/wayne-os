// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Unit tests for SecureString.

#include "brillo/secure_string.h"

#include <array>
#include <cstring>
#include <limits>
#include <string>
#include <vector>

#include <base/timer/lap_timer.h>
#include <gtest/gtest.h>

namespace brillo {

static constexpr char str1[] = "abc";
static constexpr char str2[] = "def";
static constexpr char str3[] = "abc";

static_assert(static_cast<const char*>(str1) != static_cast<const char*>(str3),
              "The strings should have different addresses");

TEST(SecureClearBytes, SecureClearBytes) {
  std::vector<uint8_t> input = {0xFF, 0xFF, 0xFF};
  SecureClearBytes(input.data(), input.size());
  EXPECT_EQ(input, std::vector<uint8_t>({0x00, 0x00, 0x00}));
}

TEST(SecureClearContainer, SecureClearVector) {
  std::vector<uint8_t> input = {0xFF, 0xFF, 0xFF};
  SecureClearContainer(input);
  EXPECT_EQ(input, std::vector<uint8_t>({0x00, 0x00, 0x00}));
}

TEST(SecureClearContainer, SecureClearVectorUint16) {
  std::vector<uint16_t> input = {0xFFFF, 0xFFFF, 0xFFFF};
  SecureClearContainer(input);
  EXPECT_EQ(input, std::vector<uint16_t>({0x0000, 0x0000, 0x0000}));
}

TEST(SecureClearContainer, SecureClearArray) {
  std::array<uint8_t, 3> input = {0xFF, 0xFF, 0xFF};
  SecureClearContainer(input);
  EXPECT_EQ(input, (std::array<uint8_t, 3>{0x00, 0x00, 0x00}));
}

TEST(SecureClearContainer, SecureClearCStyleArray) {
  uint8_t input[3] = {0xFF, 0xFF, 0xFF};
  constexpr uint8_t kExpected[3] = {0x00, 0x00, 0x00};
  SecureClearContainer(input);
  for (int i = 0; i < sizeof(kExpected); i++) {
    EXPECT_EQ(input[i], kExpected[i]);
  }
}

TEST(SecureClearContainer, SecureClearString) {
  std::string input = "abc";
  EXPECT_EQ(input.size(), 3);
  SecureClearContainer(input);
  // string has three NULs (plus terminating NUL)
  EXPECT_EQ(input, std::string({0, 0, 0}));
}

TEST(SecureClearObject, SecureClearObject) {
  struct TestObj {
    int a = 0xFF;
    int b = 0xFF;
  };

  struct TestObj input;
  SecureClearObject(input);

  TestObj kExpected;
  memset(&kExpected, 0, sizeof(kExpected));

  EXPECT_EQ(memcmp(&kExpected, &input, sizeof(kExpected)), 0);
}

TEST(SecureClearObject, SecureClearScalarObject) {
  int scalar = std::numeric_limits<int>::max();
  constexpr int kExpected = 0;

  SecureClearObject(scalar);

  EXPECT_EQ(scalar, kExpected);
}

TEST(SecureMemcmp, Zero_Size) {
  EXPECT_EQ(SecureMemcmp(nullptr, nullptr, 0), 0);

  // memcmp has the first two arguments marked as non-null:
  // https://sourceware.org/git/?p=glibc.git;a=blob;f=string/string.h;h=b0be00c0f703ae7014fa7c424bfa8767edc500ca;hb=HEAD#l64
  // so we need to disable the warning in order to pass nullptr arguments to
  // it. Otherwise this will fail to compile.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnonnull"
  EXPECT_EQ(memcmp(nullptr, nullptr, 0), 0);
#pragma clang diagnostic pop
}

TEST(SecureMemcmp, Different) {
  // The return value for this differs than memcmp, which will return a
  // negative value.
  EXPECT_EQ(SecureMemcmp(str1, str2, sizeof(str1)), 1);
  EXPECT_LT(std::memcmp(str1, str2, sizeof(str1)), 0);

  // memcmp will return a positive value.
  EXPECT_EQ(SecureMemcmp(str2, str1, sizeof(str1)), 1);
  EXPECT_GT(std::memcmp(str2, str1, sizeof(str1)), 0);
}

TEST(SecureMemcmp, Same) {
  EXPECT_EQ(SecureMemcmp(str1, str3, sizeof(str1)), 0);
  EXPECT_EQ(std::memcmp(str1, str3, sizeof(str1)), 0);
}

// Even when increasing kAbsoluteError to 0.25, this test flakes too much when
// run on the CQ: https://crrev.com/c/2427403. It should pass if you enable and
// run it locally.
TEST(SecureMemcmp, DISABLED_ConstantTime) {
  // Compare two large vectors that are completely different (0x00 and 0xFF)
  // The "secure" comparison should take roughly the same amount of time for
  // both, as opposed to exiting early on the first byte.
  // Caveats: different compilation flags (e.g., around optimizations) may
  // significantly change the behavior of the "secure" version, so the fact
  // that this test passes in the testing environment does not guarantee that
  // it behaves the same in a release build (or different architectures /
  // compilers).

  constexpr double kAbsoluteError = 0.01;
  constexpr size_t kBufSizeBytes = 1000;
  std::vector<uint8_t> all_zero(kBufSizeBytes, 0x00);
  std::vector<uint8_t> all_one(kBufSizeBytes, 0xFF);
  int memcmp_ret = 0;

  base::LapTimer timer_different_data(
      base::LapTimer::TimerMethod::kUseThreadTicks);
  do {
    memcmp_ret = SecureMemcmp(all_zero.data(), all_one.data(), all_zero.size());
    timer_different_data.NextLap();
  } while (!timer_different_data.HasTimeLimitExpired());
  EXPECT_EQ(memcmp_ret, 1);

  base::LapTimer timer_same_data(base::LapTimer::TimerMethod::kUseThreadTicks);
  do {
    memcmp_ret =
        SecureMemcmp(all_zero.data(), all_zero.data(), all_zero.size());
    timer_same_data.NextLap();
  } while (!timer_same_data.HasTimeLimitExpired());
  EXPECT_EQ(memcmp_ret, 0);

  double lap_ratio = static_cast<double>(timer_same_data.NumLaps()) /
                     static_cast<double>(timer_different_data.NumLaps());
  EXPECT_NEAR(lap_ratio, 1.0, kAbsoluteError);
}

}  // namespace brillo

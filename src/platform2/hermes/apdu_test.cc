// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "hermes/apdu.h"

#include <cstdint>
#include <type_traits>
#include <utility>
#include <vector>

#include <base/logging.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

using ::testing::_;
using ::testing::ElementsAreArray;

namespace hermes {

// The ToVector functions create a single vector<uint8_t> given a list of
// integers and vector<uint8_t>s of any amount.
std::vector<uint8_t> ToVector() {
  return std::vector<uint8_t>();
}

template <typename T>
std::vector<uint8_t> ToVector(T v) {
  return std::vector<uint8_t>{static_cast<uint8_t>(v)};
}

std::vector<uint8_t> ToVector(std::vector<uint8_t> v) {
  return v;
}

template <typename T, typename... Args>
std::vector<uint8_t> ToVector(T&& first, Args&&... args) {
  std::vector<uint8_t> head = ToVector(std::forward<T>(first));
  std::vector<uint8_t> tail = ToVector(std::forward<Args>(args)...);
  head.insert(head.end(), tail.begin(), tail.end());
  return head;
}

// Expect the value of the next fragment.
//
// The first parameter is the CommandApdu. Futher parameters can be any number
// of integers (which will all be cast to uint8_ts) and vector<uint8_t>s, in
// any order.
//
// Note that by making EXPECT_FRAGMENT a macro, failures will report the actual
// line number within the test that caused the failure. If this were a function,
// failures would point to the line number within EXPECT_FRAGMENT, which is much
// less informative.
#define EXPECT_FRAGMENT(apdu, ...)                                       \
  do {                                                                   \
    uint8_t* fragment;                                                   \
    size_t fragment_len = apdu.GetNextFragment(&fragment);               \
    EXPECT_NE(fragment, nullptr);                                        \
    EXPECT_THAT(std::vector<uint8_t>(fragment, fragment + fragment_len), \
                ElementsAreArray(ToVector(__VA_ARGS__)));                \
  } while (0)

///////////////
// Constants //
///////////////

const std::vector<uint8_t> kHeaderStart =
    ToVector(CLA_STORE_DATA, INS_STORE_DATA);

constexpr uint16_t kShortLe = 18;
constexpr uint16_t kLongLe = 1800;

//////////////////////////
// Command APDU: Case 1 //
//////////////////////////

TEST(CommandCase1, Standard) {
  CommandApdu cmd(CLA_STORE_DATA, INS_STORE_DATA, false, 0);
  EXPECT_FRAGMENT(cmd, kHeaderStart, kApduP1LastBlock, 0);
  EXPECT_FALSE(cmd.HasMoreFragments());
}

TEST(CommandCase1, Extended) {
  CommandApdu cmd(CLA_STORE_DATA, INS_STORE_DATA, true, 0);
  EXPECT_FRAGMENT(cmd, kHeaderStart, kApduP1LastBlock, 0);
  EXPECT_FALSE(cmd.HasMoreFragments());
}

//////////////////////////
// Command APDU: Case 2 //
//////////////////////////

TEST(CommandCase2, StandardWithShortLe) {
  CommandApdu cmd(CLA_STORE_DATA, INS_STORE_DATA, false, kShortLe);
  EXPECT_FRAGMENT(cmd, kHeaderStart, kApduP1LastBlock, 0,
                  static_cast<uint8_t>(kShortLe));
  EXPECT_FALSE(cmd.HasMoreFragments());
}

TEST(CommandCase2, StandardWithLongLe) {
  CommandApdu cmd(CLA_STORE_DATA, INS_STORE_DATA, false, kLongLe);
  // Le field should be set to 0 (Ne=256)
  EXPECT_FRAGMENT(cmd, kHeaderStart, kApduP1LastBlock, 0, 0);
  EXPECT_FALSE(cmd.HasMoreFragments());
}

TEST(CommandCase2, ExtendedWithShortLe) {
  CommandApdu cmd(CLA_STORE_DATA, INS_STORE_DATA, true, kShortLe);
  EXPECT_FRAGMENT(cmd,
                  // Header
                  kHeaderStart, kApduP1LastBlock, 0,
                  // Extended Le field
                  0, static_cast<uint8_t>(kShortLe), 0);
  EXPECT_FALSE(cmd.HasMoreFragments());
}

TEST(CommandCase2, ExtendedWithLongLe) {
  CommandApdu cmd(CLA_STORE_DATA, INS_STORE_DATA, true, kLongLe);
  EXPECT_FRAGMENT(cmd,
                  // Header
                  kHeaderStart, kApduP1LastBlock, 0,
                  // Extended Le field
                  0, static_cast<uint8_t>(kLongLe),
                  static_cast<uint8_t>(kLongLe >> 8));
  EXPECT_FALSE(cmd.HasMoreFragments());
}

//////////////////////////
// Command APDU: Case 3 //
//////////////////////////

TEST(CommandCase3, StandardNoFragment) {
  CommandApdu cmd(CLA_STORE_DATA, INS_STORE_DATA, false, 0);
  std::vector<uint8_t> data = ToVector(1, 2, 3);
  cmd.AddData(data);
  EXPECT_FRAGMENT(cmd, kHeaderStart, kApduP1LastBlock, 0, data.size(), data);
  EXPECT_FALSE(cmd.HasMoreFragments());
}

TEST(CommandCase3, StandardTwoFragments) {
  CommandApdu cmd(CLA_STORE_DATA, INS_STORE_DATA, false, 0);
  std::vector<uint8_t> data;
  for (int i = 0; i < 300; ++i) {
    data.push_back(static_cast<uint8_t>(i));
  }
  cmd.AddData(data);
  // Data should be fragmented between 255 and 45 bytes
  EXPECT_FRAGMENT(cmd, kHeaderStart, kApduP1MoreBlocks, 0, 255,
                  std::vector<uint8_t>(data.begin(), data.begin() + 255));
  EXPECT_FRAGMENT(cmd, kHeaderStart, kApduP1LastBlock, 1, 45,
                  std::vector<uint8_t>(data.begin() + 255, data.end()));
  EXPECT_FALSE(cmd.HasMoreFragments());
}

TEST(CommandCase3, ExtendedNoFragmentShort) {
  CommandApdu cmd(CLA_STORE_DATA, INS_STORE_DATA, true, 0);
  std::vector<uint8_t> data = ToVector(1, 2, 3);
  cmd.AddData(data);
  EXPECT_FRAGMENT(cmd,
                  // Header
                  kHeaderStart, kApduP1LastBlock, 0, 0, data.size(), 0, data);
  EXPECT_FALSE(cmd.HasMoreFragments());
}

TEST(CommandCase3, ExtendedNoFragmentLong) {
  CommandApdu cmd(CLA_STORE_DATA, INS_STORE_DATA, true, 0);
  size_t data_len = 20000;
  std::vector<uint8_t> data;
  for (size_t i = 0; i < data_len; ++i) {
    data.push_back(static_cast<uint8_t>(i));
  }
  cmd.AddData(data);
  EXPECT_FRAGMENT(cmd,
                  // Header
                  kHeaderStart, kApduP1LastBlock, 0, 0, data_len & 0xFF,
                  data_len >> 8, data);
  EXPECT_FALSE(cmd.HasMoreFragments());
}

TEST(CommandCase3, ExtendedTwoFragments) {
  CommandApdu cmd(CLA_STORE_DATA, INS_STORE_DATA, true, 0);
  size_t data_len = 40000;
  std::vector<uint8_t> data;
  for (size_t i = 0; i < data_len; ++i) {
    data.push_back(static_cast<uint8_t>(i));
  }
  cmd.AddData(data);
  size_t frag_len = 32767;
  EXPECT_FRAGMENT(cmd,
                  // Header
                  kHeaderStart, kApduP1MoreBlocks, 0, 0, frag_len & 0xFF,
                  frag_len >> 8,
                  std::vector<uint8_t>(data.begin(), data.begin() + frag_len));
  frag_len = data_len - frag_len;
  EXPECT_FRAGMENT(cmd,
                  // Header
                  kHeaderStart, kApduP1LastBlock, 1, 0, frag_len & 0xFF,
                  frag_len >> 8,
                  std::vector<uint8_t>(data.begin() + 32767, data.end()));
  EXPECT_FALSE(cmd.HasMoreFragments());
}

//////////////////////////
// Command APDU: Case 4 //
//////////////////////////

TEST(CommandCase4, StandardNoFragmentShortLe) {
  CommandApdu cmd(CLA_STORE_DATA, INS_STORE_DATA, false, kShortLe);
  std::vector<uint8_t> data = ToVector(1, 2, 3);
  cmd.AddData(data);
  EXPECT_FRAGMENT(cmd, kHeaderStart, kApduP1LastBlock, 0, data.size(), data,
                  kShortLe);
  EXPECT_FALSE(cmd.HasMoreFragments());
}

TEST(CommandCase4, StandardTwoFragmentsShortLe) {
  CommandApdu cmd(CLA_STORE_DATA, INS_STORE_DATA, false, kShortLe);
  std::vector<uint8_t> data;
  for (int i = 0; i < 300; ++i) {
    data.push_back(static_cast<uint8_t>(i));
  }
  cmd.AddData(data);
  // Data should be fragmented between 255 and 45 bytes with no Le in the first
  // fragment
  EXPECT_FRAGMENT(cmd, kHeaderStart, kApduP1MoreBlocks, 0, 255,
                  std::vector<uint8_t>(data.begin(), data.begin() + 255));
  EXPECT_FRAGMENT(cmd, kHeaderStart, kApduP1LastBlock, 1, 45,
                  std::vector<uint8_t>(data.begin() + 255, data.end()),
                  kShortLe);
  EXPECT_FALSE(cmd.HasMoreFragments());
}

TEST(CommandCase4, StandardNoFragmentLongLe) {
  CommandApdu cmd(CLA_STORE_DATA, INS_STORE_DATA, false, kLongLe);
  std::vector<uint8_t> data = ToVector(1, 2, 3);
  cmd.AddData(data);
  EXPECT_FRAGMENT(cmd, kHeaderStart, kApduP1LastBlock, 0, data.size(), data,
                  256);
  EXPECT_FALSE(cmd.HasMoreFragments());
}

TEST(CommandCase4, StandardTwoFragmentsLongLe) {
  CommandApdu cmd(CLA_STORE_DATA, INS_STORE_DATA, false, kLongLe);
  std::vector<uint8_t> data;
  for (int i = 0; i < 300; ++i) {
    data.push_back(static_cast<uint8_t>(i));
  }
  cmd.AddData(data);
  // Data should be fragmented between 255 and 45 bytes with no Le in the first
  // fragment
  EXPECT_FRAGMENT(cmd, kHeaderStart, kApduP1MoreBlocks, 0, 255,
                  std::vector<uint8_t>(data.begin(), data.begin() + 255));
  EXPECT_FRAGMENT(cmd, kHeaderStart, kApduP1LastBlock, 1, 45,
                  std::vector<uint8_t>(data.begin() + 255, data.end()), 256);
  EXPECT_FALSE(cmd.HasMoreFragments());
}

TEST(CommandCase4, ExtendedNoFragmentShortLe) {
  CommandApdu cmd(CLA_STORE_DATA, INS_STORE_DATA, true, kShortLe);
  std::vector<uint8_t> data = ToVector(1, 2, 3);
  cmd.AddData(data);
  EXPECT_FRAGMENT(cmd,
                  // Header
                  kHeaderStart, kApduP1LastBlock, 0, 0, data.size(), 0, data, 0,
                  kShortLe, 0);
  EXPECT_FALSE(cmd.HasMoreFragments());
}

TEST(CommandCase4, ExtendedNoFragmentLongLe) {
  CommandApdu cmd(CLA_STORE_DATA, INS_STORE_DATA, true, kLongLe);
  size_t data_len = 20000;
  std::vector<uint8_t> data;
  for (size_t i = 0; i < data_len; ++i) {
    data.push_back(static_cast<uint8_t>(i));
  }
  cmd.AddData(data);
  EXPECT_FRAGMENT(cmd,
                  // Header
                  kHeaderStart, kApduP1LastBlock, 0, 0, data_len & 0xFF,
                  data_len >> 8, data, 0, kLongLe & 0xFF, kLongLe >> 8);
  EXPECT_FALSE(cmd.HasMoreFragments());
}

TEST(CommandCase4, ExtendedTwoFragmentsShortLe) {
  CommandApdu cmd(CLA_STORE_DATA, INS_STORE_DATA, true, kShortLe);
  size_t data_len = 40000;
  std::vector<uint8_t> data;
  for (size_t i = 0; i < data_len; ++i) {
    data.push_back(static_cast<uint8_t>(i));
  }
  cmd.AddData(data);
  size_t frag_len = 32767;
  EXPECT_FRAGMENT(cmd,
                  // Header
                  kHeaderStart, kApduP1MoreBlocks, 0, 0, frag_len & 0xFF,
                  frag_len >> 8,
                  std::vector<uint8_t>(data.begin(), data.begin() + frag_len));
  frag_len = data_len - frag_len;
  EXPECT_FRAGMENT(
      cmd,
      // Header
      kHeaderStart, kApduP1LastBlock, 1, 0, frag_len & 0xFF, frag_len >> 8,
      std::vector<uint8_t>(data.begin() + 32767, data.end()), 0, kShortLe, 0);
  EXPECT_FALSE(cmd.HasMoreFragments());
}

TEST(CommandCase4, ExtendedTwoFragmentsLongLe) {
  CommandApdu cmd(CLA_STORE_DATA, INS_STORE_DATA, true, kLongLe);
  size_t data_len = 40000;
  std::vector<uint8_t> data;
  for (size_t i = 0; i < data_len; ++i) {
    data.push_back(static_cast<uint8_t>(i));
  }
  cmd.AddData(data);
  size_t frag_len = 32767;
  EXPECT_FRAGMENT(cmd,
                  // Header
                  kHeaderStart, kApduP1MoreBlocks, 0, 0, frag_len & 0xFF,
                  frag_len >> 8,
                  std::vector<uint8_t>(data.begin(), data.begin() + frag_len));
  frag_len = data_len - frag_len;
  EXPECT_FRAGMENT(cmd,
                  // Header
                  kHeaderStart, kApduP1LastBlock, 1, 0, frag_len & 0xFF,
                  frag_len >> 8,
                  std::vector<uint8_t>(data.begin() + 32767, data.end()), 0,
                  kLongLe & 0xFF, kLongLe >> 8);
  EXPECT_FALSE(cmd.HasMoreFragments());
}

}  // namespace hermes

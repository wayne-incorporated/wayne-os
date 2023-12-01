// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>
#include <stdlib.h>
#include <string>

#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <gtest/gtest.h>

#include "libbrillo/brillo/hash/MurmurHash3.h"

namespace brillo {

namespace {

class MurmurHashTest : public ::testing::Test {
 protected:
  void TestMurmurHash3x8632(std::string input, uint32_t seed, uint32_t out) {
    LOG(INFO) << "Testng MurmurHash3_x86_32("
              << base::HexEncode(input.data(), input.size()) << ", " << seed
              << ", " << out << ")";

    // Requires 1 extra byte because we need to test unaligned access.
    // Note that malloc() will return aligned memory for input.size() that is
    // large enough that alignment matters.
    uint8_t* buffer = static_cast<uint8_t*>(malloc(input.size() + 1));

    // Test the usual aligned access.
    if (input.size()) {
      memcpy(buffer, input.data(), input.size());
    }
    // Set to incorrect value so that no-op on result will fail.
    uint32_t result = out + 1;
    MurmurHash3_x86_32(buffer, input.size(), seed, &result);
    EXPECT_EQ(result, out);

    // Test unaligned access.
    if (input.size()) {
      memcpy(buffer + 1, input.data(), input.size());
    }
    result = out + 1;
    MurmurHash3_x86_32(buffer + 1, input.size(), seed, &result);
    EXPECT_EQ(result, out);

    free(buffer);
  }
};

TEST_F(MurmurHashTest, TestVectors) {
  TestMurmurHash3x8632(std::string("", 0), 0, 0);
  TestMurmurHash3x8632(std::string("", 0), 1, 0x514E28B7);
  TestMurmurHash3x8632(std::string("", 0), 0xFFFFFFFF, 0x81F16F39);
  TestMurmurHash3x8632(std::string("\xFF\xFF\xFF\xFF", 4), 0, 0x76293B50);
  TestMurmurHash3x8632(std::string("\x21\x43\x65\x87", 4), 0, 0xF55B516B);
  TestMurmurHash3x8632(std::string("\x21\x43\x65\x87", 4), 0x5082EDEE,
                       0x2362F9DE);
  TestMurmurHash3x8632(std::string("\x21\x43\x65", 3), 0, 0x7E4A8634);
  TestMurmurHash3x8632(std::string("\x21\x43", 2), 0, 0xA0F7B07A);
  TestMurmurHash3x8632(std::string("\x21", 1), 0, 0x72661CF4);
  TestMurmurHash3x8632(std::string("\0\0\0\0", 4), 0, 0x2362F9DE);
  TestMurmurHash3x8632(std::string("\0\0\0", 3), 0, 0x85F0B427);
  TestMurmurHash3x8632(std::string("\0\0", 2), 0, 0x30F4C306);
  TestMurmurHash3x8632(std::string("\0", 1), 0, 0x514E28B7);
  TestMurmurHash3x8632(
      std::string("The quick brown fox jumps over the lazy dog", 43),
      0xBAADF00D, 0x70740512);
}

}  // namespace

}  // namespace brillo

// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <optional>
#include <string_view>

#include <gtest/gtest.h>

// Ensure that VCSID is set.
// This mimics the behavior of CROS_WORKON_USE_VCSID being set.
#ifdef VCSID
#undef VCSID
#endif
#define VCSID "0.0.1-r2004-67ec4c03828a50c2b8cacba45c0cf5f9b4f2ff34"
#include <brillo/vcsid.h>

namespace brillo {

TEST(VCSIDTest, kVCSID_Set) {
  EXPECT_TRUE(brillo::kVCSID);
  EXPECT_EQ(*brillo::kVCSID,
            "0.0.1-r2004-67ec4c03828a50c2b8cacba45c0cf5f9b4f2ff34");
}

TEST(VCSIDTest, kShortVCSID_Set) {
  EXPECT_TRUE(brillo::kShortVCSID);
  EXPECT_EQ(*brillo::kShortVCSID, "0.0.1-r2004-67ec4c0382");
}

TEST(VCSIDInternalTest, IsSha1HexString) {
  // Check a blank string.
  EXPECT_FALSE(vcsid_internal::IsSHA1HexString(""));
  // Check an undersized hex string.
  EXPECT_FALSE(vcsid_internal::IsSHA1HexString("0"));
  // Check an oversized hex string.
  EXPECT_FALSE(vcsid_internal::IsSHA1HexString(
      "01234567890123456789012345678901234567890"));
  // Check a properly sized string with a non-hex character.
  EXPECT_FALSE(vcsid_internal::IsSHA1HexString(
      "012345678901234567890123456789012345678z"));
  // Check a proper SHA1 hex string.
  EXPECT_TRUE(vcsid_internal::IsSHA1HexString(
      "0123456789012345678901234567ABCDEFabcdef"));
}

TEST(VCSIDInternalTest, IsValidVCSID) {
  EXPECT_FALSE(vcsid_internal::IsValidVCSID(""));
  EXPECT_FALSE(vcsid_internal::IsValidVCSID("0"));

  EXPECT_FALSE(vcsid_internal::IsValidVCSID("0-0"));
  EXPECT_FALSE(vcsid_internal::IsValidVCSID("0-67ec4c0382"));
  EXPECT_TRUE(vcsid_internal::IsValidVCSID(
      "0-67ec4c03828a50c2b8cacba45c0cf5f9b4f2ff34"));
  EXPECT_TRUE(vcsid_internal::IsValidVCSID(
      "9999-67ec4c03828a50c2b8cacba45c0cf5f9b4f2ff34"));

  EXPECT_FALSE(vcsid_internal::IsValidVCSID("0-0-0"));
  EXPECT_FALSE(vcsid_internal::IsValidVCSID("0-0-67ec4c0382"));
  EXPECT_TRUE(vcsid_internal::IsValidVCSID(
      "0-0-67ec4c03828a50c2b8cacba45c0cf5f9b4f2ff34"));
  EXPECT_TRUE(vcsid_internal::IsValidVCSID(
      "0.0.0-r0-67ec4c03828a50c2b8cacba45c0cf5f9b4f2ff34"));

  EXPECT_FALSE(vcsid_internal::IsValidVCSID(
      "0-0-67ec4c03828a50c2b8cacba45c0cf5f9b4f2ff34-0"));
}

TEST(VCSIDInternalTest, ShortenVCSID) {
  EXPECT_EQ(brillo::vcsid_internal::ShortenVCSID(
                "0.0.0-r0-67ec4c03828a50c2b8cacba45c0cf5f9b4f2ff34"),
            "0.0.0-r0-67ec4c0382");
  EXPECT_EQ(brillo::vcsid_internal::ShortenVCSID(
                "9999-67ec4c03828a50c2b8cacba45c0cf5f9b4f2ff34"),
            "9999-67ec4c0382");
}

}  // namespace brillo

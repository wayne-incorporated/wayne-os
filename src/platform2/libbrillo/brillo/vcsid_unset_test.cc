// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <optional>
#include <string_view>

#include <gtest/gtest.h>

// Ensure that VCSID is unset.
// This mimics the behavior of CROS_WORKON_USE_VCSID not being set.
#ifdef VCSID
#undef VCSID
#endif
#include <brillo/vcsid.h>

namespace brillo {

TEST(VCSIDTest, GetVCSID_Unset) {
  EXPECT_FALSE(brillo::kVCSID);
}

TEST(VCSIDTest, GetShortVCSID_Unset) {
  EXPECT_FALSE(brillo::kShortVCSID);
}

}  // namespace brillo

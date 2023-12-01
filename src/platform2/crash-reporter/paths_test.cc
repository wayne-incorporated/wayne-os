// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/paths.h"

#include <base/files/file_path.h>
#include <gtest/gtest.h>

namespace util {

TEST(CrashCommonPathsTest, Get) {
  EXPECT_EQ("/run/foo", paths::Get("/run/foo").value());
}

TEST(CrashCommonPathsTest, SetPrefixForTesting) {
  paths::SetPrefixForTesting(base::FilePath("/tmp"));
  EXPECT_EQ("/tmp/run/foo", paths::Get("/run/foo").value());
  paths::SetPrefixForTesting(base::FilePath());
  EXPECT_EQ("/run/foo", paths::Get("/run/foo").value());
}

TEST(CrashCommonPathsTest, GetAtWithPrefix) {
  paths::SetPrefixForTesting(base::FilePath("/tmp"));
  EXPECT_EQ("/tmp/run/foo", paths::GetAt("/run", "foo").value());
  paths::SetPrefixForTesting(base::FilePath());
  EXPECT_EQ("/run/foo", paths::GetAt("/run", "foo").value());
}

}  // namespace util

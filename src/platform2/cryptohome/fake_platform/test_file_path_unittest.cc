// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/fake_platform/test_file_path.h"

#include <list>
#include <string>
#include <utility>

#include <base/files/file_path.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace cryptohome {
namespace fake_platform {

class TestFilePathTest : public ::testing::Test {};

namespace {

using ::testing::Eq;

TEST_F(TestFilePathTest, SpliceTestFilePath) {
  const base::FilePath root("/some/root");
  const base::FilePath path("/and/path");
  const base::FilePath expected_result("/some/root/and/path");

  EXPECT_THAT(SpliceTestFilePath(root, path), Eq(expected_result));
}

TEST_F(TestFilePathTest, SpliceTestFilePath_Root) {
  const base::FilePath root("/some/root");
  const base::FilePath path("/");
  const base::FilePath expected_result("/some/root");

  EXPECT_THAT(SpliceTestFilePath(root, path), Eq(expected_result));
}

TEST_F(TestFilePathTest, StripTestFilePath_Strip) {
  const base::FilePath root("/some/root");
  const base::FilePath path("/some/root/and/path");
  const base::FilePath expected_result("/and/path");

  EXPECT_THAT(StripTestFilePath(root, path), Eq(expected_result));
}

TEST_F(TestFilePathTest, StripTestFilePath_Root) {
  const base::FilePath root("/some/root");
  const base::FilePath path("/some/root");
  const base::FilePath expected_result("/");

  EXPECT_THAT(StripTestFilePath(root, path), Eq(expected_result));
}

TEST_F(TestFilePathTest, StripTestFilePath_NoStrip) {
  const base::FilePath root("/some/root");
  const base::FilePath path("/and/path");
  const base::FilePath expected_result("/and/path");

  EXPECT_THAT(StripTestFilePath(root, path), Eq(expected_result));
}

TEST_F(TestFilePathTest, NormalizePath_NoOp) {
  for (const auto& [from, to] : std::list<std::pair<std::string, std::string>>{
           {"/", "/"},
           {"/./././", "/"},
           {"/./../../", "/"},
           {"/some/random/path", "/some/random/path"},
           {"/some/./random/path", "/some/random/path"},
           {"/../some/random/path", "/some/random/path"},
           {"/some/./random/path", "/some/random/path"},
           {"/some/../random/path", "/random/path"},
           {"/some/random/path/../../.././.././", "/"},
           {"/some/../some/random/path", "/some/random/path"},
       }) {
    EXPECT_THAT(NormalizePath(base::FilePath(from)), Eq(base::FilePath(to)));
  }
}

}  // namespace

}  // namespace fake_platform
}  // namespace cryptohome

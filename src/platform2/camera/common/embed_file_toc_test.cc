/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "common/embed_file_toc.h"

#include <base/at_exit.h>
#include <gtest/gtest.h>

#include "common/embed_file_toc_test_files_toc.h"

using ::testing::Test;

namespace cros {

namespace {

constexpr const char kEmbeddedTestHeaderFile[] = "embed_file_toc.h";
constexpr const char kEmbeddedTestCcFile[] = "embed_file_toc.cc";

}  // namespace

class EmbedFileTocTest : public Test {
 protected:
  EmbedFileTocTest() = default;
  ~EmbedFileTocTest() = default;
};

TEST_F(EmbedFileTocTest, EmbedFileTocTest) {
  EmbeddedFileToc test_toc = GetEmbedFileTocTestFilesToc();

  base::span<const char> header_file = test_toc.Get(kEmbeddedTestHeaderFile);
  base::span<const char> cc_file = test_toc.Get(kEmbeddedTestCcFile);

  ASSERT_GT(header_file.size(), 0);
  ASSERT_GT(cc_file.size(), 0);
}

}  // namespace cros

int main(int argc, char** argv) {
  base::AtExitManager exit_manager;
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}

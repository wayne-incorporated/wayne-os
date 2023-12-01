// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "p2p/common/testutil.h"

#include <glib-object.h>

#include <gtest/gtest.h>

#include <base/files/file_util.h>

using std::string;
using std::vector;

using base::FilePath;

namespace p2p {

namespace testutil {

TEST(TestUtil, TestDir) {
  FilePath testdir = SetupTestDir("test-dir");

  string path = testdir.value();

  EXPECT_EQ(path.find("/tmp/p2p-testing-test-dir."), 0);

  EXPECT_TRUE(g_file_test(path.c_str(), G_FILE_TEST_EXISTS));
  EXPECT_TRUE(g_file_test(path.c_str(), G_FILE_TEST_IS_DIR));

  int num_files = 0;
  GDir* dir = g_dir_open(path.c_str(), 0, NULL);
  while (g_dir_read_name(dir) != NULL) {
    num_files++;
  }
  g_dir_close(dir);
  EXPECT_EQ(num_files, 0);

  TeardownTestDir(testdir);

  EXPECT_TRUE(!g_file_test(path.c_str(), G_FILE_TEST_EXISTS));
}

TEST(TestUtil, ExpectCommandSimple) {
  EXPECT_COMMAND(0, "true");
  EXPECT_COMMAND(1, "false");
}

TEST(TestUtil, ExpectCommandSideEffects) {
  FilePath testdir = SetupTestDir("expect-command-side-effects");

  EXPECT_COMMAND(0, "echo -n xyz > %s",
                 testdir.Append("file.txt").value().c_str());

  string contents;
  EXPECT_TRUE(base::ReadFileToString(testdir.Append("file.txt"), &contents));
  EXPECT_EQ(contents, "xyz");

  TeardownTestDir(testdir);
}

TEST(TestUtil, FileSize) {
  FilePath testdir = SetupTestDir("expect-file-size");

  EXPECT_COMMAND(0, "echo -n 1 > %s", testdir.Append("a").value().c_str());
  EXPECT_COMMAND(0, "echo -n 11 > %s", testdir.Append("b").value().c_str());
  EXPECT_COMMAND(0, "echo -n 111 > %s", testdir.Append("c").value().c_str());

  ExpectFileSize(testdir, "a", 1);
  ExpectFileSize(testdir, "b", 2);
  ExpectFileSize(testdir, "c", 3);

  TeardownTestDir(testdir);
}

}  // namespace testutil

}  // namespace p2p

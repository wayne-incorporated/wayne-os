// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <sstream>
#include <string>

#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/process/launch.h>
#include <gtest/gtest.h>

#include "chargesplash/frecon.h"
#include "chargesplash/test_util.h"

namespace {

constexpr char kFakeFreconProgram[] =
    "#!/bin/bash\n"
    "sysroot=\"$(dirname \"$0\")/..\"\n"
    "mkdir -p \"${sysroot}/run/frecon\"\n"
    "nohup sleep infinity >/dev/null 2>&1 &\n"
    "echo $! > \"${sysroot}/run/frecon/pid\"\n";

class FreconTest : public ::testing::Test {
 public:
  void SetUp() override {
    ASSERT_TRUE(fake_sysroot_.CreateUniqueTempDir());

    auto sbin_dir = fake_sysroot_.GetPath().Append("sbin");

    base::File::Error err;
    ASSERT_TRUE(base::CreateDirectoryAndGetError(sbin_dir, &err));

    auto frecon_path = sbin_dir.Append("frecon");
    ASSERT_TRUE(base::WriteFile(frecon_path, kFakeFreconProgram));
    ASSERT_TRUE(base::SetPosixFilePermissions(frecon_path, 0755));

    chargesplash::SetSysrootForTesting(fake_sysroot_.GetPath().MaybeAsASCII());
  }

 protected:
  base::ScopedTempDir fake_sysroot_;
};

// Test frecon process can be initialized and destroyed.
TEST_F(FreconTest, TestInitFrecon) {
  auto frecon = chargesplash::Frecon();
  EXPECT_TRUE(frecon.InitFrecon());
}

// Test writing to frecon and to an output file.
TEST_F(FreconTest, TestWriteToMultipleOutputs) {
  auto frecon = chargesplash::Frecon();
  EXPECT_TRUE(frecon.InitFrecon());

  std::stringstream output;
  frecon.AttachOutput(&output);
  frecon.Write("some text");
  EXPECT_EQ(output.str(), "some text");

  auto file_path = base::FilePath(chargesplash::GetPath("/run/frecon/vt0"));
  std::string file_contents;
  EXPECT_TRUE(base::ReadFileToString(file_path, &file_contents));
  EXPECT_EQ(file_contents, "some text");
}

// Test that, when initializing frecon, if there is already a frecon
// running, we terminate it first.
TEST_F(FreconTest, TestTerminateRunningFrecon) {
  std::vector<std::string> argv = {chargesplash::GetPath("/sbin/frecon")};
  std::string output;
  EXPECT_TRUE(base::GetAppOutputAndError(argv, &output));

  auto frecon = chargesplash::Frecon();
  EXPECT_TRUE(frecon.InitFrecon());
}

}  // namespace

// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "installer/inst_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <base/files/file_util.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "installer/chromeos_install_config.h"
#include "installer/chromeos_postinst.h"

using std::string;
using std::vector;

class UtilTest : public ::testing::Test {};

const base::FilePath GetSourceFile(const base::FilePath& file) {
  static const char* srcdir = getenv("SRC");

  return srcdir ? base::FilePath(srcdir).Append(file) : file;
}

TEST(UtilTest, RunCommandTest) {
  // Note that RunCommand returns the raw system() result, including signal
  // values. WEXITSTATUS would be needed to check clean result codes.
  EXPECT_EQ(RunCommand({"/bin/true"}), 0);
  EXPECT_EQ(RunCommand({"/bin/false"}), 1);
  EXPECT_EQ(RunCommand({"/bin/bogus"}), 127);
  EXPECT_EQ(RunCommand({"/bin/bash", "-c", "exit 2"}), 2);
  EXPECT_EQ(RunCommand({"/bin/echo", "RunCommand*Test"}), 0);
  EXPECT_EQ(RunCommand({"kill", "-INT", "$$"}), 1);
}

TEST(UtilTest, LsbReleaseValueTest) {
  string result_string;
  base::FilePath lsb_file =
      GetSourceFile(base::FilePath("lsb-release-test.txt"));

  EXPECT_EQ(LsbReleaseValue(base::FilePath("bogus"), "CHROMEOS_RELEASE_BOARD",
                            &result_string),
            false);

  EXPECT_EQ(LsbReleaseValue(lsb_file, "CHROMEOS_RELEASE_BOARD", &result_string),
            true);
  EXPECT_EQ(result_string, "x86-mario");

  EXPECT_EQ(LsbReleaseValue(lsb_file, "CHROMEOS_RELEASE", &result_string),
            true);
  EXPECT_EQ(result_string, "1568.0.2012_01_19_1424");

  EXPECT_EQ(LsbReleaseValue(lsb_file, "CHROMEOS_AUSERVER", &result_string),
            true);
  EXPECT_EQ(result_string, "http://blah.blah:8080/update");
}

TEST(UtilTest, GetBlockDevFromPartitionDev) {
  EXPECT_EQ(GetBlockDevFromPartitionDev(base::FilePath("/dev/sda3")),
            base::FilePath("/dev/sda"));
  EXPECT_EQ(GetBlockDevFromPartitionDev(base::FilePath("/dev/sda321")),
            base::FilePath("/dev/sda"));
  EXPECT_EQ(GetBlockDevFromPartitionDev(base::FilePath("/dev/sda")),
            base::FilePath("/dev/sda"));
  EXPECT_EQ(GetBlockDevFromPartitionDev(base::FilePath("/dev/mmcblk0p3")),
            base::FilePath("/dev/mmcblk0"));
  EXPECT_EQ(GetBlockDevFromPartitionDev(base::FilePath("/dev/mmcblk12p321")),
            base::FilePath("/dev/mmcblk12"));
  EXPECT_EQ(GetBlockDevFromPartitionDev(base::FilePath("/dev/mmcblk0")),
            base::FilePath("/dev/mmcblk0"));
  EXPECT_EQ(GetBlockDevFromPartitionDev(base::FilePath("/dev/loop0")),
            base::FilePath("/dev/loop0"));
  EXPECT_EQ(GetBlockDevFromPartitionDev(base::FilePath("/dev/loop32p12")),
            base::FilePath("/dev/loop32"));
  EXPECT_EQ(GetBlockDevFromPartitionDev(base::FilePath("/dev/mtd0")),
            base::FilePath("/dev/mtd0"));
  EXPECT_EQ(GetBlockDevFromPartitionDev(base::FilePath("/dev/ubi1_0")),
            base::FilePath("/dev/mtd0"));
  EXPECT_EQ(GetBlockDevFromPartitionDev(base::FilePath("/dev/mtd2_0")),
            base::FilePath("/dev/mtd0"));
  EXPECT_EQ(GetBlockDevFromPartitionDev(base::FilePath("/dev/ubiblock3_0")),
            base::FilePath("/dev/mtd0"));
  EXPECT_EQ(GetBlockDevFromPartitionDev(base::FilePath("/dev/nvme0n1p12")),
            base::FilePath("/dev/nvme0n1"));
}

TEST(UtilTest, GetPartitionDevTest) {
  EXPECT_EQ(GetPartitionFromPartitionDev(base::FilePath("/dev/sda3")),
            PartitionNum(3));
  EXPECT_EQ(GetPartitionFromPartitionDev(base::FilePath("/dev/sda321")),
            PartitionNum(321));
  EXPECT_EQ(GetPartitionFromPartitionDev(base::FilePath("/dev/sda")),
            PartitionNum(0));
  EXPECT_EQ(GetPartitionFromPartitionDev(base::FilePath("/dev/mmcblk0p3")),
            PartitionNum(3));
  EXPECT_EQ(GetPartitionFromPartitionDev(base::FilePath("/dev/mmcblk12p321")),
            PartitionNum(321));
  EXPECT_EQ(GetPartitionFromPartitionDev(base::FilePath("/dev/mmcblk1")),
            PartitionNum(0));
  EXPECT_EQ(GetPartitionFromPartitionDev(base::FilePath("3")), PartitionNum(3));
  EXPECT_EQ(GetPartitionFromPartitionDev(base::FilePath("/dev/loop1")),
            PartitionNum(0));
  EXPECT_EQ(GetPartitionFromPartitionDev(base::FilePath("/dev/loop1p12")),
            PartitionNum(12));
  EXPECT_EQ(GetPartitionFromPartitionDev(base::FilePath("/dev/mtd0")),
            PartitionNum(0));
  EXPECT_EQ(GetPartitionFromPartitionDev(base::FilePath("/dev/ubi1_0")),
            PartitionNum(1));
  EXPECT_EQ(GetPartitionFromPartitionDev(base::FilePath("/dev/mtd2_0")),
            PartitionNum(2));
  EXPECT_EQ(GetPartitionFromPartitionDev(base::FilePath("/dev/ubiblock3_0")),
            PartitionNum(3));
  EXPECT_EQ(GetPartitionFromPartitionDev(base::FilePath("/dev/mtd4_0")),
            PartitionNum(4));
  EXPECT_EQ(GetPartitionFromPartitionDev(base::FilePath("/dev/ubiblock5_0")),
            PartitionNum(5));
  EXPECT_EQ(GetPartitionFromPartitionDev(base::FilePath("/dev/mtd6_0")),
            PartitionNum(6));
  EXPECT_EQ(GetPartitionFromPartitionDev(base::FilePath("/dev/ubiblock7_0")),
            PartitionNum(7));
  EXPECT_EQ(GetPartitionFromPartitionDev(base::FilePath("/dev/ubi8_0")),
            PartitionNum(8));
  EXPECT_EQ(GetPartitionFromPartitionDev(base::FilePath("/dev/nvme0n1p12")),
            PartitionNum(12));
}

TEST(UtilTest, MakePartitionDevTest) {
  EXPECT_EQ(MakePartitionDev(base::FilePath("/dev/sda"), PartitionNum(3)),
            base::FilePath("/dev/sda3"));
  EXPECT_EQ(MakePartitionDev(base::FilePath("/dev/sda"), PartitionNum(321)),
            base::FilePath("/dev/sda321"));
  EXPECT_EQ(MakePartitionDev(base::FilePath("/dev/mmcblk0"), PartitionNum(3)),
            base::FilePath("/dev/mmcblk0p3"));
  EXPECT_EQ(
      MakePartitionDev(base::FilePath("/dev/mmcblk12"), PartitionNum(321)),
      base::FilePath("/dev/mmcblk12p321"));
  EXPECT_EQ(MakePartitionDev(base::FilePath("/dev/loop16"), PartitionNum(321)),
            base::FilePath("/dev/loop16p321"));
  EXPECT_EQ(MakePartitionDev(base::FilePath(), PartitionNum(0)),
            base::FilePath("0"));
  EXPECT_EQ(MakePartitionDev(base::FilePath("/dev/mtd0"), PartitionNum(0)),
            base::FilePath("/dev/mtd0"));
  EXPECT_EQ(MakePartitionDev(base::FilePath("/dev/mtd0"), PartitionNum(1)),
            base::FilePath("/dev/ubi1_0"));
  EXPECT_EQ(MakePartitionDev(base::FilePath("/dev/mtd0"), PartitionNum(2)),
            base::FilePath("/dev/mtd2"));
  EXPECT_EQ(MakePartitionDev(base::FilePath("/dev/mtd0"), PartitionNum(3)),
            base::FilePath("/dev/ubiblock3_0"));
  EXPECT_EQ(MakePartitionDev(base::FilePath("/dev/mtd0"), PartitionNum(4)),
            base::FilePath("/dev/mtd4"));
  EXPECT_EQ(MakePartitionDev(base::FilePath("/dev/mtd0"), PartitionNum(5)),
            base::FilePath("/dev/ubiblock5_0"));
  EXPECT_EQ(MakePartitionDev(base::FilePath("/dev/nvme0n1"), PartitionNum(12)),
            base::FilePath("/dev/nvme0n1p12"));
}

TEST(UtilTest, RemovePackFileTest) {
  // Setup
  EXPECT_EQ(RunCommand({"rm", "-rf", "/tmp/PackFileTest"}), 0);
  EXPECT_EQ(RunCommand({"mkdir", "/tmp/PackFileTest"}), 0);
  EXPECT_EQ(Touch(base::FilePath("/tmp/PackFileTest/foo")), true);
  EXPECT_EQ(Touch(base::FilePath("/tmp/PackFileTest/foo.pack")), true);
  EXPECT_EQ(Touch(base::FilePath("/tmp/PackFileTest/foopack")), true);
  EXPECT_EQ(Touch(base::FilePath("/tmp/PackFileTest/.foo.pack")), true);

  // Test
  EXPECT_EQ(RemovePackFiles(base::FilePath("/tmp/PackFileTest")), true);

  // Test to see which files were removed
  struct stat stats;

  EXPECT_EQ(stat("/tmp/PackFileTest/foo", &stats), 0);
  EXPECT_EQ(stat("/tmp/PackFileTest/foo.pack", &stats), -1);
  EXPECT_EQ(stat("/tmp/PackFileTest/foopack", &stats), -1);
  EXPECT_EQ(stat("/tmp/PackFileTest/.foo.pack", &stats), 0);

  // Bad dir name
  EXPECT_EQ(RemovePackFiles(base::FilePath("/fuzzy")), false);

  // Cleanup
  EXPECT_EQ(RunCommand({"rm", "-rf", "/tmp/PackFileTest"}), 0);
}

TEST(UtilTest, TouchTest) {
  unlink("/tmp/fuzzy");

  // Touch a non-existent file
  EXPECT_EQ(Touch(base::FilePath("/tmp/fuzzy")), true);

  // Touch an existent file
  EXPECT_EQ(Touch(base::FilePath("/tmp/fuzzy")), true);

  // This touch creates files, and so can't touch a dir
  EXPECT_EQ(Touch(base::FilePath("/tmp")), false);

  // Bad Touch
  EXPECT_EQ(Touch(base::FilePath("/fuzzy/wuzzy")), false);

  unlink("/tmp/fuzzy");
}

TEST(UtilTest, ReplaceInFileTest) {
  const base::FilePath file("/tmp/fuzzy");
  const string start = "Fuzzy Wuzzy was a lamb";
  string finish;

  // File doesn't exist
  EXPECT_EQ(ReplaceInFile("was", "wuz", base::FilePath("/fuzzy/wuzzy")), false);

  // Change middle, same length
  EXPECT_EQ(base::WriteFile(file, start), true);
  EXPECT_EQ(ReplaceInFile("was", "wuz", file), true);
  EXPECT_EQ(base::ReadFileToString(file, &finish), true);
  EXPECT_EQ(finish, "Fuzzy Wuzzy wuz a lamb");

  // Change middle, longer
  EXPECT_EQ(base::WriteFile(file, start), true);
  EXPECT_EQ(ReplaceInFile("was", "wasn't", file), true);
  EXPECT_EQ(base::ReadFileToString(file, &finish), true);
  EXPECT_EQ(finish, "Fuzzy Wuzzy wasn't a lamb");

  // Change middle, longer, could match again
  EXPECT_EQ(base::WriteFile(file, start), true);
  EXPECT_EQ(ReplaceInFile("was", "was was", file), true);
  EXPECT_EQ(base::ReadFileToString(file, &finish), true);
  EXPECT_EQ(finish, "Fuzzy Wuzzy was was a lamb");

  // Change middle, shorter
  EXPECT_EQ(base::WriteFile(file, start), true);
  EXPECT_EQ(ReplaceInFile("Wuzzy", "Wuz", file), true);
  EXPECT_EQ(ReadFileToString(file, &finish), true);
  EXPECT_EQ(finish, "Fuzzy Wuz was a lamb");

  // Change beginning, longer
  EXPECT_EQ(base::WriteFile(file, start), true);
  EXPECT_EQ(ReplaceInFile("Fuzzy", "AFuzzy", file), true);
  EXPECT_EQ(base::ReadFileToString(file, &finish), true);
  EXPECT_EQ(finish, "AFuzzy Wuzzy was a lamb");

  // Change end, shorter
  EXPECT_EQ(base::WriteFile(file, start), true);
  EXPECT_EQ(ReplaceInFile("lamb", "la", file), true);
  EXPECT_EQ(base::ReadFileToString(file, &finish), true);
  EXPECT_EQ(finish, "Fuzzy Wuzzy was a la");
}

TEST(UtilTest, ExtractKernelArgTest) {
  string kernel_config =
      "root=/dev/dm-1 dm=\"foo bar, ver=2 root2=1 stuff=v\""
      " fuzzy=wuzzy root2=/dev/dm-2";
  string dm_config = "foo bar, ver=2 root2=1 stuff=v";

  // kernel config
  EXPECT_EQ(ExtractKernelArg(kernel_config, "root"), "/dev/dm-1");
  EXPECT_EQ(ExtractKernelArg(kernel_config, "root2"), "/dev/dm-2");
  EXPECT_EQ(ExtractKernelArg(kernel_config, "dm"), dm_config);

  // Corrupt config
  EXPECT_EQ(ExtractKernelArg("root=\"", "root"), "");
  EXPECT_EQ(ExtractKernelArg("root=\" bar", "root"), "");

  // Inside dm config
  EXPECT_EQ(ExtractKernelArg(dm_config, "ver"), "2");
  EXPECT_EQ(ExtractKernelArg(dm_config, "stuff"), "v");
  EXPECT_EQ(ExtractKernelArg(dm_config, "root"), "");
}

TEST(UtilTest, SetKernelArgTest) {
  const string kernel_config =
      "root=/dev/dm-1 dm=\"foo bar, ver=2 root2=1 stuff=v\""
      " fuzzy=wuzzy root2=/dev/dm-2";

  string working_config;

  // Basic change
  working_config = kernel_config;
  EXPECT_EQ(SetKernelArg("fuzzy", "tuzzy", &working_config), true);
  EXPECT_EQ(working_config,
            "root=/dev/dm-1 dm=\"foo bar, ver=2 root2=1 stuff=v\""
            " fuzzy=tuzzy root2=/dev/dm-2");

  // Empty a value
  working_config = kernel_config;
  EXPECT_EQ(SetKernelArg("root", "", &working_config), true);
  EXPECT_EQ(working_config,
            "root= dm=\"foo bar, ver=2 root2=1 stuff=v\""
            " fuzzy=wuzzy root2=/dev/dm-2");

  // Set a value that requires quotes
  working_config = kernel_config;
  EXPECT_EQ(SetKernelArg("root", "a b", &working_config), true);
  EXPECT_EQ(working_config,
            "root=\"a b\" dm=\"foo bar, ver=2 root2=1 stuff=v\""
            " fuzzy=wuzzy root2=/dev/dm-2");

  // Change a value that requires quotes to be removed
  working_config = kernel_config;
  EXPECT_EQ(SetKernelArg("dm", "ab", &working_config), true);
  EXPECT_EQ(working_config, "root=/dev/dm-1 dm=ab fuzzy=wuzzy root2=/dev/dm-2");

  // Change a quoted value that stays quoted
  working_config = kernel_config;
  EXPECT_EQ(SetKernelArg("dm", "a b", &working_config), true);
  EXPECT_EQ(working_config,
            "root=/dev/dm-1 dm=\"a b\" fuzzy=wuzzy root2=/dev/dm-2");

  // Try to change value that's not present
  working_config = kernel_config;
  EXPECT_EQ(SetKernelArg("unknown", "", &working_config), false);
  EXPECT_EQ(working_config, kernel_config);

  // Try to change a term inside quotes to ensure it's ignored
  working_config = kernel_config;
  EXPECT_EQ(SetKernelArg("ver", "", &working_config), false);
  EXPECT_EQ(working_config, kernel_config);
}

TEST(UtilTest, IsReadonlyTest) {
  EXPECT_EQ(IsReadonly(base::FilePath("/dev/sda3")), false);
  EXPECT_EQ(IsReadonly(base::FilePath("/dev/dm-0")), true);
  EXPECT_EQ(IsReadonly(base::FilePath("/dev/dm-1")), true);
  EXPECT_EQ(IsReadonly(base::FilePath("/dev/ubi1_0")), true);
  EXPECT_EQ(IsReadonly(base::FilePath("/dev/ubo1_0")), false);
  EXPECT_EQ(IsReadonly(base::FilePath("/dev/ubiblock1_0")), true);
}

TEST(UtilTest, ReplaceAllTest) {
  string a = "abcdeabcde";
  string b = a;
  ReplaceAll(&b, "xyz", "lmnop");
  EXPECT_EQ(a, b);
  ReplaceAll(&b, "ea", "ea");
  EXPECT_EQ(a, b);
  ReplaceAll(&b, "ea", "xyz");
  EXPECT_EQ(b, "abcdxyzbcde");
  ReplaceAll(&b, "bcd", "rs");
  EXPECT_EQ(b, "arsxyzrse");
}

TEST(UtilTest, ScopedPathRemoverWithFile) {
  const base::FilePath filename = base::FilePath(tmpnam(NULL));
  EXPECT_TRUE(base::WriteFile(filename, "abc"));
  ASSERT_TRUE(base::PathExists(filename));

  // Release early to prevent removal.
  {
    ScopedPathRemover remover(filename);
    remover.Release();
  }
  EXPECT_TRUE(base::PathExists(filename));

  // No releasing, the file should be removed.
  { ScopedPathRemover remover(filename); }
  EXPECT_FALSE(base::PathExists(filename));
}

TEST(UtilTest, ScopedPathRemoverWithDirectory) {
  const base::FilePath dirname = base::FilePath(tmpnam(NULL));
  const base::FilePath filename = dirname.Append("abc");
  ASSERT_TRUE(base::CreateDirectory(dirname));
  ASSERT_TRUE(base::PathExists(dirname));
  EXPECT_TRUE(base::WriteFile(filename, "abc"));
  ASSERT_TRUE(base::PathExists(filename));
  { ScopedPathRemover remover(dirname); }
  EXPECT_FALSE(base::PathExists(filename));
  EXPECT_FALSE(base::PathExists(dirname));
}

TEST(UtilTest, ScopedPathRemoverWithNonExistingPath) {
  base::FilePath filename = base::FilePath(tmpnam(NULL));
  ASSERT_FALSE(base::PathExists(filename));
  { ScopedPathRemover remover(filename); }
  // There should be no crash.
}

TEST(UtilTest, GetKernelInfo) {
  EXPECT_FALSE(GetKernelInfo(nullptr));

  string uname;
  EXPECT_TRUE(GetKernelInfo(&uname));
  EXPECT_NE(uname.find("sysname"), string::npos);
  EXPECT_NE(uname.find("nodename"), string::npos);
  EXPECT_NE(uname.find("release"), string::npos);
  EXPECT_NE(uname.find("version"), string::npos);
  EXPECT_NE(uname.find("machine"), string::npos);
}

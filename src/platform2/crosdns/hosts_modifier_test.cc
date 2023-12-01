// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crosdns/hosts_modifier.h"

#include <string>

#include <base/check.h>
#include <base/files/scoped_temp_dir.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <gtest/gtest.h>

namespace crosdns {

namespace {

constexpr char kBaseFileContents[] =
    "# Example /etc/hosts file\n"
    "127.0.0.1 localhost\n";
constexpr char kFileModificationDelimeter[] =
    "\n#####DYNAMIC-CROSDNS-ENTRIES#####\n";

class HostsModifierTest : public ::testing::Test {
 public:
  HostsModifierTest() {
    CHECK(temp_dir_.CreateUniqueTempDir());
    hosts_file_ = temp_dir_.GetPath().Append("hosts");
    WriteHostsContents(kBaseFileContents);
  }
  HostsModifierTest(const HostsModifierTest&) = delete;
  HostsModifierTest& operator=(const HostsModifierTest&) = delete;

  ~HostsModifierTest() override = default;

  void WriteHostsContents(const std::string& file_contents) {
    EXPECT_EQ(file_contents.size(),
              base::WriteFile(hosts_file_, file_contents.c_str(),
                              file_contents.size()));
  }

  std::string ReadHostsContents() const {
    std::string ret;
    EXPECT_TRUE(base::ReadFileToString(hosts_file_, &ret));
    return ret;
  }

  HostsModifier* hosts_modifier() { return &hosts_modifier_; }
  base::FilePath hosts_file() const { return hosts_file_; }

 private:
  base::ScopedTempDir temp_dir_;
  base::FilePath hosts_file_;
  HostsModifier hosts_modifier_;
};

}  // namespace

TEST_F(HostsModifierTest, InitSucceeds) {
  EXPECT_TRUE(hosts_modifier()->Init(hosts_file()));
  // The hosts file contents should be unchanged now.
  EXPECT_EQ(kBaseFileContents, ReadHostsContents());
}

TEST_F(HostsModifierTest, InitFailsNonExistentFile) {
  EXPECT_TRUE(base::DeleteFile(hosts_file()));
  EXPECT_FALSE(hosts_modifier()->Init(hosts_file()));
}

TEST_F(HostsModifierTest, InitRemovesOldEntries) {
  std::string extra_contents = kBaseFileContents;
  extra_contents += kFileModificationDelimeter;
  extra_contents += "1.2.3.4 example.com\n";
  WriteHostsContents(extra_contents);
  EXPECT_TRUE(hosts_modifier()->Init(hosts_file()));
  // The hosts file contents should be the original contents up to our
  // delimeter.
  EXPECT_EQ(kBaseFileContents, ReadHostsContents());
}

TEST_F(HostsModifierTest, SettingRemovingHostnames) {
  std::string err;
  EXPECT_TRUE(hosts_modifier()->Init(hosts_file()));
  // Valid hostname for default container.
  EXPECT_TRUE(hosts_modifier()->SetHostnameIpMapping(
      "penguin.linux.test", "100.115.92.24", "", &err));
  // Valid hostnames for vm/container.
  EXPECT_TRUE(hosts_modifier()->SetHostnameIpMapping(
      "foo12.linux.test", "100.115.92.22", "", &err));
  EXPECT_TRUE(hosts_modifier()->SetHostnameIpMapping(
      "penguin.termina.linux.test", "100.115.92.253", "", &err));
  // Invalid hostnames.
  EXPECT_FALSE(hosts_modifier()->SetHostnameIpMapping(
      "google.com", "100.115.92.24", "", &err));
  EXPECT_FALSE(hosts_modifier()->SetHostnameIpMapping(
      "localhost", "100.115.92.24", "", &err));
  EXPECT_FALSE(hosts_modifier()->SetHostnameIpMapping(
      "-foo-local", "100.115.92.24", "", &err));
  EXPECT_FALSE(hosts_modifier()->SetHostnameIpMapping(
      "foo..linux.test", "100.115.92.24", "", &err));
  EXPECT_FALSE(hosts_modifier()->SetHostnameIpMapping(
      ".linux.test", "100.115.92.24", "", &err));
  EXPECT_FALSE(hosts_modifier()->SetHostnameIpMapping(
      "linux.test", "100.115.92.24", "", &err));
  EXPECT_FALSE(
      hosts_modifier()->SetHostnameIpMapping("", "100.115.92.24", "", &err));
  // Invalid IPs.
  EXPECT_FALSE(hosts_modifier()->SetHostnameIpMapping(
      "penguin.linux.test", "100.115.91.24", "", &err));
  EXPECT_FALSE(hosts_modifier()->SetHostnameIpMapping("penguin.linux.test",
                                                      "8.8.8.8", "", &err));
  EXPECT_FALSE(hosts_modifier()->SetHostnameIpMapping(
      "penguin.linux.test", "101.115.92.24", "", &err));
  // Verify the contents of the hosts file. We are assuming an ordered map is
  // used here (which it is in the code) to make analyzing the results easier.
  std::string extra_contents = kBaseFileContents;
  extra_contents += kFileModificationDelimeter;
  extra_contents += "100.115.92.22 foo12.linux.test\n";
  extra_contents += "100.115.92.24 penguin.linux.test\n";
  extra_contents += "100.115.92.253 penguin.termina.linux.test\n";
  EXPECT_EQ(extra_contents, ReadHostsContents());

  // Removing an invalid hostname should fail.
  EXPECT_FALSE(hosts_modifier()->RemoveHostnameIpMapping("bar-local", &err));
  EXPECT_FALSE(hosts_modifier()->RemoveHostnameIpMapping("google.com", &err));
  // Removing a valid hostname should succeed.
  EXPECT_TRUE(
      hosts_modifier()->RemoveHostnameIpMapping("penguin.linux.test", &err));
  EXPECT_TRUE(
      hosts_modifier()->RemoveHostnameIpMapping("foo12.linux.test", &err));

  // Verify the contents of the hosts file again, there should be one entry
  // left.
  extra_contents = kBaseFileContents;
  extra_contents += kFileModificationDelimeter;
  extra_contents += "100.115.92.253 penguin.termina.linux.test\n";
  EXPECT_EQ(extra_contents, ReadHostsContents());
}

}  // namespace crosdns

// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gtest/gtest.h>

#include "smbprovider/fake_samba_interface.h"
#include "smbprovider/iterator/share_iterator.h"
#include "smbprovider/smbprovider_test_helper.h"

namespace smbprovider {

class ShareIteratorTest : public testing::Test {
 public:
  ShareIteratorTest() = default;
  ShareIteratorTest(const ShareIteratorTest&) = delete;
  ShareIteratorTest& operator=(const ShareIteratorTest&) = delete;

  ~ShareIteratorTest() override = default;

 protected:
  void CreateHost() { fake_samba_.AddDirectory(GetDefaultServer()); }

  FakeSambaInterface fake_samba_;
};

TEST_F(ShareIteratorTest, InitSucceedsOnHostWithNoShares) {
  CreateHost();

  ShareIterator it(GetDefaultServer(), &fake_samba_);

  EXPECT_EQ(0, it.Init());
  EXPECT_TRUE(it.IsDone());
}

TEST_F(ShareIteratorTest, InitSucceedsOnHostWithShare) {
  CreateHost();

  fake_samba_.AddEntry("smb://wdshare/share1", SMBC_FILE_SHARE);

  ShareIterator it(GetDefaultServer(), &fake_samba_);

  EXPECT_EQ(0, it.Init());
  EXPECT_FALSE(it.IsDone());
  EXPECT_EQ("share1", it.Get().name);
}

TEST_F(ShareIteratorTest, ShouldOnlyReturnShareType) {
  CreateHost();

  fake_samba_.AddEntry("smb://wdshare/share1", SMBC_FILE_SHARE);
  fake_samba_.AddDirectory("smb://wdshare/folder");

  ShareIterator it(GetDefaultServer(), &fake_samba_);

  EXPECT_EQ(0, it.Init());
  EXPECT_FALSE(it.IsDone());

  const DirectoryEntry& share = it.Get();
  EXPECT_EQ("share1", share.name);
  EXPECT_EQ("smb://wdshare/share1", share.full_path);
  EXPECT_TRUE(share.is_directory);
  EXPECT_EQ(-1, share.size);
  EXPECT_EQ(-1, share.last_modified_time);

  // Should be empty since there is only one SMBC_FILE_SHARE in the host.
  EXPECT_EQ(0, it.Next());
  EXPECT_TRUE(it.IsDone());
}

}  // namespace smbprovider

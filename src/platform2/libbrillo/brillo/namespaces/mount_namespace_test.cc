// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "brillo/namespaces/mock_platform.h"
#include "brillo/namespaces/mount_namespace.h"
#include "brillo/namespaces/platform.h"

#include <unistd.h>

#include <memory>

#include <base/files/file_path.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

using ::testing::_;
using ::testing::DoAll;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::SetArgPointee;

namespace brillo {

class MountNamespaceTest : public ::testing::Test {
 public:
  MountNamespaceTest() {}
  MountNamespaceTest(const MountNamespaceTest&) = delete;
  MountNamespaceTest& operator=(const MountNamespaceTest&) = delete;

  ~MountNamespaceTest() {}
  void SetUp() {}

  void TearDown() {}

 protected:
  NiceMock<MockPlatform> platform_;
};

TEST_F(MountNamespaceTest, CreateNamespace) {
  std::unique_ptr<MountNamespace> ns =
      std::make_unique<MountNamespace>(base::FilePath(), &platform_);
  EXPECT_CALL(platform_, Fork()).WillOnce(Return(1));
  EXPECT_CALL(platform_, Mount(_, _, _, _, _))
      .Times(2)
      .WillRepeatedly(Return(0));
  EXPECT_CALL(platform_, Waitpid(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(0x00000000), Return(0)));
  EXPECT_TRUE(ns->Create());
  EXPECT_CALL(platform_, Unmount(ns->path(), _, _)).WillOnce(Return(true));
}

TEST_F(MountNamespaceTest, CreateNamespaceFailedOnWaitpid) {
  std::unique_ptr<MountNamespace> ns =
      std::make_unique<MountNamespace>(base::FilePath(), &platform_);
  EXPECT_CALL(platform_, Fork()).WillOnce(Return(1));
  EXPECT_CALL(platform_, Mount(_, _, _, _, _))
      .Times(2)
      .WillRepeatedly(Return(0));
  EXPECT_CALL(platform_, Waitpid(_, _)).WillOnce(Return(-1));
  EXPECT_FALSE(ns->Create());
}

TEST_F(MountNamespaceTest, CreateNamespaceFailedOnMount) {
  std::unique_ptr<MountNamespace> ns =
      std::make_unique<MountNamespace>(base::FilePath(), &platform_);
  EXPECT_CALL(platform_, Fork()).WillOnce(Return(1));
  EXPECT_CALL(platform_, Mount(_, _, _, _, _)).WillOnce(Return(-1));
  EXPECT_FALSE(ns->Create());
}

TEST_F(MountNamespaceTest, CreateNamespaceFailedOnStatus) {
  std::unique_ptr<MountNamespace> ns =
      std::make_unique<MountNamespace>(base::FilePath(), &platform_);
  EXPECT_CALL(platform_, Fork()).WillOnce(Return(1));
  EXPECT_CALL(platform_, Mount(_, _, _, _, _))
      .Times(2)
      .WillRepeatedly(Return(0));
  EXPECT_CALL(platform_, Waitpid(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(0xFFFFFFFF), Return(0)));
  EXPECT_FALSE(ns->Create());
}

TEST_F(MountNamespaceTest, DestroyAfterUnmountFailsAndUnmountSucceeds) {
  std::unique_ptr<MountNamespace> ns =
      std::make_unique<MountNamespace>(base::FilePath(), &platform_);
  EXPECT_CALL(platform_, Fork()).WillOnce(Return(1));
  EXPECT_CALL(platform_, Mount(_, _, _, _, _))
      .Times(2)
      .WillRepeatedly(Return(0));
  EXPECT_CALL(platform_, Waitpid(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(0x00000000), Return(0)));
  EXPECT_TRUE(ns->Create());
  EXPECT_CALL(platform_, Unmount(ns->path(), _, _)).WillOnce(Return(false));
  EXPECT_FALSE(ns->Destroy());
  EXPECT_CALL(platform_, Unmount(ns->path(), _, _)).WillOnce(Return(true));
  EXPECT_TRUE(ns->Destroy());
}

}  // namespace brillo

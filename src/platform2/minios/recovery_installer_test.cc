// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gtest/gtest.h>

#include "minios/mock_process_manager.h"
#include "minios/recovery_installer.h"

using testing::_;

namespace minios {

class RecoveryInstallerTest : public ::testing::Test {
 protected:
  MockProcessManager mock_process_manager_;
  RecoveryInstaller recovery_installer_{&mock_process_manager_};
};

TEST_F(RecoveryInstallerTest, RepartitionDiskFailure) {
  EXPECT_CALL(mock_process_manager_, RunCommand(_, _))
      .WillOnce(testing::Return(1));
  EXPECT_FALSE(recovery_installer_.RepartitionDisk());
}

TEST_F(RecoveryInstallerTest, RepeatedRepartitionDisk) {
  EXPECT_CALL(mock_process_manager_, RunCommand(_, _))
      .WillOnce(testing::Return(0));
  EXPECT_TRUE(recovery_installer_.RepartitionDisk());

  // Does not call to repartition the disk again since it completed successfully
  // last time. Still returns true.
  EXPECT_TRUE(recovery_installer_.RepartitionDisk());
}

}  // namespace minios

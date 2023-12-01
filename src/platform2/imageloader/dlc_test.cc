// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "imageloader/dlc.h"

#include <memory>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "imageloader/manifest.h"
#include "imageloader/mock_helper_process_proxy.h"
#include "imageloader/test_utilities.h"

namespace imageloader {

TEST(DlcTest, MountDlc) {
  base::FilePath metadata_path = GetTestDataPath("example_dlc");
  base::FilePath image_path = metadata_path.Append("dlc.img");
  base::FilePath manifest_path = metadata_path.Append("imageloader.json");
  base::FilePath table_path = metadata_path.Append("table");

  auto proxy = std::make_unique<MockHelperProcessProxy>();
  EXPECT_CALL(*proxy, SendMountCommand(testing::_, testing::_,
                                       FileSystem::kExt4, testing::_))
      .Times(1);
  ON_CALL(*proxy,
          SendMountCommand(testing::_, testing::_, testing::_, testing::_))
      .WillByDefault(testing::Return(true));

  Dlc dlc("id", "package", base::FilePath());
  EXPECT_TRUE(dlc.Mount(proxy.get(), image_path, manifest_path, table_path,
                        base::FilePath()));
}

}  // namespace imageloader

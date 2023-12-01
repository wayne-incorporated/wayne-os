// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <list>
#include <string>
#include <utility>

#include <base/files/file_path.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "diagnostics/cros_healthd/fetchers/storage/device_lister.h"
#include "diagnostics/cros_healthd/fetchers/storage/mock/mock_platform.h"

using testing::Return;
using testing::UnorderedElementsAre;

namespace diagnostics {
namespace {

constexpr char kFakeRoot[] = "cros_healthd/fetchers/storage/testdata/";

TEST(StorageDeviceListerTest, EmmcRoot) {
  auto mock_platform = std::make_unique<MockPlatform>();
  EXPECT_CALL(*mock_platform, GetRootDeviceName())
      .WillRepeatedly(Return("mmcblk0"));
  StorageDeviceLister lister(std::move(mock_platform));

  auto result = lister.ListDevices(base::FilePath(kFakeRoot));
  EXPECT_THAT(result, UnorderedElementsAre("mmcblk0", "nvme0n1", "nvme0n2",
                                           "missing_model_and_name_test",
                                           "missing_revision", "name_file_test",
                                           "model_file_test", "sdc"));
}

TEST(StorageDeviceListerTest, NonEmmcRoot) {
  auto mock_platform = std::make_unique<MockPlatform>();
  EXPECT_CALL(*mock_platform, GetRootDeviceName())
      .WillRepeatedly(Return("nvme0n1"));
  StorageDeviceLister lister(std::move(mock_platform));

  auto result = lister.ListDevices(base::FilePath(kFakeRoot));
  EXPECT_THAT(result, UnorderedElementsAre("nvme0n1", "nvme0n2",
                                           "missing_model_and_name_test",
                                           "missing_revision", "name_file_test",
                                           "model_file_test", "sdc"));
}

}  // namespace
}  // namespace diagnostics

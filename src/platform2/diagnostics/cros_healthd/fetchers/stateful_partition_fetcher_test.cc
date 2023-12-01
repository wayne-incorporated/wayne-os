// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <brillo/files/file_util.h>
#include <gtest/gtest.h>

#include "diagnostics/base/file_test_utils.h"
#include "diagnostics/cros_healthd/fetchers/stateful_partition_fetcher.h"
#include "diagnostics/cros_healthd/system/mock_context.h"
#include "diagnostics/mojom/public/cros_healthd_probe.mojom.h"

namespace diagnostics {
namespace {

namespace mojom = ::ash::cros_healthd::mojom;

const char kFakeMountSource[] = "/dev/mmcblk0p1";
const char kFakeFilesystem[] = "ext4";
const char kFakeMtabOpt[] = "rw 0 0";

class StatefulePartitionFetcherTest : public ::testing::Test {
 protected:
  StatefulePartitionFetcherTest() = default;
  StatefulePartitionFetcherTest(const StatefulePartitionFetcherTest&) = delete;
  StatefulePartitionFetcherTest& operator=(
      const StatefulePartitionFetcherTest&) = delete;

  void SetUp() override {
    // Populate fake stateful partition directory.
    const auto stateful_partition_dir =
        root_dir().Append(kStatefulPartitionPath);
    ASSERT_TRUE(base::CreateDirectory(stateful_partition_dir));
    // Populate fake mtab contents.
    const auto mtab_path = root_dir().Append(kMtabPath);
    const auto fake_content = std::string(kFakeMountSource) + " " +
                              stateful_partition_dir.value() + " " +
                              kFakeFilesystem + " " + kFakeMtabOpt;
    ASSERT_TRUE(WriteFileAndCreateParentDirs(mtab_path, fake_content));
  }

  const base::FilePath& root_dir() { return mock_context_.root_dir(); }

  mojom::StatefulPartitionResultPtr FetchStatefulPartitionInfo() {
    return stateful_partition_fetcher_.FetchStatefulPartitionInfo();
  }

 private:
  MockContext mock_context_;
  StatefulPartitionFetcher stateful_partition_fetcher_{&mock_context_};
};

TEST_F(StatefulePartitionFetcherTest, TestFetchStatefulPartitionInfo) {
  const auto result = FetchStatefulPartitionInfo();
  ASSERT_TRUE(result->is_partition_info());
  EXPECT_GE(result->get_partition_info()->available_space, 0);
  EXPECT_EQ(result->get_partition_info()->filesystem, kFakeFilesystem);
  EXPECT_EQ(result->get_partition_info()->mount_source, kFakeMountSource);
}

TEST_F(StatefulePartitionFetcherTest, TestNoStatefulPartition) {
  ASSERT_TRUE(brillo::DeleteFile(root_dir().Append(kStatefulPartitionPath)));

  const auto result = FetchStatefulPartitionInfo();
  EXPECT_TRUE(result->is_error());
}

TEST_F(StatefulePartitionFetcherTest, TestNoMtabFile) {
  ASSERT_TRUE(brillo::DeleteFile(root_dir().Append(kMtabPath)));

  const auto result = FetchStatefulPartitionInfo();
  EXPECT_TRUE(result->is_error());
}

}  // namespace
}  // namespace diagnostics

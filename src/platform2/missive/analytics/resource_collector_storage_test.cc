// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "missive/analytics/resource_collector_storage.h"

#include <memory>
#include <numeric>
#include <string>
#include <vector>

#include <base/files/file_util.h>
#include <base/test/task_environment.h>
#include <base/test/test_file_util.h>
#include <base/time/time.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "missive/analytics/metrics_test_util.h"

using ::testing::Return;

namespace reporting::analytics {

class ResourceCollectorStorageTest
    : public ::testing::TestWithParam<std::vector<uint64_t>> {
 protected:
  void SetUp() override {
    DeployFilesToStorageDirectory();
  }

  // Deploy some files to the storage directory for testing
  void DeployFilesToStorageDirectory() const {
    std::vector<uint64_t> file_sizes{GetParam()};
    for (size_t i = 0; i < file_sizes.size(); ++i) {
      const base::FilePath path(storage_directory_.Append(std::to_string(i)));
      // Write file_sizes[i] times of 'a' to the file
      ASSERT_TRUE(base::WriteFile(path, std::string(file_sizes[i], 'a')))
          << "Failed to write test file " << path;
    }
  }

  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
  // The time interval that resource collector is expected to collect resources
  const base::TimeDelta kInterval{base::Minutes(8)};
  // The mock storage directory
  const base::FilePath storage_directory_{
      base::CreateUniqueTempDirectoryScopedToTest()};
  // Total file size in the mock storage
  const uint64_t total_file_size_{
      std::accumulate(GetParam().begin(), GetParam().end(), 0U)};
  // Replace the metrics library instance with a mock one
  Metrics::TestEnvironment metrics_test_environment_;
  ResourceCollectorStorage resource_collector_{kInterval, storage_directory_};
};

TEST_P(ResourceCollectorStorageTest, SuccessfullySend) {
  const int sample = ResourceCollectorStorage::ConvertBytesToMibs(
      static_cast<int>(total_file_size_));
  // Regression check: Ensure we have tested non-empty situations even if
  // parameters have been changed in the future. Based on the current
  // parameters, total file size greater than 1.5MiB should yield a sample
  // greater than 1.
  if (total_file_size_ >= 1024U * 512U * 3U) {
    ASSERT_GT(sample, 1);
  }

  // Proper data should be sent to UMA upon kInterval having elapsed
  EXPECT_CALL(Metrics::TestEnvironment::GetMockMetricsLibrary(),
              SendToUMA(
                  /*name=*/ResourceCollectorStorage::kUmaName,
                  /*sample=*/sample,
                  /*min=*/ResourceCollectorStorage::kMin,
                  /*max=*/ResourceCollectorStorage::kMax,
                  /*nbuckets=*/ResourceCollectorStorage::kUmaNumberOfBuckets))
      .Times(1)
      .WillOnce(Return(true));
  task_environment_.FastForwardBy(kInterval);
  task_environment_.RunUntilIdle();
}

// Each element in the array represent the size of one file.
INSTANTIATE_TEST_SUITE_P(
    VaryingStorageFiles,
    ResourceCollectorStorageTest,
    testing::Values(
        // One single empty file
        std::vector<uint64_t>{0U},
        // One single small file
        std::vector<uint64_t>{1024U},
        // One single large file
        std::vector<uint64_t>{1024U * 1024U * 11U},
        // Two files
        std::vector<uint64_t>{1024U * 1024U * 14U, 1024U * 1024U * 2U},
        // One empty file and two large files
        std::vector<uint64_t>{0, 1024U * 1024U * 16U, 1024U * 1024U * 20U}));
}  // namespace reporting::analytics

// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "croslog/metrics_collector_util.h"

#include <string>

#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/files/scoped_temp_dir.h"
#include "gtest/gtest.h"

#include "croslog/log_parser_audit.h"
#include "croslog/log_parser_syslog.h"
#include "croslog/test_util.h"

namespace croslog {

class MetricsCollectorUtilTest : public ::testing::Test {
 public:
  MetricsCollectorUtilTest() = default;
  MetricsCollectorUtilTest(const MetricsCollectorUtilTest&) = delete;
  MetricsCollectorUtilTest& operator=(const MetricsCollectorUtilTest&) = delete;
};

TEST_F(MetricsCollectorUtilTest, CalculateLogMetrics) {
  {
    base::FilePath log_path("./testdata/TEST_AUDIT_LOG");

    int64_t max_throughput = 0;
    int64_t entry_count = 0;
    int64_t byte_count = 0;

    // base::Time count_after = base::Time::Now() - base::Days(1);
    CalculateLogMetrics(log_path, base::Time(),
                        std::make_unique<LogParserAudit>(), &byte_count,
                        &entry_count, &max_throughput);
    EXPECT_EQ(1561, byte_count);
    EXPECT_EQ(7, entry_count);
    EXPECT_EQ(3, max_throughput);
  }

  {
    base::FilePath log_path("./testdata/TEST_NORMAL_LOG1");

    int64_t max_throughput = 0;
    int64_t entry_count = 0;
    int64_t byte_count = 0;

    // base::Time count_after = base::Time::Now() - base::Days(1);
    CalculateLogMetrics(log_path, base::Time(),
                        std::make_unique<LogParserSyslog>(), &byte_count,
                        &entry_count, &max_throughput);
    EXPECT_EQ(330, byte_count);
    EXPECT_EQ(2, entry_count);
    EXPECT_EQ(2, max_throughput);
  }

  {
    base::FilePath log_path("./testdata/TEST_BOOT_ID_LOG");

    int64_t max_throughput = 0;
    int64_t entry_count = 0;
    int64_t byte_count = 0;

    // base::Time count_after = base::Time::Now() - base::Days(1);
    CalculateLogMetrics(log_path, base::Time(),
                        std::make_unique<LogParserSyslog>(), &byte_count,
                        &entry_count, &max_throughput);
    EXPECT_EQ(240, byte_count);
    EXPECT_EQ(3, entry_count);
    EXPECT_EQ(1, max_throughput);
  }

  {
    base::FilePath log_path("./testdata/TEST_BOOT_ID_LOG");

    int64_t max_throughput = 0;
    int64_t entry_count = 0;
    int64_t byte_count = 0;

    base::Time count_after = TimeFromExploded(2020, 7, 3, 16, 23, 24, 0, 9);
    CalculateLogMetrics(log_path, count_after,
                        std::make_unique<LogParserSyslog>(), &byte_count,
                        &entry_count, &max_throughput);
    EXPECT_EQ(80, byte_count);
    EXPECT_EQ(1, entry_count);
    EXPECT_EQ(1, max_throughput);
  }
}

TEST_F(MetricsCollectorUtilTest, CalculateMultipleLogMetrics) {
  {
    Multiplexer multiplexer;
    multiplexer.AddSource(base::FilePath("./testdata/TEST_BOOT_ID_LOG"),
                          std::make_unique<LogParserSyslog>(), false);

    int64_t max_throughput = 0;
    int64_t entry_count = 0;

    CalculateMultipleLogMetrics(&multiplexer, base::Time(), &entry_count,
                                &max_throughput);
    EXPECT_EQ(3, entry_count);
    EXPECT_EQ(1, max_throughput);
  }

  {
    Multiplexer multiplexer;
    multiplexer.AddSource(base::FilePath("./testdata/TEST_BOOT_ID_LOG"),
                          std::make_unique<LogParserSyslog>(), false);

    int64_t max_throughput = 0;
    int64_t entry_count = 0;

    base::Time count_after = TimeFromExploded(2020, 7, 3, 16, 23, 24, 0, 9);
    CalculateMultipleLogMetrics(&multiplexer, count_after, &entry_count,
                                &max_throughput);
    EXPECT_EQ(1, entry_count);
    EXPECT_EQ(1, max_throughput);
  }
}

TEST_F(MetricsCollectorUtilTest, CalculateChromeLogMetrics) {
  {
    int64_t byte_count = 0;
    int64_t max_throughput = 0;
    int64_t entry_count = 0;

    CalculateChromeLogMetrics(base::FilePath("./testdata/"),
                              "TEST_SEQUENTIAL_LOG?", base::Time(), &byte_count,
                              &entry_count, &max_throughput);
    EXPECT_EQ(444, byte_count);
    EXPECT_EQ(6, entry_count);
    EXPECT_EQ(2, max_throughput);
  }

  {
    int64_t byte_count = 0;
    int64_t max_throughput = 0;
    int64_t entry_count = 0;

    base::Time count_after = TimeFromExploded(2020, 5, 25, 14, 16, 0, 0, 9);
    CalculateChromeLogMetrics(base::FilePath("./testdata/"),
                              "TEST_SEQUENTIAL_LOG?", count_after, &byte_count,
                              &entry_count, &max_throughput);
    EXPECT_EQ(222, byte_count);
    EXPECT_EQ(3, entry_count);
    EXPECT_EQ(1, max_throughput);
  }

  // Test to traverse many files.
  {
    // Prepares a temporary directory and many (empty) log files in it.
    base::ScopedTempDir temp_dir;
    EXPECT_TRUE(temp_dir.CreateUniqueTempDir());
    for (int i = 0; i < 1000; i++) {
      base::FilePath temp_file_path;
      base::CreateTemporaryFileInDir(temp_dir.GetPath(), &temp_file_path);
    }

    // Calculate
    int64_t byte_count = 0;
    int64_t max_throughput = 0;
    int64_t entry_count = 0;
    base::Time count_after = TimeFromExploded(2020, 5, 25, 14, 16, 0, 0, 9);
    CalculateChromeLogMetrics(temp_dir.GetPath(), "*", count_after, &byte_count,
                              &entry_count, &max_throughput);

    // All log files are empty so the results should be zero.
    EXPECT_EQ(0, byte_count);
    EXPECT_EQ(0, entry_count);
    EXPECT_EQ(0, max_throughput);
  }

  // Test to traverse no file.
  {
    int64_t byte_count = 0;
    int64_t max_throughput = 0;
    int64_t entry_count = 0;
    base::Time count_after = TimeFromExploded(2020, 5, 25, 14, 16, 0, 0, 9);
    CalculateChromeLogMetrics(base::FilePath("./testdata/"), "NON_EXISTING",
                              count_after, &byte_count, &entry_count,
                              &max_throughput);

    // Log files don't exist so the results should be zero.
    EXPECT_EQ(0, byte_count);
    EXPECT_EQ(0, entry_count);
    EXPECT_EQ(0, max_throughput);
  }
}

}  // namespace croslog

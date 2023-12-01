// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "metrics/metrics_writer.h"

#include <base/files/file_path.h>
#include <base/files/scoped_temp_dir.h>
#include <base/memory/scoped_refptr.h>
#include <base/task/thread_pool.h>
#include <base/test/task_environment.h>
#include <gtest/gtest.h>

#include "metrics/serialization/serialization_utils.h"

TEST(SynchronousMetricsWriterTest, WriteMetrics) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  auto file_path = temp_dir.GetPath().Append("metrics");
  auto writer = base::MakeRefCounted<SynchronousMetricsWriter>(file_path);

  auto sample1 = metrics::MetricSample::LinearHistogramSample("Test1", 1, 2);
  auto sample2 = metrics::MetricSample::LinearHistogramSample("Test2", 1, 2);
  EXPECT_TRUE(writer->WriteMetrics({sample1}));
  EXPECT_TRUE(writer->WriteMetrics({sample2}));
  std::vector<metrics::MetricSample> samples;
  ASSERT_TRUE(metrics::SerializationUtils::ReadAndTruncateMetricsFromFile(
      file_path.value(), &samples,
      metrics::SerializationUtils::kSampleBatchMaxLength));
  EXPECT_EQ(samples.size(), 2);
  EXPECT_EQ(samples[0].name(), sample1.name());
  EXPECT_EQ(samples[1].name(), sample2.name());
}

TEST(SynchronousMetricsWriterTest, SetOutputFile) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  auto file_path = temp_dir.GetPath().Append("metrics");
  auto file_path2 = temp_dir.GetPath().Append("metrics2");
  auto writer = base::MakeRefCounted<SynchronousMetricsWriter>(file_path);

  auto sample1 = metrics::MetricSample::LinearHistogramSample("Test1", 1, 2);
  auto sample2 = metrics::MetricSample::LinearHistogramSample("Test2", 1, 2);
  EXPECT_TRUE(writer->WriteMetrics({sample1}));
  EXPECT_TRUE(writer->SetOutputFile(file_path2.value()));
  EXPECT_TRUE(writer->WriteMetrics({sample2}));
  std::vector<metrics::MetricSample> samples;
  ASSERT_TRUE(metrics::SerializationUtils::ReadAndTruncateMetricsFromFile(
      file_path.value(), &samples,
      metrics::SerializationUtils::kSampleBatchMaxLength));
  EXPECT_EQ(samples.size(), 1);
  EXPECT_EQ(samples[0].name(), sample1.name());
  samples.clear();
  ASSERT_TRUE(metrics::SerializationUtils::ReadAndTruncateMetricsFromFile(
      file_path2.value(), &samples,
      metrics::SerializationUtils::kSampleBatchMaxLength));
  EXPECT_EQ(samples.size(), 1);
  EXPECT_EQ(samples[0].name(), sample2.name());
}

class AsynchronousMetricsWriterTest : public testing::Test {
 protected:
  void SetUp() override {
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    file_path_ = temp_dir_.GetPath().Append("metrics");
    writer_ = base::MakeRefCounted<AsynchronousMetricsWriter>(
        base::ThreadPool::CreateSequencedTaskRunner({base::MayBlock()}), true,
        file_path_);
  }

  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::ThreadingMode::MULTIPLE_THREADS};
  scoped_refptr<AsynchronousMetricsWriter> writer_;
  base::ScopedTempDir temp_dir_;
  base::FilePath file_path_;
};

TEST_F(AsynchronousMetricsWriterTest, WriteMetrics) {
  auto sample1 = metrics::MetricSample::LinearHistogramSample("Test1", 1, 2);
  auto sample2 = metrics::MetricSample::LinearHistogramSample("Test2", 1, 2);

  EXPECT_TRUE(writer_->WriteMetrics({sample1}));
  EXPECT_TRUE(writer_->WriteMetrics({sample2}));
  writer_->WaitUntilFlushed();

  std::vector<metrics::MetricSample> samples;
  ASSERT_TRUE(metrics::SerializationUtils::ReadAndTruncateMetricsFromFile(
      file_path_.value(), &samples,
      metrics::SerializationUtils::kSampleBatchMaxLength));
  EXPECT_EQ(samples.size(), 2);
  EXPECT_EQ(samples[0].name(), sample1.name());
  EXPECT_EQ(samples[1].name(), sample2.name());
}

TEST_F(AsynchronousMetricsWriterTest, WriteMetricsWithoutFlush) {
  auto sample1 = metrics::MetricSample::LinearHistogramSample("Test1", 1, 2);
  auto sample2 = metrics::MetricSample::LinearHistogramSample("Test2", 1, 2);

  EXPECT_TRUE(writer_->WriteMetrics({sample1}));
  EXPECT_TRUE(writer_->WriteMetrics({sample2}));
  // Destructor call `WaitUntilFlushed()` implicitly by default.
  writer_.reset();

  std::vector<metrics::MetricSample> samples;
  ASSERT_TRUE(metrics::SerializationUtils::ReadAndTruncateMetricsFromFile(
      file_path_.value(), &samples,
      metrics::SerializationUtils::kSampleBatchMaxLength));
  EXPECT_EQ(samples.size(), 2);
  EXPECT_EQ(samples[0].name(), sample1.name());
  EXPECT_EQ(samples[1].name(), sample2.name());
}

TEST_F(AsynchronousMetricsWriterTest, SetOutputFile) {
  auto file_path2 = temp_dir_.GetPath().Append("metrics2");
  auto sample1 = metrics::MetricSample::LinearHistogramSample("Test1", 1, 2);
  auto sample2 = metrics::MetricSample::LinearHistogramSample("Test2", 1, 2);

  EXPECT_TRUE(writer_->WriteMetrics({sample1}));
  EXPECT_TRUE(writer_->SetOutputFile(file_path2.value()));
  EXPECT_TRUE(writer_->WriteMetrics({sample2}));
  writer_->WaitUntilFlushed();

  std::vector<metrics::MetricSample> samples;
  ASSERT_TRUE(metrics::SerializationUtils::ReadAndTruncateMetricsFromFile(
      file_path_.value(), &samples,
      metrics::SerializationUtils::kSampleBatchMaxLength));
  EXPECT_EQ(samples.size(), 1);
  EXPECT_EQ(samples[0].name(), sample1.name());
  samples.clear();
  ASSERT_TRUE(metrics::SerializationUtils::ReadAndTruncateMetricsFromFile(
      file_path2.value(), &samples,
      metrics::SerializationUtils::kSampleBatchMaxLength));
  EXPECT_EQ(samples.size(), 1);
  EXPECT_EQ(samples[0].name(), sample2.name());
}

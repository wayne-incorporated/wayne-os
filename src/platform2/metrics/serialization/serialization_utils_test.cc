// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "metrics/serialization/serialization_utils.h"

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>
#include <gtest/gtest.h>

#include "metrics/serialization/metric_sample.h"

namespace metrics {
namespace {

class SerializationUtilsTest : public testing::Test {
 protected:
  SerializationUtilsTest() {
    bool success = temporary_dir_.CreateUniqueTempDir();
    if (success) {
      base::FilePath dir_path = temporary_dir_.GetPath();
      filepath_ = dir_path.Append("chromeossampletest");
      filename_ = filepath_.value();
    }
  }
  SerializationUtilsTest(const SerializationUtilsTest&) = delete;
  SerializationUtilsTest& operator=(const SerializationUtilsTest&) = delete;

  void SetUp() override { base::DeleteFile(filepath_); }

  void TestSerialization(const MetricSample& sample) {
    std::string serialized(sample.ToString());
    ASSERT_EQ('\0', serialized[serialized.length() - 1]);
    MetricSample deserialized = SerializationUtils::ParseSample(serialized);
    EXPECT_TRUE(sample.IsEqual(deserialized));
  }

  std::string filename_;
  base::ScopedTempDir temporary_dir_;
  base::FilePath filepath_;
};

TEST_F(SerializationUtilsTest, CrashSerializeTest) {
  TestSerialization(MetricSample::CrashSample("test"));
}

TEST_F(SerializationUtilsTest, HistogramSerializeTest) {
  TestSerialization(MetricSample::HistogramSample("myhist", 13, 1, 100, 10));
}

TEST_F(SerializationUtilsTest, RepeatedSerializeTest) {
  TestSerialization(
      MetricSample::HistogramSample("myrepeatedhist", 26, 1, 100, 10, 1000));
}

TEST_F(SerializationUtilsTest, LinearSerializeTest) {
  TestSerialization(MetricSample::LinearHistogramSample("linearhist", 12, 30));
}

TEST_F(SerializationUtilsTest, SparseSerializeTest) {
  TestSerialization(MetricSample::SparseHistogramSample("mysparse", 30));
}

TEST_F(SerializationUtilsTest, UserActionSerializeTest) {
  TestSerialization(MetricSample::UserActionSample("myaction"));
}

TEST_F(SerializationUtilsTest, IllegalNameAreFilteredTest) {
  EXPECT_FALSE(SerializationUtils::WriteMetricsToFile(
      {MetricSample::SparseHistogramSample("no space", 10),
       MetricSample::LinearHistogramSample(
           base::StringPrintf("here%cbhe", '\0'), 1, 3)},
      filename_));

  int64_t size = 0;
  ASSERT_TRUE(!PathExists(filepath_) || base::GetFileSize(filepath_, &size));
  EXPECT_EQ(0, size);
}

TEST_F(SerializationUtilsTest, BadHistogramsTest) {
  EXPECT_FALSE(SerializationUtils::WriteMetricsToFile(
      {MetricSample::HistogramSample("myhist", 5, 1, 10, 100)}, filename_));
  EXPECT_FALSE(SerializationUtils::WriteMetricsToFile(
      {MetricSample::LinearHistogramSample("alsomyhist", 0, 1)}, filename_));
}

TEST_F(SerializationUtilsTest, BadInputIsCaughtTest) {
  std::string input(
      base::StringPrintf("sparsehistogram%cname foo%c", '\0', '\0'));
  EXPECT_FALSE(MetricSample::ParseSparseHistogram(input).IsValid());
}

TEST_F(SerializationUtilsTest, MessageSeparatedByZero) {
  SerializationUtils::WriteMetricsToFile({MetricSample::CrashSample("mycrash")},
                                         filename_);
  int64_t size = 0;
  ASSERT_TRUE(base::GetFileSize(filepath_, &size));
  // 4 bytes for the size
  // 5 bytes for crash
  // 7 bytes for mycrash
  // 2 bytes for the \0
  // -> total of 18
  EXPECT_EQ(size, 18);
}

TEST_F(SerializationUtilsTest, MessagesTooLongAreDiscardedTest) {
  // Creates a message that is bigger than the maximum allowed size.
  // As we are adding extra character (crash, \0s, etc), if the name is
  // kMessageMaxLength long, it will be too long.
  std::string name(SerializationUtils::kMessageMaxLength, 'c');

  EXPECT_FALSE(SerializationUtils::WriteMetricsToFile(
      {MetricSample::CrashSample(name)}, filename_));
  EXPECT_FALSE(base::PathExists(filepath_));
}

TEST_F(SerializationUtilsTest, ReadLongMessageTest) {
  base::File test_file(filepath_,
                       base::File::FLAG_OPEN_ALWAYS | base::File::FLAG_APPEND);
  std::string message(SerializationUtils::kMessageMaxLength + 1, 'c');

  int32_t message_size = message.length() + sizeof(int32_t);
  test_file.WriteAtCurrentPos(reinterpret_cast<const char*>(&message_size),
                              sizeof(message_size));
  test_file.WriteAtCurrentPos(message.c_str(), message.length());
  test_file.Close();

  MetricSample crash = MetricSample::CrashSample("test");
  SerializationUtils::WriteMetricsToFile({crash}, filename_);

  std::vector<MetricSample> samples;
  SerializationUtils::ReadAndTruncateMetricsFromFile(
      filename_, &samples, SerializationUtils::kSampleBatchMaxLength);
  ASSERT_EQ(1U, samples.size());
  EXPECT_TRUE(crash.IsEqual(samples.front()));
}

TEST_F(SerializationUtilsTest, NegativeLengthTest) {
  // This input is specifically constructed to yield a single crash sample when
  // parsed by a buggy version of the code but fails to parse and doesn't yield
  // samples when parsed by a correct implementation.
  constexpr uint8_t kInput[] = {
      // Length indicating that next length field is the negative one below.
      // This sample is invalid as it contains more than three null bytes.
      0x14,
      0x00,
      0x00,
      0x00,
      // Encoding of a valid crash sample.
      0x0c,
      0x00,
      0x00,
      0x00,
      0x63,
      0x72,
      0x61,
      0x73,
      0x68,
      0x00,
      0x61,
      0x00,
      // Invalid sample that jumps past the negative length bytes below.
      0x08,
      0x00,
      0x00,
      0x00,
      // This is -16 in two's complement interpretation, pointing to the valid
      // crash sample before.
      0xf0,
      0xff,
      0xff,
      0xff,
  };
  CHECK(base::WriteFile(filepath_, reinterpret_cast<const char*>(kInput),
                        sizeof(kInput)));

  std::vector<MetricSample> samples;
  SerializationUtils::ReadAndTruncateMetricsFromFile(
      filename_, &samples, SerializationUtils::kSampleBatchMaxLength);
  ASSERT_EQ(0U, samples.size());
}

TEST_F(SerializationUtilsTest, WriteReadTest) {
  std::vector<MetricSample> output_samples = {
      MetricSample::HistogramSample("myhist", 3, 1, 10, 5),
      MetricSample::CrashSample("mycrash"),
      MetricSample::LinearHistogramSample("linear", 1, 10),
      MetricSample::SparseHistogramSample("mysparse", 30),
      MetricSample::UserActionSample("myaction"),
      MetricSample::HistogramSample("myrepeatedhist", 3, 1, 10, 5, 10),
  };

  SerializationUtils::WriteMetricsToFile(output_samples, filename_);
  std::vector<MetricSample> samples;
  SerializationUtils::ReadAndTruncateMetricsFromFile(
      filename_, &samples, SerializationUtils::kSampleBatchMaxLength);

  ASSERT_EQ(output_samples.size(), samples.size());
  for (size_t i = 0; i < output_samples.size(); ++i) {
    EXPECT_TRUE(output_samples[i].IsEqual(samples[i]));
  }

  int64_t size = 0;
  ASSERT_TRUE(base::GetFileSize(filepath_, &size));
  ASSERT_EQ(0, size);
}

// Test of batched upload.  Creates a metrics log with enough samples to
// trigger two uploads.
TEST_F(SerializationUtilsTest, BatchedUploadTest) {
  MetricSample hist =
      MetricSample::HistogramSample("Boring.Histogram", 3, 1, 10, 5);
  // The serialized MetricSample does not contain the header size (4 bytes for
  // the total sample length).
  size_t serialized_sample_length = hist.ToString().length() + 4;
  // Make the max batch size a multiple of the filesystem block size so we can
  // test the hole-punching optimization (maybe overkill, but fun).
  const size_t sample_batch_max_length = 10 * 4096;
  // Write enough samples for two passes.
  const int sample_count =
      1.5 * sample_batch_max_length / serialized_sample_length;

  SerializationUtils::WriteMetricsToFile(
      std::vector<MetricSample>(sample_count, hist), filename_);

  std::vector<MetricSample> samples;
  bool first_pass_status = SerializationUtils::ReadAndTruncateMetricsFromFile(
      filename_, &samples, sample_batch_max_length);

  ASSERT_FALSE(first_pass_status);  // means: more samples remain
  int first_pass_count = samples.size();
  ASSERT_LT(first_pass_count, sample_count);

  // There is nothing in the base library which returns the actual file
  // allocation (size - holes).
  struct stat stat_buf;
  // Check that stat() is successful.
  ASSERT_EQ(::stat(filename_.c_str(), &stat_buf), 0);
  // Check that the file is not truncated to zero.
  ASSERT_GT(stat_buf.st_size, 0);
  // Check that the file has holes.
  ASSERT_LT(stat_buf.st_blocks * 512, stat_buf.st_size);

  bool second_pass_status = SerializationUtils::ReadAndTruncateMetricsFromFile(
      filename_, &samples, sample_batch_max_length);

  ASSERT_TRUE(second_pass_status);  // no more samples.
  // Check that stat() is successful.
  ASSERT_EQ(::stat(filename_.c_str(), &stat_buf), 0);
  // Check that the file is empty.
  ASSERT_EQ(stat_buf.st_size, 0);
  // Check that we read all samples.
  ASSERT_EQ(samples.size(), sample_count);
}

}  // namespace
}  // namespace metrics

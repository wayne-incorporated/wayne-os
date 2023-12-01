// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "missive/compression/compression_module.h"

#include <memory>
#include <optional>
#include <string>
#include <tuple>
#include <utility>

#include <base/functional/bind.h>
#include <base/hash/hash.h>
#include <base/memory/scoped_refptr.h>
#include <base/rand_util.h>
#include <base/strings/strcat.h>
#include <base/synchronization/waitable_event.h>
#include <base/task/thread_pool.h>
#include <base/test/task_environment.h>
#include <base/time/time.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <snappy.h>

#include "missive/proto/record.pb.h"
#include "missive/resources/resource_manager.h"
#include "missive/util/test_support_callbacks.h"

using ::testing::Eq;
using ::testing::StrEq;

namespace reporting {
namespace {

constexpr char kTestString[] = "AAAAAAAAAAAAAA1111111111111";
constexpr char kPoorlyCompressibleTestString[] = "AAAAA11111";

class CompressionModuleTest : public ::testing::Test {
 protected:
  CompressionModuleTest()
      : memory_resource_(base::MakeRefCounted<ResourceManager>(
            4u * 1024LLu * 1024LLu))  // 4 MiB
  {}

  void TearDown() override { ASSERT_THAT(memory_resource_->GetUsed(), Eq(0u)); }
  std::string BenchmarkCompressRecordSnappy(std::string record_string) {
    std::string output;
    snappy::Compress(record_string.data(), record_string.size(), &output);
    return output;
  }

  base::test::TaskEnvironment task_environment_;
  scoped_refptr<ResourceManager> memory_resource_;
  scoped_refptr<CompressionModule> compression_module_;
};

TEST_F(CompressionModuleTest, CompressRecordSnappy) {
  scoped_refptr<CompressionModule> test_compression_module =
      CompressionModule::Create(/*is_enabled=*/true, 0,
                                CompressionInformation::COMPRESSION_SNAPPY);

  // Compress string directly with snappy as benchmark
  const std::string expected_output =
      BenchmarkCompressRecordSnappy(kTestString);

  test::TestMultiEvent<std::string, std::optional<CompressionInformation>>
      compressed_record_event;
  // Compress string with CompressionModule
  test_compression_module->CompressRecord(kTestString, memory_resource_,
                                          compressed_record_event.cb());

  const std::tuple<std::string, std::optional<CompressionInformation>>
      compressed_record_tuple = compressed_record_event.result();

  const base::StringPiece compressed_string_callback =
      std::get<0>(compressed_record_tuple);

  // Expect that benchmark compression is the same as compression module
  EXPECT_THAT(compressed_string_callback, StrEq(expected_output));

  const std::optional<CompressionInformation> compression_info =
      std::get<1>(compressed_record_tuple);

  EXPECT_TRUE(compression_info.has_value());

  // Expect that compression information contains COMPRESSION_SNAPPY
  EXPECT_THAT(compression_info.value().compression_algorithm(),
              Eq(CompressionInformation::COMPRESSION_SNAPPY));
}

TEST_F(CompressionModuleTest, CompressPoorlyCompressibleRecordSnappy) {
  scoped_refptr<CompressionModule> test_compression_module =
      CompressionModule::Create(/*is_enabled=*/true, 0,
                                CompressionInformation::COMPRESSION_SNAPPY);

  // Compress string directly with snappy as benchmark
  const std::string expected_output =
      BenchmarkCompressRecordSnappy(kPoorlyCompressibleTestString);

  test::TestMultiEvent<std::string, std::optional<CompressionInformation>>
      compressed_record_event;
  // Compress string with CompressionModule
  test_compression_module->CompressRecord(kPoorlyCompressibleTestString,
                                          memory_resource_,
                                          compressed_record_event.cb());

  const std::tuple<std::string, std::optional<CompressionInformation>>
      compressed_record_tuple = compressed_record_event.result();

  const base::StringPiece compressed_string_callback =
      std::get<0>(compressed_record_tuple);

  // Expect that benchmark compression is the same as compression module
  EXPECT_THAT(compressed_string_callback, StrEq(kPoorlyCompressibleTestString));

  const std::optional<CompressionInformation> compression_info =
      std::get<1>(compressed_record_tuple);

  EXPECT_TRUE(compression_info.has_value());

  // Expect that compression information contains COMPRESSION_NONE
  EXPECT_THAT(compression_info.value().compression_algorithm(),
              Eq(CompressionInformation::COMPRESSION_NONE));
}

TEST_F(CompressionModuleTest, CompressRecordBelowThreshold) {
  scoped_refptr<CompressionModule> test_compression_module =
      CompressionModule::Create(/*is_enabled=*/true, 512,
                                CompressionInformation::COMPRESSION_SNAPPY);

  test::TestMultiEvent<std::string, std::optional<CompressionInformation>>
      compressed_record_event;
  // Compress string with CompressionModule
  test_compression_module->CompressRecord(kTestString, memory_resource_,
                                          compressed_record_event.cb());

  const std::tuple<std::string, std::optional<CompressionInformation>>
      compressed_record_tuple = compressed_record_event.result();

  const base::StringPiece compressed_string_callback =
      std::get<0>(compressed_record_tuple);

  // Expect that record is not compressed since size is smaller than 512 bytes
  EXPECT_THAT(compressed_string_callback, StrEq(kTestString));

  const std::optional<CompressionInformation> compression_info =
      std::get<1>(compressed_record_tuple);

  EXPECT_TRUE(compression_info.has_value());

  // Expect that compression information contains COMPRESSION_NONE since the
  // record was below the compression threshold.
  EXPECT_THAT(compression_info.value().compression_algorithm(),
              Eq(CompressionInformation::COMPRESSION_NONE));
}

TEST_F(CompressionModuleTest, CompressRecordCompressionDisabled) {
  scoped_refptr<CompressionModule> test_compression_module =
      CompressionModule::Create(/*is_enabled=*/false, 0,
                                CompressionInformation::COMPRESSION_SNAPPY);

  test::TestMultiEvent<std::string, std::optional<CompressionInformation>>
      compressed_record_event;

  // Compress string with CompressionModule
  test_compression_module->CompressRecord(kTestString, memory_resource_,
                                          compressed_record_event.cb());

  const std::tuple<std::string, std::optional<CompressionInformation>>
      compressed_record_tuple = compressed_record_event.result();

  const base::StringPiece compressed_string_callback =
      std::get<0>(compressed_record_tuple);

  // Expect that record is not compressed since compression is not enabled
  EXPECT_THAT(compressed_string_callback, StrEq(kTestString));

  const std::optional<CompressionInformation> compression_info =
      std::get<1>(compressed_record_tuple);

  // Expect no compression information since compression has been disabled.
  EXPECT_FALSE(compression_info.has_value());
}

TEST_F(CompressionModuleTest, CompressRecordCompressionNone) {
  scoped_refptr<CompressionModule> test_compression_module =
      CompressionModule::Create(/*is_enabled=*/true, 0,
                                CompressionInformation::COMPRESSION_NONE);

  test::TestMultiEvent<std::string, std::optional<CompressionInformation>>
      compressed_record_event;

  // Compress string with CompressionModule
  test_compression_module->CompressRecord(kTestString, memory_resource_,
                                          compressed_record_event.cb());
  const std::tuple<std::string, std::optional<CompressionInformation>>
      compressed_record_tuple = compressed_record_event.result();

  const base::StringPiece compressed_string_callback =
      std::get<0>(compressed_record_tuple);

  // Expect that record is not compressed since COMPRESSION_NONE was chosen as
  // the compression_algorithm.
  EXPECT_THAT(compressed_string_callback, StrEq(kTestString));

  const std::optional<CompressionInformation> compression_info =
      std::get<1>(compressed_record_tuple);

  EXPECT_TRUE(compression_info.has_value());

  // Expect that compression information contains COMPRESSION_NONE
  EXPECT_THAT(compression_info.value().compression_algorithm(),
              Eq(CompressionInformation::COMPRESSION_NONE));
}

TEST_F(CompressionModuleTest, DynamicEnableDisable) {
  scoped_refptr<CompressionModule> test_compression_module =
      CompressionModule::Create(/*is_enabled=*/true, 0,
                                CompressionInformation::COMPRESSION_NONE);
  EXPECT_TRUE(test_compression_module->is_enabled());
  test_compression_module->SetValue(/*is_enabled=*/false);
  EXPECT_FALSE(test_compression_module->is_enabled());
  test_compression_module->SetValue(/*is_enabled=*/true);
  EXPECT_TRUE(test_compression_module->is_enabled());
}
}  // namespace
}  // namespace reporting

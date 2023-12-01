// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "federated/utils.h"

#include <memory>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "federated/mojom/example.mojom.h"
#include "federated/protos/example.pb.h"
#include "federated/protos/feature.pb.h"
#include "federated/test_utils.h"

namespace federated {
namespace {

using ::chromeos::federated::mojom::Example;
using ::chromeos::federated::mojom::ExamplePtr;
using ::chromeos::federated::mojom::Features;
using ::testing::ElementsAre;

TEST(UtilsTest, ConvertToTensorFlowExampleProto) {
  const auto example = CreateExamplePtr();

  const tensorflow::Example tf_example_converted =
      ConvertToTensorFlowExampleProto(example);
  const auto& tf_feature_map = tf_example_converted.features().feature();

  EXPECT_EQ(tf_feature_map.size(), 4);

  EXPECT_TRUE(tf_feature_map.contains("int_feature1"));
  const auto& int_feature1 = tf_feature_map.at("int_feature1");
  EXPECT_TRUE(int_feature1.has_int64_list() && !int_feature1.has_float_list() &&
              !int_feature1.has_bytes_list());
  EXPECT_THAT(int_feature1.int64_list().value(), ElementsAre(1, 2, 3, 4, 5));

  EXPECT_TRUE(tf_feature_map.contains("int_feature2"));
  const auto& int_feature2 = tf_feature_map.at("int_feature2");
  EXPECT_TRUE(int_feature2.has_int64_list() && !int_feature2.has_float_list() &&
              !int_feature2.has_bytes_list());
  EXPECT_THAT(int_feature2.int64_list().value(),
              ElementsAre(10, 20, 30, 40, 50));

  EXPECT_TRUE(tf_feature_map.contains("float_feature1"));
  const auto& float_feature = tf_feature_map.at("float_feature1");
  EXPECT_TRUE(!float_feature.has_int64_list() &&
              float_feature.has_float_list() &&
              !float_feature.has_bytes_list());
  EXPECT_THAT(float_feature.float_list().value(),
              ElementsAre(1.1, 2.1, 3.1, 4.1, 5.1));

  EXPECT_TRUE(tf_feature_map.contains("string_feature1"));
  const auto& string_feature = tf_feature_map.at("string_feature1");
  EXPECT_TRUE(!string_feature.has_int64_list() &&
              !string_feature.has_float_list() &&
              string_feature.has_bytes_list());
  EXPECT_THAT(string_feature.bytes_list().value(),
              ElementsAre("abc", "123", "xyz"));
}

TEST(UtilsTest, FilePaths) {
  const std::string sanitized_username = "foo";
  const std::string client_name = "bar";
  EXPECT_EQ(GetDatabasePath(sanitized_username).value(),
            "/run/daemon-store/federated/foo/examples.db");
  EXPECT_EQ(GetBaseDir(sanitized_username, client_name).value(),
            "/run/daemon-store/federated/foo/bar");
}

TEST(UtilsTest, ValidBrellaLibVersion) {
  // Valid release versions.
  auto brella_lib_version = ConvertBrellaLibVersion("15217.0.0");
  EXPECT_TRUE(brella_lib_version.has_value());
  EXPECT_EQ(brella_lib_version.value(), "chromeos_152170000000000");

  brella_lib_version = ConvertBrellaLibVersion("15217.123.4");
  EXPECT_TRUE(brella_lib_version.has_value());
  EXPECT_EQ(brella_lib_version.value(), "chromeos_152170001230004");

  brella_lib_version = ConvertBrellaLibVersion("123456789.123456.7890");
  EXPECT_TRUE(brella_lib_version.has_value());
  EXPECT_EQ(brella_lib_version.value(), "chromeos_1234567891234567890");
}

TEST(UtilsTest, InValidClientVersion) {
  // Major version is too long.
  EXPECT_EQ(ConvertBrellaLibVersion("1521715127.12345.67"), std::nullopt);

  // Minor version is too long.
  EXPECT_EQ(ConvertBrellaLibVersion("15217.1234567.8"), std::nullopt);

  // Sub version is too long.
  EXPECT_EQ(ConvertBrellaLibVersion("15217.123.45678"), std::nullopt);

  // Malformed patterns
  EXPECT_EQ(ConvertBrellaLibVersion("15217.123"), std::nullopt);
  EXPECT_EQ(ConvertBrellaLibVersion("15217.123.4.5"), std::nullopt);
  EXPECT_EQ(ConvertBrellaLibVersion("R109-15217.123.4"), std::nullopt);
}

}  // namespace
}  // namespace federated

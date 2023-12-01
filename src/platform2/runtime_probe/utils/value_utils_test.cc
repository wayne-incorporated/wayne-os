// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>
#include <utility>

#include <base/json/json_reader.h>
#include <base/values.h>
#include <gtest/gtest.h>

#include "runtime_probe/utils/value_utils.h"

namespace {

base::Value LoadValueFromJSON(const char* raw_json_content) {
  auto load_result = base::JSONReader::Read(raw_json_content);
  EXPECT_TRUE(load_result.has_value());
  return std::move(load_result.value());
}

}  // namespace

namespace runtime_probe {

TEST(ValueUtilsTest, TestPrependToDVKey) {
  auto dict_value = LoadValueFromJSON(R"({
    "key_1": "value_1",
    "key_2": 123
  })");
  auto expected_converted_dict_value = LoadValueFromJSON(R"({
    "the_prefix_key_1": "value_1",
    "the_prefix_key_2": 123
  })");

  PrependToDVKey(&dict_value, "the_prefix_");
  EXPECT_EQ(dict_value, expected_converted_dict_value);
}

TEST(ValueUtilsTest, TestRenameKey) {
  auto dict_value = LoadValueFromJSON(R"({
    "old_key_1": "value_1",
    "old_key_2": 123
  })");
  auto expected_converted_dict_value = LoadValueFromJSON(R"({
    "new_key_1": "value_1",
    "old_key_2": 123
  })");

  EXPECT_TRUE(RenameKey(&dict_value, "old_key_1", "new_key_1"));
  EXPECT_EQ(dict_value, expected_converted_dict_value);
}

TEST(ValueUtilsTest, TestRenameKeyWithNonDictValue) {
  base::Value int_value(123);
  auto expected_converted_int_value = int_value.Clone();

  EXPECT_FALSE(RenameKey(&int_value, "old_key", "new_key"));
  EXPECT_EQ(int_value, expected_converted_int_value);
}

TEST(ValueUtilsTest, TestRenameKeyWithNonExistKey) {
  auto dict_value = LoadValueFromJSON(R"({
    "old_key_1": "value_1",
    "old_key_2": 123
  })");
  auto expected_converted_dict_value = dict_value.Clone();

  EXPECT_FALSE(RenameKey(&dict_value, "old_key_3", "new_key_3"));
  EXPECT_EQ(dict_value, expected_converted_dict_value);
}

}  // namespace runtime_probe

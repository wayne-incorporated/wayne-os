// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/utils/type_conversions.h"

#include <map>
#include <string>
#include <vector>

#include <base/values.h>
#include <gtest/gtest.h>

namespace {

constexpr int kIntVariable = 123;
constexpr double kDoubleVariable = 0.1234567890123;
constexpr char kStringVariable[] = "abc";
const std::vector<int> kVectorIntVariable = {1, 2, 3};
const std::map<std::string, int> kMapIntVariable = {
    {"1", 1}, {"2", 2}, {"3", 3}};

}  // namespace

namespace rmad {

class TypeConversionsTest : public testing::Test {
 public:
  TypeConversionsTest() {}
};

TEST_F(TypeConversionsTest, ConvertToValue_bool) {
  EXPECT_EQ(base::Value(false), ConvertToValue(false));
  EXPECT_EQ(base::Value(true), ConvertToValue(true));
}

TEST_F(TypeConversionsTest, ConvertToValue_int) {
  EXPECT_EQ(base::Value(kIntVariable), ConvertToValue(kIntVariable));
}

TEST_F(TypeConversionsTest, ConvertToValue_double) {
  EXPECT_EQ(base::Value(kDoubleVariable), ConvertToValue(kDoubleVariable));
}

TEST_F(TypeConversionsTest, ConvertToValue_string) {
  EXPECT_EQ(base::Value(kStringVariable), ConvertToValue(kStringVariable));
}

TEST_F(TypeConversionsTest, ConvertToValue_vector) {
  base::Value value = ConvertToValue(kVectorIntVariable);
  for (int i = 0; i < kVectorIntVariable.size(); i++) {
    EXPECT_EQ(value.GetList()[i], ConvertToValue(kVectorIntVariable[i]));
  }
}

TEST_F(TypeConversionsTest, ConvertToValue_map) {
  base::Value value = ConvertToValue(kMapIntVariable);
  ASSERT_TRUE(value.is_dict());
  base::Value::Dict& dict = value.GetDict();
  for (const auto& [key, v] : kMapIntVariable) {
    EXPECT_EQ(*(dict.Find(key)), ConvertToValue(v));
  }
}

TEST_F(TypeConversionsTest, ConvertFromValue_bool) {
  bool v;
  base::Value value_false = ConvertToValue(false);
  EXPECT_TRUE(ConvertFromValue(&value_false, &v));
  EXPECT_FALSE(v);

  base::Value value_true = ConvertToValue(true);
  EXPECT_TRUE(ConvertFromValue(&value_true, &v));
  EXPECT_TRUE(v);
}

TEST_F(TypeConversionsTest, ConvertFromValue_int) {
  int v;
  base::Value value = ConvertToValue(kIntVariable);
  EXPECT_TRUE(ConvertFromValue(&value, &v));
  EXPECT_EQ(v, kIntVariable);
}

TEST_F(TypeConversionsTest, ConvertFromValue_double) {
  double v;
  base::Value value = ConvertToValue(kDoubleVariable);
  EXPECT_TRUE(ConvertFromValue(&value, &v));
  EXPECT_EQ(v, kDoubleVariable);
}

TEST_F(TypeConversionsTest, ConvertFromValue_string) {
  std::string v;
  base::Value value = ConvertToValue(kStringVariable);
  EXPECT_TRUE(ConvertFromValue(&value, &v));
  EXPECT_EQ(v, kStringVariable);
}

TEST_F(TypeConversionsTest, ConvertFromValue_vector) {
  std::vector<int> v;
  base::Value value = ConvertToValue(kVectorIntVariable);
  EXPECT_TRUE(ConvertFromValue(&value, &v));
  EXPECT_EQ(v, kVectorIntVariable);
}

TEST_F(TypeConversionsTest, ConvertFromValue_map) {
  std::map<std::string, int> v;
  base::Value value = ConvertToValue(kMapIntVariable);
  EXPECT_TRUE(ConvertFromValue(&value, &v));
  EXPECT_EQ(v, kMapIntVariable);
}

}  // namespace rmad

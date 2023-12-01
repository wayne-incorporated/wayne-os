// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>
#include <utility>

#include <base/json/json_reader.h>
#include <base/values.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "runtime_probe/field_converter.h"

namespace runtime_probe {

namespace {

using ReturnCode = FieldConverter::ReturnCode;

}  // namespace

TEST(StringFieldConverterTest, TestIntToString) {
  base::Value dict_value(base::Value::Type::DICT);
  auto& dict = dict_value.GetDict();
  dict.Set("key", 123);

  auto converter = StringFieldConverter::Build("");

  ASSERT_EQ(converter->Convert("key", &dict_value), ReturnCode::OK)
      << "failed to convert 123 to string";

  auto* string_value = dict.FindString("key");
  ASSERT_NE(string_value, nullptr);
  ASSERT_EQ(*string_value, "123");
}

TEST(StringFieldConverterTest, TestInvalidRegexPattern) {
  auto invalid = StringFieldConverter::Build("!re hello[");
  ASSERT_EQ(invalid, nullptr);

  auto valid = StringFieldConverter::Build("!eq hello[");
  ASSERT_TRUE(valid);
}

TEST(IntegerFieldConverterTest, TestStringToInt) {
  for (const auto s : {"123", "  123", "123  ", "  123  "}) {
    base::Value dict_value(base::Value::Type::DICT);
    auto& dict = dict_value.GetDict();
    dict.Set("key", s);

    auto converter = IntegerFieldConverter::Build("");

    ASSERT_EQ(converter->Convert("key", &dict_value), ReturnCode::OK)
        << "failed to convert string: " << s;

    auto int_value = dict.FindInt("key");
    ASSERT_TRUE(int_value.has_value());
    ASSERT_EQ(*int_value, 123) << s << " is not converted to 123";
  }
}

TEST(HexFieldConverterTest, TestHexStringToDecString) {
  static const struct {
    std::string input;
    std::string output;
  } cases[] = {
      {"7b", "123"},
      {"0x7b", "123"},
      {"  0x7b", "123"},
      {"  0x7b  ", "123"},
      {"0x7b  ", "123"},
      {"-0x7b", "-123"},
      {"0x80000000", "2147483648"},
      {"-0x80000000", "-2147483648"},
  };
  for (const auto& [in, out] : cases) {
    base::Value dict_value(base::Value::Type::DICT);
    dict_value.GetDict().Set("key", in);

    auto converter = HexFieldConverter::Build("");

    ASSERT_EQ(converter->Convert("key", &dict_value), ReturnCode::OK)
        << "failed to convert string: \"" << in << "\"";

    auto* string_value = dict_value.GetDict().FindString("key");
    ASSERT_NE(string_value, nullptr);
    ASSERT_EQ(*string_value, out)
        << "\"" << in << "\" is not converted to " << out;
  }
}

TEST(HexFieldConverterTest, TestIntToDecString) {
  static const struct {
    int input;
    std::string output;
  } cases[] = {
      {0x7b, "123"},
      {-0x7b, "-123"},
  };
  for (const auto& [in, out] : cases) {
    base::Value::Dict dict_value = base::Value::Dict().Set("key", in);

    auto converter = HexFieldConverter::Build("");

    auto value = base::Value(std::move(dict_value));
    ASSERT_EQ(converter->Convert("key", &value), ReturnCode::OK)
        << "failed to convert string: " << in;

    auto* string_value = value.GetDict().FindString("key");
    ASSERT_NE(string_value, nullptr);
    ASSERT_EQ(*string_value, out) << in << " is not converted to " << out;
  }
}

TEST(IntegerFieldConverterTest, TestDoubleToInt) {
  double v = 123.5;
  auto dict_value = base::Value::Dict().Set("key", v);

  auto converter = IntegerFieldConverter::Build("");

  auto value = base::Value(std::move(dict_value));
  ASSERT_EQ(converter->Convert("key", &value), ReturnCode::OK)
      << "failed to convert double";

  auto int_value = value.GetDict().FindInt("key");
  ASSERT_TRUE(int_value.has_value());
  ASSERT_EQ(*int_value, 123) << v << " is not converted to 123";
}

TEST(DoubleFieldConverterTest, TestStringToDouble) {
  for (const auto s : {"123.5", "  123.5", "123.5  ", "  123.5  "}) {
    base::Value dict_value(base::Value::Type::DICT);
    auto& dict = dict_value.GetDict();
    dict.Set("key", s);

    auto converter = DoubleFieldConverter::Build("");

    ASSERT_EQ(converter->Convert("key", &dict_value), ReturnCode::OK)
        << "failed to convert string: " << s;

    auto double_value = dict.FindDouble("key");
    ASSERT_TRUE(double_value.has_value());
    ASSERT_EQ(*double_value, 123.5) << s << " is not converted to 123.5";
  }
}

TEST(DoubleFieldConverterTest, TestInvalidStringToDouble) {
  for (const auto s : {"this is not double", "", "   "}) {
    base::Value dict_value(base::Value::Type::DICT);
    dict_value.GetDict().Set("key", s);

    auto converter = DoubleFieldConverter::Build("");

    ASSERT_EQ(converter->Convert("key", &dict_value),
              ReturnCode::INCOMPATIBLE_VALUE)
        << "Converting " << s << " to double should fail";
  }
}

TEST(StringFieldConverterTest, TestValidateRule) {
  const auto json_string = R"({
    "0": "hello world",
    "1": "hello ???",
    "2": "??? hello ???",
    "3": "??? hello"
  })";
  auto dict_value = base::JSONReader::Read(json_string);
  ASSERT_TRUE(dict_value.has_value());
  ASSERT_TRUE(dict_value->is_dict());
  {
    auto converter = StringFieldConverter::Build("!ne hello world");
    ASSERT_EQ(converter->operator_, ValidatorOperator::NE);
    ASSERT_EQ(converter->regex_, nullptr);
    ASSERT_EQ(converter->operand_, "hello world");
    ASSERT_EQ(converter->Validate("0", &*dict_value),
              ReturnCode::INVALID_VALUE);
    ASSERT_EQ(converter->Validate("1", &*dict_value), ReturnCode::OK);
    ASSERT_EQ(converter->Validate("2", &*dict_value), ReturnCode::OK);
  }
  {
    auto converter = StringFieldConverter::Build("!eq hello world");
    ASSERT_EQ(converter->operator_, ValidatorOperator::EQ);
    ASSERT_EQ(converter->regex_, nullptr);
    ASSERT_EQ(converter->operand_, "hello world");
    ASSERT_EQ(converter->Validate("0", &*dict_value), ReturnCode::OK);
    ASSERT_EQ(converter->Validate("1", &*dict_value),
              ReturnCode::INVALID_VALUE);
    ASSERT_EQ(converter->Validate("2", &*dict_value),
              ReturnCode::INVALID_VALUE);
  }
  {
    auto converter = StringFieldConverter::Build("!re hello .*");
    ASSERT_EQ(converter->operator_, ValidatorOperator::RE);
    ASSERT_EQ(converter->regex_->pattern(), "hello .*");
    ASSERT_EQ(converter->Validate("0", &*dict_value), ReturnCode::OK);
    ASSERT_EQ(converter->Validate("1", &*dict_value), ReturnCode::OK);
    ASSERT_EQ(converter->Validate("2", &*dict_value),
              ReturnCode::INVALID_VALUE);
  }
  {
    auto converter = StringFieldConverter::Build("!re .* hello");
    ASSERT_EQ(converter->operator_, ValidatorOperator::RE);
    ASSERT_EQ(converter->regex_->pattern(), ".* hello");
    ASSERT_EQ(converter->Validate("0", &*dict_value),
              ReturnCode::INVALID_VALUE);
    ASSERT_EQ(converter->Validate("1", &*dict_value),
              ReturnCode::INVALID_VALUE);
    ASSERT_EQ(converter->Validate("2", &*dict_value),
              ReturnCode::INVALID_VALUE);
    ASSERT_EQ(converter->Validate("3", &*dict_value), ReturnCode::OK);
  }
}

TEST(IntegerFieldConverterTest, TestValidateRule) {
  const auto json_string = R"({
    "0": 0,
    "1": 1,
    "2": 2
  })";
  auto dict_value = base::JSONReader::Read(json_string);
  ASSERT_TRUE(dict_value.has_value());
  ASSERT_TRUE(dict_value->is_dict());
  {
    auto converter = IntegerFieldConverter::Build("!ne 1");
    ASSERT_EQ(converter->operator_, ValidatorOperator::NE);
    ASSERT_EQ(converter->operand_, 1);
    ASSERT_EQ(converter->Validate("0", &*dict_value), ReturnCode::OK);
    ASSERT_EQ(converter->Validate("1", &*dict_value),
              ReturnCode::INVALID_VALUE);
    ASSERT_EQ(converter->Validate("2", &*dict_value), ReturnCode::OK);
  }
  {
    auto converter = IntegerFieldConverter::Build("!eq 1");
    ASSERT_EQ(converter->operator_, ValidatorOperator::EQ);
    ASSERT_EQ(converter->operand_, 1);
    ASSERT_EQ(converter->Validate("0", &*dict_value),
              ReturnCode::INVALID_VALUE);
    ASSERT_EQ(converter->Validate("1", &*dict_value), ReturnCode::OK);
    ASSERT_EQ(converter->Validate("2", &*dict_value),
              ReturnCode::INVALID_VALUE);
  }
  {
    auto converter = IntegerFieldConverter::Build("!gt 1");
    ASSERT_EQ(converter->operator_, ValidatorOperator::GT);
    ASSERT_EQ(converter->operand_, 1);
    ASSERT_EQ(converter->Validate("0", &*dict_value),
              ReturnCode::INVALID_VALUE);
    ASSERT_EQ(converter->Validate("1", &*dict_value),
              ReturnCode::INVALID_VALUE);
    ASSERT_EQ(converter->Validate("2", &*dict_value), ReturnCode::OK);
  }
  {
    auto converter = IntegerFieldConverter::Build("!ge 1");
    ASSERT_EQ(converter->operator_, ValidatorOperator::GE);
    ASSERT_EQ(converter->operand_, 1);
    ASSERT_EQ(converter->Validate("0", &*dict_value),
              ReturnCode::INVALID_VALUE);
    ASSERT_EQ(converter->Validate("1", &*dict_value), ReturnCode::OK);
    ASSERT_EQ(converter->Validate("2", &*dict_value), ReturnCode::OK);
  }
  {
    auto converter = IntegerFieldConverter::Build("!lt 1");
    ASSERT_EQ(converter->operator_, ValidatorOperator::LT);
    ASSERT_EQ(converter->operand_, 1);
    ASSERT_EQ(converter->Validate("0", &*dict_value), ReturnCode::OK);
    ASSERT_EQ(converter->Validate("1", &*dict_value),
              ReturnCode::INVALID_VALUE);
    ASSERT_EQ(converter->Validate("2", &*dict_value),
              ReturnCode::INVALID_VALUE);
  }
  {
    auto converter = IntegerFieldConverter::Build("!le 1");
    ASSERT_EQ(converter->operator_, ValidatorOperator::LE);
    ASSERT_EQ(converter->operand_, 1);
    ASSERT_EQ(converter->Validate("0", &*dict_value), ReturnCode::OK);
    ASSERT_EQ(converter->Validate("1", &*dict_value), ReturnCode::OK);
    ASSERT_EQ(converter->Validate("2", &*dict_value),
              ReturnCode::INVALID_VALUE);
  }
}

TEST(HexFieldConverterTest, TestValidateRule) {
  const auto json_string = R"({
    "0": 0,
    "1": 1,
    "2": 2
  })";
  auto dict_value = base::JSONReader::Read(json_string);
  ASSERT_TRUE(dict_value.has_value());
  ASSERT_TRUE(dict_value->is_dict());
  {
    auto converter = HexFieldConverter::Build("!ne 1");
    ASSERT_EQ(converter->operator_, ValidatorOperator::NE);
    ASSERT_EQ(converter->operand_, 1);
    ASSERT_EQ(converter->Validate("0", &*dict_value), ReturnCode::OK);
    ASSERT_EQ(converter->Validate("1", &*dict_value),
              ReturnCode::INVALID_VALUE);
    ASSERT_EQ(converter->Validate("2", &*dict_value), ReturnCode::OK);
  }
  {
    auto converter = HexFieldConverter::Build("!eq 1");
    ASSERT_EQ(converter->operator_, ValidatorOperator::EQ);
    ASSERT_EQ(converter->operand_, 1);
    ASSERT_EQ(converter->Validate("0", &*dict_value),
              ReturnCode::INVALID_VALUE);
    ASSERT_EQ(converter->Validate("1", &*dict_value), ReturnCode::OK);
    ASSERT_EQ(converter->Validate("2", &*dict_value),
              ReturnCode::INVALID_VALUE);
  }
  {
    auto converter = HexFieldConverter::Build("!gt 1");
    ASSERT_EQ(converter->operator_, ValidatorOperator::GT);
    ASSERT_EQ(converter->operand_, 1);
    ASSERT_EQ(converter->Validate("0", &*dict_value),
              ReturnCode::INVALID_VALUE);
    ASSERT_EQ(converter->Validate("1", &*dict_value),
              ReturnCode::INVALID_VALUE);
    ASSERT_EQ(converter->Validate("2", &*dict_value), ReturnCode::OK);
  }
  {
    auto converter = HexFieldConverter::Build("!ge 1");
    ASSERT_EQ(converter->operator_, ValidatorOperator::GE);
    ASSERT_EQ(converter->operand_, 1);
    ASSERT_EQ(converter->Validate("0", &*dict_value),
              ReturnCode::INVALID_VALUE);
    ASSERT_EQ(converter->Validate("1", &*dict_value), ReturnCode::OK);
    ASSERT_EQ(converter->Validate("2", &*dict_value), ReturnCode::OK);
  }
  {
    auto converter = HexFieldConverter::Build("!lt 1");
    ASSERT_EQ(converter->operator_, ValidatorOperator::LT);
    ASSERT_EQ(converter->operand_, 1);
    ASSERT_EQ(converter->Validate("0", &*dict_value), ReturnCode::OK);
    ASSERT_EQ(converter->Validate("1", &*dict_value),
              ReturnCode::INVALID_VALUE);
    ASSERT_EQ(converter->Validate("2", &*dict_value),
              ReturnCode::INVALID_VALUE);
  }
  {
    auto converter = HexFieldConverter::Build("!le 1");
    ASSERT_EQ(converter->operator_, ValidatorOperator::LE);
    ASSERT_EQ(converter->operand_, 1);
    ASSERT_EQ(converter->Validate("0", &*dict_value), ReturnCode::OK);
    ASSERT_EQ(converter->Validate("1", &*dict_value), ReturnCode::OK);
    ASSERT_EQ(converter->Validate("2", &*dict_value),
              ReturnCode::INVALID_VALUE);
  }
}

TEST(DoubleFieldConverterTest, TestValidateRule) {
  const auto json_string = R"({
    "0": 0,
    "1": 1,
    "2": 2
  })";
  auto dict_value = base::JSONReader::Read(json_string);
  ASSERT_TRUE(dict_value.has_value());
  ASSERT_TRUE(dict_value->is_dict());
  {
    auto converter = DoubleFieldConverter::Build("!ne 1");
    ASSERT_EQ(converter->operator_, ValidatorOperator::NE);
    ASSERT_EQ(converter->operand_, 1);
    ASSERT_EQ(converter->Validate("0", &*dict_value), ReturnCode::OK);
    ASSERT_EQ(converter->Validate("1", &*dict_value),
              ReturnCode::INVALID_VALUE);
    ASSERT_EQ(converter->Validate("2", &*dict_value), ReturnCode::OK);
  }
  {
    auto converter = DoubleFieldConverter::Build("!eq 1");
    ASSERT_EQ(converter->operator_, ValidatorOperator::EQ);
    ASSERT_EQ(converter->operand_, 1);
    ASSERT_EQ(converter->Validate("0", &*dict_value),
              ReturnCode::INVALID_VALUE);
    ASSERT_EQ(converter->Validate("1", &*dict_value), ReturnCode::OK);
    ASSERT_EQ(converter->Validate("2", &*dict_value),
              ReturnCode::INVALID_VALUE);
  }
  {
    auto converter = DoubleFieldConverter::Build("!gt 1");
    ASSERT_EQ(converter->operator_, ValidatorOperator::GT);
    ASSERT_EQ(converter->operand_, 1);
    ASSERT_EQ(converter->Validate("0", &*dict_value),
              ReturnCode::INVALID_VALUE);
    ASSERT_EQ(converter->Validate("1", &*dict_value),
              ReturnCode::INVALID_VALUE);
    ASSERT_EQ(converter->Validate("2", &*dict_value), ReturnCode::OK);
  }
  {
    auto converter = DoubleFieldConverter::Build("!ge 1");
    ASSERT_EQ(converter->operator_, ValidatorOperator::GE);
    ASSERT_EQ(converter->operand_, 1);
    ASSERT_EQ(converter->Validate("0", &*dict_value),
              ReturnCode::INVALID_VALUE);
    ASSERT_EQ(converter->Validate("1", &*dict_value), ReturnCode::OK);
    ASSERT_EQ(converter->Validate("2", &*dict_value), ReturnCode::OK);
  }
  {
    auto converter = DoubleFieldConverter::Build("!lt 1");
    ASSERT_EQ(converter->operator_, ValidatorOperator::LT);
    ASSERT_EQ(converter->operand_, 1);
    ASSERT_EQ(converter->Validate("0", &*dict_value), ReturnCode::OK);
    ASSERT_EQ(converter->Validate("1", &*dict_value),
              ReturnCode::INVALID_VALUE);
    ASSERT_EQ(converter->Validate("2", &*dict_value),
              ReturnCode::INVALID_VALUE);
  }
  {
    auto converter = DoubleFieldConverter::Build("!le 1");
    ASSERT_EQ(converter->operator_, ValidatorOperator::LE);
    ASSERT_EQ(converter->operand_, 1);
    ASSERT_EQ(converter->Validate("0", &*dict_value), ReturnCode::OK);
    ASSERT_EQ(converter->Validate("1", &*dict_value), ReturnCode::OK);
    ASSERT_EQ(converter->Validate("2", &*dict_value),
              ReturnCode::INVALID_VALUE);
  }
}

}  // namespace runtime_probe

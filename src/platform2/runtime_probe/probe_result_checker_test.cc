// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "runtime_probe/probe_result_checker.h"

#include <memory>
#include <utility>
#include <vector>

#include <base/json/json_reader.h>
#include <base/values.h>
#include <brillo/map_utils.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace runtime_probe {

namespace {

using ::testing::_;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::StrictMock;
using ::testing::UnorderedElementsAre;

class MockProbeResultChecker : public ProbeResultChecker {
 public:
  MOCK_METHOD(bool, Apply, (base::Value * probe_result), (const, override));
};

}  // namespace

TEST(ProbeResultCheckerDictTest, TestFromValue) {
  const auto json_string = R"({
    "string_field": [true, "str"],
    "string_field_exact_match": [true, "str", "!eq xx[yy"],
    "string_field_with_validate_rule": [true, "str", "!re hello_.*"],
    "int_field": [true, "int"],
    "double_field": [true, "double"],
    "hex_field": [false, "hex"]
  })";
  auto dict_value = base::JSONReader::Read(json_string);
  ASSERT_TRUE(dict_value.has_value());
  ASSERT_TRUE(dict_value->is_dict());

  auto expect_fields = ProbeResultCheckerDict::FromValue(*dict_value);
  ASSERT_TRUE(expect_fields.get());

  const auto& required = expect_fields->required_fields_;
  ASSERT_THAT(brillo::GetMapKeys(required),
              UnorderedElementsAre("string_field", "string_field_exact_match",
                                   "string_field_with_validate_rule",
                                   "int_field", "double_field"));
  ASSERT_TRUE(
      dynamic_cast<StringFieldConverter*>(required.at("string_field").get()));
  ASSERT_TRUE(dynamic_cast<StringFieldConverter*>(
      required.at("string_field_exact_match").get()));
  ASSERT_TRUE(dynamic_cast<StringFieldConverter*>(
      required.at("string_field_exact_match").get()));
  ASSERT_TRUE(dynamic_cast<StringFieldConverter*>(
      required.at("string_field_with_validate_rule").get()));
  ASSERT_TRUE(
      dynamic_cast<IntegerFieldConverter*>(required.at("int_field").get()));
  ASSERT_TRUE(
      dynamic_cast<DoubleFieldConverter*>(required.at("double_field").get()));

  const auto& optional = expect_fields->optional_fields_;
  ASSERT_THAT(brillo::GetMapKeys(optional), UnorderedElementsAre("hex_field"));
  ASSERT_TRUE(dynamic_cast<HexFieldConverter*>(optional.at("hex_field").get()));
}

TEST(ProbeResultCheckerDictTest, TestApplySuccess) {
  const auto expect_string = R"({
    "str": [true, "str"],
    "int": [true, "int"],
    "hex": [true, "hex"],
    "double": [true, "double"]
  })";

  const auto probe_result_string = R"({
    "str": "string result",
    "int": "1024",
    "hex": "0x7b",
    "double": "1e2"
  })";

  auto expect = base::JSONReader::Read(expect_string);
  ASSERT_TRUE(expect.has_value());
  ASSERT_TRUE(expect->is_dict());

  auto probe_result = base::JSONReader::Read(probe_result_string);
  ASSERT_TRUE(probe_result.has_value());
  ASSERT_TRUE(probe_result->is_dict());

  const auto& probe_result_dict = probe_result->GetDict();

  auto checker = ProbeResultCheckerDict::FromValue(*expect);

  ASSERT_TRUE(checker->Apply(&*probe_result));

  auto* str_value = probe_result_dict.FindString("str");
  ASSERT_NE(str_value, nullptr);
  ASSERT_EQ(*str_value, "string result");

  auto int_value = probe_result_dict.FindInt("int");
  ASSERT_TRUE(int_value.has_value());
  ASSERT_EQ(*int_value, 1024);

  auto* hex_value = probe_result_dict.FindString("hex");
  ASSERT_NE(hex_value, nullptr);
  ASSERT_EQ(*hex_value, "123");

  auto double_value = probe_result_dict.FindDouble("double");
  ASSERT_TRUE(double_value.has_value());
  ASSERT_EQ(*double_value, 100);
}

TEST(ProbeResultCheckerDictTest, TestApplyWithLimitsSuccess) {
  const auto expect_string = R"({
    "str": [true, "str", "!eq string result"],
    "int": [true, "int", "!gt 1000"],
    "hex": [true, "hex", "!ne 0x0"],
    "double": [true, "double", "!lt 1e3"]
  })";

  const auto probe_result_string = R"({
    "str": "string result",
    "int": "1024",
    "hex": "0x7b",
    "double": "1e2"
  })";

  auto expect = base::JSONReader::Read(expect_string);
  ASSERT_TRUE(expect.has_value());
  ASSERT_TRUE(expect->is_dict());

  auto probe_result = base::JSONReader::Read(probe_result_string);
  ASSERT_TRUE(probe_result.has_value());
  ASSERT_TRUE(probe_result->is_dict());

  auto checker = ProbeResultCheckerDict::FromValue(*expect);

  ASSERT_TRUE(checker->Apply(&*probe_result));

  const auto& probe_result_dict = probe_result->GetDict();

  auto* str_value = probe_result_dict.FindString("str");
  ASSERT_NE(str_value, nullptr);
  ASSERT_EQ(*str_value, "string result");

  auto int_value = probe_result_dict.FindInt("int");
  ASSERT_TRUE(int_value.has_value());
  ASSERT_EQ(*int_value, 1024);

  auto* hex_value = probe_result_dict.FindString("hex");
  ASSERT_NE(hex_value, nullptr);
  ASSERT_EQ(*hex_value, "123");

  auto double_value = probe_result_dict.FindDouble("double");
  ASSERT_TRUE(double_value.has_value());
  ASSERT_EQ(*double_value, 100);
}

TEST(ProbeResultCheckerDictTest, TestApplyWithLimitsFail) {
  // For each field converter, |TestValidateRule| should already check each kind
  // of operators.  This function only checks if |Apply| function would return
  // |false| if any of the fields is invalid.
  const auto expect_string = R"({
    "str": [true, "str", "!eq string result"],
    "int": [true, "int", "!gt 1000"],
    "hex": [true, "hex", "!ne 0x0"],
    "double": [true, "double", "!lt 1e3"]
  })";
  const auto probe_result_string = R"({
    "str": "This doesn't match!",
    "int": "1024",
    "hex": "0x7b",
    "double": "1e2"
  })";

  auto expect = base::JSONReader::Read(expect_string);
  ASSERT_TRUE(expect.has_value());
  ASSERT_TRUE(expect->is_dict());

  auto probe_result = base::JSONReader::Read(probe_result_string);
  ASSERT_TRUE(probe_result.has_value());
  ASSERT_TRUE(probe_result->is_dict());

  auto checker = ProbeResultCheckerDict::FromValue(*expect);

  ASSERT_FALSE(checker->Apply(&*probe_result));
}

TEST(ProbeResultCheckerListTest, TestFromValue) {
  const auto json_string = R"([
    {
      "string_field": [true, "str"],
      "hex_field": [false, "hex"]
    },
    {
      "string_field": [false, "str"],
      "hex_field": [true, "hex"]
    }
  ])";
  const auto list_value = base::JSONReader::Read(json_string);
  ASSERT_TRUE(list_value.has_value());
  ASSERT_TRUE(list_value->is_list());

  const auto checker_list = ProbeResultCheckerList::FromValue(*list_value);
  ASSERT_EQ(checker_list->checkers.size(), 2);

  {
    const auto expect_fields = dynamic_cast<ProbeResultCheckerDict*>(
        checker_list->checkers.at(0).get());
    ASSERT_TRUE(expect_fields);

    const auto& required = expect_fields->required_fields_;
    ASSERT_THAT(brillo::GetMapKeys(required),
                UnorderedElementsAre("string_field"));
    ASSERT_TRUE(
        dynamic_cast<StringFieldConverter*>(required.at("string_field").get()));

    const auto& optional = expect_fields->optional_fields_;
    ASSERT_THAT(brillo::GetMapKeys(optional),
                UnorderedElementsAre("hex_field"));
    ASSERT_TRUE(
        dynamic_cast<HexFieldConverter*>(optional.at("hex_field").get()));
  }

  {
    const auto expect_fields = dynamic_cast<ProbeResultCheckerDict*>(
        checker_list->checkers.at(1).get());
    ASSERT_TRUE(expect_fields);

    const auto& required = expect_fields->required_fields_;
    ASSERT_THAT(brillo::GetMapKeys(required),
                UnorderedElementsAre("hex_field"));
    ASSERT_TRUE(
        dynamic_cast<HexFieldConverter*>(required.at("hex_field").get()));

    const auto& optional = expect_fields->optional_fields_;
    ASSERT_THAT(brillo::GetMapKeys(optional),
                UnorderedElementsAre("string_field"));
    ASSERT_TRUE(
        dynamic_cast<StringFieldConverter*>(optional.at("string_field").get()));
  }
}

TEST(ProbeResultCheckerListTest, TestApply) {
  std::vector<std::pair<std::vector<bool>, bool>> testdata = {
      {{}, true},
      {{true}, true},
      {{false}, false},
      {{true, false}, true},
      {{false, true}, true},
      {{false, false}, false}};
  for (const auto& [inputs, output] : testdata) {
    auto checker_list = std::make_unique<ProbeResultCheckerList>();
    for (const auto& input : inputs) {
      auto mock_checker = std::make_unique<NiceMock<MockProbeResultChecker>>();
      ON_CALL(*mock_checker, Apply(_)).WillByDefault(Return(input));
      checker_list->checkers.push_back(std::move(mock_checker));
    }
    auto probe_result_stub = std::make_unique<base::Value>();
    ASSERT_EQ(output, checker_list->Apply(&*probe_result_stub));
  }
}

TEST(ProbeResultCheckerListTest, TestApplyShortCircuit) {
  auto checker_list = std::make_unique<ProbeResultCheckerList>();

  auto mock_checker = std::make_unique<StrictMock<MockProbeResultChecker>>();
  EXPECT_CALL(*mock_checker, Apply(_)).WillOnce(Return(true));
  checker_list->checkers.push_back(std::move(mock_checker));

  // This checker should not be called.
  mock_checker = std::make_unique<StrictMock<MockProbeResultChecker>>();
  checker_list->checkers.push_back(std::move(mock_checker));

  auto probe_result_stub = std::make_unique<base::Value>();
  ASSERT_TRUE(checker_list->Apply(&*probe_result_stub));
}

TEST(ProbeResultCheckerTest, TestFromValueDict) {
  const auto json_string = R"({})";
  const auto list_value = base::JSONReader::Read(json_string);
  ASSERT_TRUE(list_value.has_value());
  ASSERT_TRUE(list_value->is_dict());

  const auto checker = ProbeResultChecker::FromValue(*list_value);
  ASSERT_TRUE(dynamic_cast<ProbeResultCheckerDict*>(checker.get()));
}

TEST(ProbeResultCheckerTest, TestFromValueList) {
  const auto json_string = R"([])";
  const auto list_value = base::JSONReader::Read(json_string);
  ASSERT_TRUE(list_value.has_value());
  ASSERT_TRUE(list_value->is_list());

  const auto checker = ProbeResultChecker::FromValue(*list_value);
  ASSERT_TRUE(dynamic_cast<ProbeResultCheckerList*>(checker.get()));
}

}  // namespace runtime_probe

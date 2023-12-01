// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "runtime_probe/component_category.h"

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/json/json_reader.h>
#include <base/values.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "runtime_probe/probe_statement.h"

namespace runtime_probe {

namespace {

using ::testing::ElementsAre;
using ::testing::NiceMock;

class MockProbeStatement : public ProbeStatement {
 public:
  MOCK_METHOD(base::Value::List, Eval, (), (const, override));
  MOCK_METHOD(std::optional<base::Value>,
              GetInformation,
              (),
              (const, override));
};

class ComponentCategoryTest : public ::testing::Test {
 protected:
  // Set a mocked probe statement that would return |eval_result| on
  // calling ProbeStatement::Eval(), and return |information| on calling
  // ProbeStatement::GetInformation() for |component_category|.
  void SetComponent(
      ComponentCategory& component_category,
      const std::string& component_name,
      const base::Value::List& eval_result,
      const std::optional<base::Value>& information = std::nullopt) {
    auto probe_statement = std::make_unique<NiceMock<MockProbeStatement>>();
    ON_CALL(*probe_statement, Eval).WillByDefault([&eval_result]() {
      return eval_result.Clone();
    });

    if (information) {
      ON_CALL(*probe_statement, GetInformation).WillByDefault([&information]() {
        return information->Clone();
      });
    } else {
      ON_CALL(*probe_statement, GetInformation).WillByDefault([]() {
        return std::nullopt;
      });
    }
    component_category.SetComponentForTesting(component_name,
                                              std::move(probe_statement));
  }
};

}  // namespace

TEST_F(ComponentCategoryTest, FromNonDictionaryValue) {
  auto non_dict_value = base::JSONReader::Read("[]");
  auto category = ComponentCategory::FromValue("category_1", *non_dict_value);
  EXPECT_EQ(category, nullptr);
}

TEST_F(ComponentCategoryTest, Eval) {
  auto dict_value = base::JSONReader::Read("{}");
  auto category = ComponentCategory::FromValue("category_1", *dict_value);
  EXPECT_TRUE(category);

  const auto eval_result_1 = base::JSONReader::Read(R"([
    {
      "field_1": "value_1"
    },
    {
      "field_1": "value_2"
    }
  ])");
  const auto eval_result_2 = base::JSONReader::Read(R"([
    {
      "field_1": "value_3"
    }
  ])");
  SetComponent(*category, "component_1", eval_result_1->GetList());
  SetComponent(*category, "component_2", eval_result_2->GetList());

  auto ans = base::JSONReader::Read(R"([
    {
      "name": "component_1",
      "values": {
        "field_1": "value_1"
      }
    },
    {
      "name": "component_1",
      "values": {
        "field_1": "value_2"
      }
    },
    {
      "name": "component_2",
      "values": {
        "field_1": "value_3"
      }
    }
  ])");
  auto res = category->Eval();
  EXPECT_EQ(res, ans);
}

TEST_F(ComponentCategoryTest, EvalWithInformation) {
  auto dict_value = base::JSONReader::Read("{}");
  auto category = ComponentCategory::FromValue("category_1", *dict_value);
  EXPECT_TRUE(category);

  const auto eval_result_1 = base::JSONReader::Read(R"([
    {
      "field_1": "value_1"
    },
    {
      "field_1": "value_2"
    }
  ])");
  const auto info = base::JSONReader::Read(R"({
    "info_field": "info_value"
  })");
  SetComponent(*category, "component_1", eval_result_1->GetList(), info);

  auto ans = base::JSONReader::Read(R"([
    {
      "name": "component_1",
      "values": {
        "field_1": "value_1"
      },
      "information": {
        "info_field": "info_value"
      }
    },
    {
      "name": "component_1",
      "values": {
        "field_1": "value_2"
      },
      "information": {
        "info_field": "info_value"
      }
    }
  ])");
  auto res = category->Eval();
  EXPECT_EQ(res, ans);
}

TEST_F(ComponentCategoryTest, GetComponentNames) {
  auto dict_value = base::JSONReader::Read("{}");
  auto category = ComponentCategory::FromValue("category_1", *dict_value);
  EXPECT_TRUE(category);

  const auto eval_result_1 = base::JSONReader::Read(R"([
    {
      "field_1": "value_1"
    }
  ])");
  const auto eval_result_2 = base::JSONReader::Read(R"([
    {
      "field_1": "value_2"
    }
  ])");
  SetComponent(*category, "component_1", eval_result_1->GetList());
  SetComponent(*category, "component_2", eval_result_2->GetList());

  auto res = category->GetComponentNames();
  EXPECT_THAT(res, ElementsAre("component_1", "component_2"));
}
}  // namespace runtime_probe

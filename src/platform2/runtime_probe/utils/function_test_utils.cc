// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <algorithm>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/json/json_reader.h>
#include <gtest/gtest.h>

#include "runtime_probe/utils/function_test_utils.h"

namespace runtime_probe {

BaseFunctionTest::BaseFunctionTest() {
  SetTestRoot(mock_context()->root_dir());
}

BaseFunctionTest::~BaseFunctionTest() = default;

// static
base::Value::List BaseFunctionTest::CreateProbeResultFromJson(
    const std::string& str) {
  auto res = base::JSONReader::Read(str);
  CHECK(res.has_value() && res->is_list());
  return std::move(res->GetList());
}

// static
void BaseFunctionTest::ExpectUnorderedListEqual(const base::Value::List& result,
                                                const base::Value::List& ans) {
  // A workaround for UnorderedElementsAreArray() not accepting non-copyable
  // types.
  std::vector<::testing::Matcher<std::reference_wrapper<const base::Value>>>
      ans_matcher_list;
  std::transform(
      ans.begin(), ans.end(), std::back_inserter(ans_matcher_list),
      [](const base::Value& entry) { return ::testing::Eq(std::cref(entry)); });

  EXPECT_THAT(result, ::testing::UnorderedElementsAreArray(ans_matcher_list));
}

}  // namespace runtime_probe

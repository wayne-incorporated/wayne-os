// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>
#include <utility>

#include <base/json/json_reader.h>
#include <gtest/gtest.h>

#include "runtime_probe/probe_function.h"
#include "runtime_probe/utils/function_test_utils.h"

namespace runtime_probe {
namespace {

class MockProbeFunction : public ProbeFunction {
  using ProbeFunction::ProbeFunction;

 public:
  NAME_PROBE_FUNCTION("mock_function");

  DataType EvalImpl() const override { return {}; }
};

class FuntionTestUtilsTest : public BaseFunctionTest {};

TEST_F(FuntionTestUtilsTest, CreateFakeProbeFunction) {
  auto probe_result = R"JSON(
      [{
        "field_1": "value_1",
        "field_2": "value_2"
      }]
    )JSON";
  auto probe_function =
      CreateFakeProbeFunction<MockProbeFunction>(probe_result);
  // CreateFakeProbeFunction<T>() should return a pointer to |T| pointing
  // to an object of |FakeProbeFunction<T>|, which is a derived class of |T|.
  static_assert(
      std::is_base_of_v<MockProbeFunction,
                        std::remove_reference_t<decltype(*probe_function)>>,
      "probe_function is not a pointer to MockProbeFunction");
  EXPECT_NE(
      dynamic_cast<FakeProbeFunction<MockProbeFunction>*>(probe_function.get()),
      nullptr);

  auto result = probe_function->Eval();
  auto ans = CreateProbeResultFromJson(probe_result);

  EXPECT_EQ(result, ans);
}

}  // namespace
}  // namespace runtime_probe

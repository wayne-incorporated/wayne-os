// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RUNTIME_PROBE_UTILS_FUNCTION_TEST_UTILS_H_
#define RUNTIME_PROBE_UTILS_FUNCTION_TEST_UTILS_H_

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/json/json_reader.h>
#include <base/values.h>

#include "runtime_probe/probe_function.h"
#include "runtime_probe/system/context_mock_impl.h"
#include "runtime_probe/utils/file_test_utils.h"

namespace runtime_probe {

// A helper class for creating probe function related unittest.
class BaseFunctionTest : public BaseFileTest {
 protected:
  BaseFunctionTest();
  BaseFunctionTest(const BaseFunctionTest&) = delete;
  BaseFunctionTest& operator=(const BaseFunctionTest&) = delete;
  ~BaseFunctionTest();

 protected:
  // Helper function to create the expected probe result form a json string.
  static base::Value::List CreateProbeResultFromJson(const std::string& str);

  // Helper function to make an assertion that |result| is equal to some
  // permutation of |ans|.Use this function for indeterminate order results.
  static void ExpectUnorderedListEqual(const base::Value::List& result,
                                       const base::Value::List& ans);

  ContextMockImpl* mock_context() { return &mock_context_; }

 private:
  ::testing::NiceMock<ContextMockImpl> mock_context_;
};

// A fake probe function that always gets |fake_result_| as probe results.
template <typename ProbeFunctionType>
class FakeProbeFunction : public ProbeFunctionType {
  using ProbeFunctionType::ProbeFunctionType;

 public:
  typename ProbeFunctionType::DataType fake_result_;

 private:
  typename ProbeFunctionType::DataType EvalImpl() const override {
    return fake_result_.Clone();
  }
};

// Create a fake of |ProbeFunctionType| that always returns |probe_result|.
template <typename ProbeFunctionType>
std::unique_ptr<ProbeFunctionType> CreateFakeProbeFunction(
    const std::string& probe_result) {
  auto probe_function =
      CreateProbeFunction<FakeProbeFunction<ProbeFunctionType>>(
          base::Value::Dict{});
  auto res = base::JSONReader::Read(probe_result);
  probe_function->fake_result_ = std::move(res->GetList());
  return probe_function;
}

}  // namespace runtime_probe

#endif  // RUNTIME_PROBE_UTILS_FUNCTION_TEST_UTILS_H_

// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <map>
#include <string>

#include <gtest/gtest.h>

#include "runtime_probe/probe_function.h"
#include "runtime_probe/probe_function_argument.h"

namespace runtime_probe {
namespace {

class BaseProbeFunction : public ProbeFunction {
  using ProbeFunction::ProbeFunction;

 public:
  DataType EvalImpl() const override { return {}; }
};

class NoArgProbeFunction : public BaseProbeFunction {
  using BaseProbeFunction::BaseProbeFunction;

 public:
  NAME_PROBE_FUNCTION("no_arg");
};

class NoArg2ProbeFunction : public BaseProbeFunction {
  using BaseProbeFunction::BaseProbeFunction;

 public:
  NAME_PROBE_FUNCTION("no_arg2");
};

class ArgProbeFunction : public BaseProbeFunction {
  using BaseProbeFunction::BaseProbeFunction;

 public:
  NAME_PROBE_FUNCTION("arg");

  bool PostParseArguments() override { return post_parse_arg_result_; }

  PROBE_FUNCTION_ARG_DEF(std::string, a_str);
  PROBE_FUNCTION_ARG_DEF(int, a_int);
  PROBE_FUNCTION_ARG_DEF(bool, a_bool);
  PROBE_FUNCTION_ARG_DEF(int, default_int, 42);
  PROBE_FUNCTION_ARG_DEF(std::optional<int>, opt_int);
  PROBE_FUNCTION_ARG_DEF(std::vector<int>, a_vec_int);
  PROBE_FUNCTION_ARG_DEF(std::vector<int>,
                         default_vec_int,
                         std::vector<int>{1, 2, 3});
  PROBE_FUNCTION_ARG_DEF(std::unique_ptr<ProbeFunction>, a_probe_fun);
  PROBE_FUNCTION_ARG_DEF(
      std::unique_ptr<ProbeFunction>,
      default_probe_fun,
      CreateProbeFunction<NoArgProbeFunction>(base::Value::Dict{}));

  static bool post_parse_arg_result_;
};

bool ArgProbeFunction::post_parse_arg_result_ = true;

class ProbeFunctionArgumentTest : public ::testing::Test {
 protected:
  void SetUp() override {
    original_function_table_ = std::move(ProbeFunction::registered_functions_);
    ProbeFunction::registered_functions_ =
        ProbeFunctions<NoArgProbeFunction,
                       NoArg2ProbeFunction>::ConstructRegisteredFunctionTable();

    ArgProbeFunction::post_parse_arg_result_ = true;

    arg_.Set("a_str", "");
    arg_.Set("a_int", 0);
    arg_.Set("a_bool", false);
    arg_.Set("a_vec_int", base::Value::List{});
    base::Value::Dict probe_fun;
    probe_fun.Set("no_arg", base::Value::Dict{});
    arg_.Set("a_probe_fun", std::move(probe_fun));
  }

  void TearDown() override {
    ProbeFunction::registered_functions_ = std::move(original_function_table_);
    ArgProbeFunction::post_parse_arg_result_ = true;
  }

  base::Value::Dict arg_;
  ProbeFunction::RegisteredFunctionTableType original_function_table_;
};

TEST_F(ProbeFunctionArgumentTest, Required) {
  arg_.Set("a_str", "str");
  arg_.Set("a_int", 42);
  arg_.Set("a_bool", true);
  {
    base::Value::List tmp;
    tmp.Append(1);
    tmp.Append(2);
    tmp.Append(3);
    arg_.Set("a_vec_int", std::move(tmp));
  }
  {
    base::Value::Dict probe_fun;
    probe_fun.Set("no_arg", base::Value::Dict{});
    arg_.Set("a_probe_fun", std::move(probe_fun));
  }

  auto fun = CreateProbeFunction<ArgProbeFunction>(arg_);
  ASSERT_TRUE(fun);
  EXPECT_EQ(fun->a_str_, "str");
  EXPECT_EQ(fun->a_int_, 42);
  EXPECT_EQ(fun->a_bool_, true);
  EXPECT_EQ(fun->a_vec_int_, (std::vector<int>{1, 2, 3}));
  ASSERT_TRUE(fun->a_probe_fun_);
  EXPECT_EQ(fun->a_probe_fun_->GetFunctionName(), "no_arg");

  // Default value
  EXPECT_EQ(fun->default_int_, 42);
  EXPECT_EQ(fun->opt_int_, std::nullopt);
  EXPECT_EQ(fun->default_vec_int_, (std::vector<int>{1, 2, 3}));
  ASSERT_TRUE(fun->default_probe_fun_);
  EXPECT_EQ(fun->default_probe_fun_->GetFunctionName(), "no_arg");
}

TEST_F(ProbeFunctionArgumentTest, Optional) {
  arg_.Set("default_int", 1);
  arg_.Set("opt_int", 2);
  {
    base::Value::List tmp;
    tmp.Append(4);
    tmp.Append(5);
    tmp.Append(6);
    arg_.Set("default_vec_int", std::move(tmp));
  }
  {
    base::Value::Dict probe_fun;
    probe_fun.Set("no_arg2", base::Value::Dict{});
    arg_.Set("default_probe_fun", std::move(probe_fun));
  }

  auto fun = CreateProbeFunction<ArgProbeFunction>(arg_);
  ASSERT_TRUE(fun);
  EXPECT_EQ(fun->default_int_, 1);
  EXPECT_EQ(fun->opt_int_, 2);
  EXPECT_EQ(fun->default_vec_int_, (std::vector<int>{4, 5, 6}));
  ASSERT_TRUE(fun->default_probe_fun_);
  EXPECT_EQ(fun->default_probe_fun_->GetFunctionName(), "no_arg2");
}

TEST_F(ProbeFunctionArgumentTest, Empty) {
  arg_.clear();
  auto fun = CreateProbeFunction<ArgProbeFunction>(arg_);
  ASSERT_FALSE(fun);
}

TEST_F(ProbeFunctionArgumentTest, WrongType) {
  arg_.Set("a_int", "str");
  auto fun = CreateProbeFunction<ArgProbeFunction>(arg_);
  ASSERT_FALSE(fun);
}

TEST_F(ProbeFunctionArgumentTest, WrongOptionalType) {
  arg_.Set("opt_int", "str");
  auto fun = CreateProbeFunction<ArgProbeFunction>(arg_);
  ASSERT_FALSE(fun);
}

TEST_F(ProbeFunctionArgumentTest, WrongDefaultType) {
  arg_.Set("default_int", "str");
  auto fun = CreateProbeFunction<ArgProbeFunction>(arg_);
  ASSERT_FALSE(fun);
}

TEST_F(ProbeFunctionArgumentTest, WrongVectorType) {
  {
    base::Value::List tmp;
    tmp.Append(4);
    tmp.Append("str");
    tmp.Append(6);
    arg_.Set("default_vec_int", std::move(tmp));
  }
  auto fun = CreateProbeFunction<ArgProbeFunction>(arg_);
  ASSERT_FALSE(fun);
}

TEST_F(ProbeFunctionArgumentTest, Unexpected) {
  arg_.Set("unexpected", "str");
  auto fun = CreateProbeFunction<ArgProbeFunction>(arg_);
  ASSERT_FALSE(fun);
}

TEST_F(ProbeFunctionArgumentTest, PostParseArgumentsFailed) {
  ArgProbeFunction::post_parse_arg_result_ = false;
  auto fun = CreateProbeFunction<ArgProbeFunction>(arg_);
  ASSERT_FALSE(fun);
}

}  // namespace
}  // namespace runtime_probe

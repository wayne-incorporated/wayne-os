// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/shims/environment.h"

#include <iterator>

#include <base/containers/contains.h>
#include <gtest/gtest.h>

namespace shill {

namespace shims {

class EnvironmentTest : public testing::Test {
 public:
  EnvironmentTest() : environment_(Environment::GetInstance()) {}

 protected:
  Environment* environment_;
};

TEST_F(EnvironmentTest, GetVariable) {
  static const char* const kVarValues[] = {
      "VALUE",
      "",
  };
  static const char kVarName[] = "SHILL_SHIMS_GET_VARIABLE_TEST";
  for (size_t i = 0; i < std::size(kVarValues); i++) {
    EXPECT_FALSE(environment_->GetVariable(kVarName, nullptr));
    EXPECT_EQ(0, setenv(kVarName, kVarValues[i], 0)) << kVarValues[i];
    std::string value;
    EXPECT_TRUE(environment_->GetVariable(kVarName, &value)) << kVarValues[i];
    EXPECT_EQ(kVarValues[i], value);
    EXPECT_EQ(0, unsetenv(kVarName));
  }
}

TEST_F(EnvironmentTest, AsMap) {
  static const char* const kVarNames[] = {
      "SHILL_SHIMS_AS_MAP_TEST_1",
      "SHILL_SHIMS_AS_MAP_TEST_EMPTY",
      "SHILL_SHIMS_AS_MAP_TEST_2",
  };
  static const char* const kVarValues[] = {
      "VALUE 1",
      "",
      "VALUE 2",
  };
  ASSERT_EQ(std::size(kVarNames), std::size(kVarValues));
  for (size_t i = 0; i < std::size(kVarNames); i++) {
    EXPECT_EQ(0, setenv(kVarNames[i], kVarValues[i], 0)) << kVarNames[i];
  }
  std::map<std::string, std::string> env = environment_->AsMap();
  for (size_t i = 0; i < std::size(kVarNames); i++) {
    EXPECT_TRUE(base::Contains(env, kVarNames[i])) << kVarNames[i];
    EXPECT_EQ(kVarValues[i], env[kVarNames[i]]) << kVarNames[i];
    EXPECT_EQ(0, unsetenv(kVarNames[i])) << kVarNames[i];
  }
}

}  // namespace shims

}  // namespace shill

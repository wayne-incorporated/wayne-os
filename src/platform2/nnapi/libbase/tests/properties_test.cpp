// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <algorithm>
#include <cstring>
#include <string>

#include <android-base/properties.h>
#include <gtest/gtest.h>

// Tests the Chrome OS implementation of retrieving properties from environment
// variables.
TEST(PropertiesTest, PropertyFromEnvironment) {
  // Add a single property to the environment
  constexpr char kEnvName[] = "TEST_PROP_1";
  constexpr char kValue[] = "value";
  constexpr char kDefault[] = "default";

  // Variable not set, default should be returned
  std::string result = android::base::GetProperty(kEnvName, kDefault);
  ASSERT_EQ(result, kDefault);

  // Environment variable set, value should be returned
  ASSERT_EQ(setenv(kEnvName, kValue, 1), 0);
  result = android::base::GetProperty(kEnvName, kDefault);
  ASSERT_EQ(result, kValue);

  // Lower case should be converted to upper case
  std::string env_name_lower = kEnvName;
  std::transform(env_name_lower.begin(), env_name_lower.end(),
                 env_name_lower.begin(), ::tolower);
  result = android::base::GetProperty(env_name_lower, kDefault);
  ASSERT_EQ(result, kValue);

  // '.' should be replaced with '_'
  std::string env_name_with_periods = kEnvName;
  std::replace(env_name_with_periods.begin(), env_name_with_periods.end(), '_',
               '.');
  result = android::base::GetProperty(env_name_with_periods, kDefault);
  ASSERT_EQ(result, kValue);

  ASSERT_EQ(unsetenv(kEnvName), 0);
  result = android::base::GetProperty(kEnvName, kDefault);
  ASSERT_EQ(result, kDefault);
}

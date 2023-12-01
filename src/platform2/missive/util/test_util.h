// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MISSIVE_UTIL_TEST_UTIL_H_
#define MISSIVE_UTIL_TEST_UTIL_H_

#include <string>

#include <gmock/gmock.h>

MATCHER_P(EqualsProto,
          message,
          "Match a proto Message equal to the matcher's argument.") {
  std::string expected_serialized, actual_serialized;
  message.SerializeToString(&expected_serialized);
  arg.SerializeToString(&actual_serialized);
  return expected_serialized == actual_serialized;
}

#endif  // MISSIVE_UTIL_TEST_UTIL_H_

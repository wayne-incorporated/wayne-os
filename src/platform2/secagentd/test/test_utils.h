// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SECAGENTD_TEST_TEST_UTILS_H_
#define SECAGENTD_TEST_TEST_UTILS_H_

#include <string>

#include "gmock/gmock-matchers.h"

namespace secagentd::testing {
MATCHER_P(EqualsProto,
          message,
          "Match a proto Message equal to the matcher's argument.") {
  std::string expected_serialized, actual_serialized;
  message.SerializeToString(&expected_serialized);
  arg.SerializeToString(&actual_serialized);
  return expected_serialized == actual_serialized;
}
}  // namespace secagentd::testing
#endif  // SECAGENTD_TEST_TEST_UTILS_H_

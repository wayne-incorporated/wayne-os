// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MINIOS_TEST_UTILS_H_
#define MINIOS_TEST_UTILS_H_

#include <gmock/gmock.h>

namespace minios {

MATCHER_P(CheckState, expected_state, "Matches the expected state.") {
  return arg.state() == expected_state;
}

}  // namespace minios
#endif  // MINIOS_TEST_UTILS_H_

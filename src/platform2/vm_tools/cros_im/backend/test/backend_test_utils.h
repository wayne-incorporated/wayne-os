// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CROS_IM_BACKEND_TEST_BACKEND_TEST_UTILS_H_
#define VM_TOOLS_CROS_IM_BACKEND_TEST_BACKEND_TEST_UTILS_H_

#include <iostream>

namespace cros_im {
namespace test {

// Helper function for logging failures in a consistent manner.
class ExpectImpl {
 public:
  explicit ExpectImpl(bool condition) : log_(!condition) {
    if (log_) {
      // tests/run_tests.py looks for this string to determine if the backend
      // had any expectation errors.
      std::cerr << "BACKEND ERROR: ";
    }
  }
  ~ExpectImpl() {
    if (log_) {
      std::cerr << std::endl;
    }
  }

  template <typename T>
  ExpectImpl& operator<<(const T& t) {
    if (log_) {
      std::cerr << t;
    }
    return *this;
  }

 private:
  bool log_;
};

#define EXPECT_TRUE(condition) cros_im::test::ExpectImpl(!!(condition))
#define EXPECT_FALSE(condition) cros_im::test::ExpectImpl(!(condition))
#define FAILED() cros_im::test::ExpectImpl(false)

}  // namespace test
}  // namespace cros_im

#endif  // VM_TOOLS_CROS_IM_BACKEND_TEST_BACKEND_TEST_UTILS_H_

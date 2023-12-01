// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FOUNDATION_ERROR_TESTING_HELPER_H_
#define LIBHWSEC_FOUNDATION_ERROR_TESTING_HELPER_H_

#include <string>
#include <type_traits>
#include <utility>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libhwsec-foundation/status/status_chain.h"

namespace hwsec_foundation {
namespace error {
namespace testing {

using ::hwsec_foundation::status::MakeStatus;
using ::hwsec_foundation::status::OkStatus;

// Some generic matcher functions for StatusChain/StatusChainOr.
// For the example usage, please check testing_helper_test.cc

MATCHER(IsOk, "") {
  if (!arg.ok()) {
    *result_listener << "status: " << arg.status();
    return false;
  }
  return true;
}

MATCHER_P(IsOkAndHolds, m, "") {
  if (!arg.ok()) {
    *result_listener << "status: " << arg.status();
    return false;
  }
  if (!(arg.value() == m)) {
    *result_listener << "value: " << ::testing::PrintToString(arg.value());
    return false;
  }
  return true;
}

MATCHER_P(IsOkAnd, m, "") {
  if (!arg.ok()) {
    *result_listener << "status: " << arg.status();
    return false;
  }
  return ExplainMatchResult(m, arg.value(), result_listener);
}

MATCHER(NotOk, "") {
  if (arg.ok()) {
    *result_listener << "is ok";
    return false;
  }
  return true;
}

MATCHER_P(NotOkWith, expect_string, "") {
  if (arg.ok()) {
    *result_listener << "is ok";
    return false;
  }
  std::string full = arg.status().ToFullString();
  if (full.find(expect_string) == std::string::npos) {
    *result_listener << "status: " << full;
    return false;
  }
  return true;
}

MATCHER_P(NotOkAnd, matcher, "") {
  if (arg.ok()) {
    *result_listener << "is ok";
    return false;
  }
  return ExplainMatchResult(matcher, arg.status(), result_listener);
}

// A helper function to return generic error object in unittest.
//
// Example Usage:
//
// using ::hwsec_foundation::error::testing::ReturnError;
//
// ON_CALL(tpm, EncryptBlob(_, _, aes_skey, _))
//     .WillByDefault(ReturnOk<TPMErrorBase>());  // Always success.
//
// ON_CALL(tpm, EncryptBlob(_, _, _, _))
//     .WillByDefault(
//         ReturnError<TPMError>("fake", TPMRetryAction::kFatal));

template <typename T>
using remove_cvref_t =
    typename std::remove_cv<typename std::remove_reference<T>::type>::type;

ACTION_P(ReturnErrorType, error_ptr) {
  return OkStatus<remove_cvref_t<decltype(*error_ptr)>>();
}

ACTION_P2(ReturnErrorType, error_ptr, p1) {
  return MakeStatus<remove_cvref_t<decltype(*error_ptr)>>(p1);
}

ACTION_P3(ReturnErrorType, error_ptr, p1, p2) {
  return MakeStatus<remove_cvref_t<decltype(*error_ptr)>>(p1, p2);
}

ACTION_P4(ReturnErrorType, error_ptr, p1, p2, p3) {
  return MakeStatus<remove_cvref_t<decltype(*error_ptr)>>(p1, p2, p3);
}

ACTION_P5(ReturnErrorType, error_ptr, p1, p2, p3, p4) {
  return MakeStatus<remove_cvref_t<decltype(*error_ptr)>>(p1, p2, p3, p4);
}

ACTION_P6(ReturnErrorType, error_ptr, p1, p2, p3, p4, p5) {
  return MakeStatus<remove_cvref_t<decltype(*error_ptr)>>(p1, p2, p3, p4, p5);
}

ACTION_P7(ReturnErrorType, error_ptr, p1, p2, p3, p4, p5, p6) {
  return MakeStatus<remove_cvref_t<decltype(*error_ptr)>>(p1, p2, p3, p4, p5,
                                                          p6);
}

ACTION_P8(ReturnErrorType, error_ptr, p1, p2, p3, p4, p5, p6, p7) {
  return MakeStatus<remove_cvref_t<decltype(*error_ptr)>>(p1, p2, p3, p4, p5,
                                                          p6, p7);
}

ACTION_P9(ReturnErrorType, error_ptr, p1, p2, p3, p4, p5, p6, p7, p8) {
  return MakeStatus<remove_cvref_t<decltype(*error_ptr)>>(p1, p2, p3, p4, p5,
                                                          p6, p7, p8);
}

template <typename ErrType, typename... Args>
auto ReturnError(Args&&... args) {
  return ReturnErrorType(static_cast<ErrType*>(nullptr),
                         std::forward<Args>(args)...);
}

template <typename ErrType>
auto ReturnOk() {
  return ReturnErrorType(static_cast<ErrType*>(nullptr));
}

ACTION_P(ReturnValue, p1) {
  return p1;
}

}  // namespace testing
}  // namespace error
}  // namespace hwsec_foundation

// The Assert* API would be useful to ensure the consumable state of
// StatusChain/StatusChainOr. This is a workaround for CHECK/DCHECK/ASSERT
// macros that doesn't work with the consumable attribute.
// For more information: crbug/1336752#c12, b/223361459
#define ASSERT_OK(x) \
  ASSERT_THAT((x).HintOk(), ::hwsec_foundation::error::testing::IsOk())
#define ASSERT_NOT_OK(x) \
  ASSERT_THAT((x).HintNotOk(), ::hwsec_foundation::error::testing::NotOk())

#endif  // LIBHWSEC_FOUNDATION_ERROR_TESTING_HELPER_H_

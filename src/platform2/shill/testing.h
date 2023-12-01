// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_TESTING_H_
#define SHILL_TESTING_H_

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <tuple>

#include "shill/device.h"
#include "shill/error.h"
#include "shill/logging.h"
#include "shill/store/key_value_store.h"

#include <base/logging.h>
#include <base/test/test_future.h>

namespace shill {

MATCHER(IsSuccess, "") {
  return arg.IsSuccess();
}

MATCHER(IsFailure, "") {
  return arg.IsFailure();
}

MATCHER_P2(ErrorIs, error_type, error_message, "") {
  return error_type == arg.type() && error_message == arg.message();
}

MATCHER_P(ErrorTypeIs, error_type, "") {
  return error_type == arg.type();
}

MATCHER(IsNullRefPtr, "") {
  return !arg.get();
}

MATCHER(NotNullRefPtr, "") {
  return arg.get();
}

// Use this matcher instead of passing RefPtrs directly into the arguments
// of EXPECT_CALL() because otherwise we may create un-cleaned-up references at
// system teardown.
MATCHER_P(IsRefPtrTo, ref_address, "") {
  return arg.get() == ref_address;
}

template <int error_argument_index>
class SetErrorTypeInArgumentAction {
 public:
  SetErrorTypeInArgumentAction(Error::Type error_type, bool warn_default)
      : error_type_(error_type), warn_default_(warn_default) {}

  template <typename Result, typename ArgumentTuple>
  Result Perform(const ArgumentTuple& args) const {
    Error* error_arg = ::std::get<error_argument_index>(args);
    if (error_arg)
      error_arg->Populate(error_type_);

    // You should be careful if you see this warning in your log messages: it is
    // likely that you want to instead set a non-default expectation on this
    // mock, to test the success code-paths.
    if (warn_default_)
      LOG(WARNING) << "Default action taken: set error to " << error_type_
                   << "(" << (error_arg ? error_arg->message() : "") << ")";
  }

 private:
  Error::Type error_type_;
  bool warn_default_;
};

base::OnceCallback<void(const Error&)> GetResultCallback(
    base::test::TestFuture<Error>* e);

// Helper function to set the enabled state of devices synchronously.
void SetEnabledSync(Device* device, bool enable, bool persist, Error* error);

template <typename CallbackType>
class CallbackValue {};

template <typename F>
class CallbackValue<base::OnceCallback<F>> {
 public:
  using Type = base::OnceCallback<F>;
};

template <typename F>
class CallbackValue<base::RepeatingCallback<F>> {
 public:
  using Type = const base::RepeatingCallback<F>&;
};

template <typename CallbackType>
void ReturnOperationFailed(typename CallbackValue<CallbackType>::Type callback);

// Many functions in the the DBus proxy classes take a (shill::Error*) output
// argument that is set to shill::Error::kOperationFailed to notify the caller
// synchronously of error conditions.
//
// If an error is not returned synchronously, a callback (passed as another
// argument to the function) must eventually be called with the result/error.
//
// TODO(b/172215298): Remove these shill::Error* arguments and move everything
// to calling the callback. The current situation often causes unit tests to be
// testing code that is dead in production, and production pathways to be un-
// tested. Instead, you should Invoke+WithArgs ReturnOperationFailed above.
template <int error_argument_index>
::testing::PolymorphicAction<SetErrorTypeInArgumentAction<error_argument_index>>
SetOperationFailedInArgumentAndWarn() {
  return ::testing::MakePolymorphicAction(
      SetErrorTypeInArgumentAction<error_argument_index>(
          Error::kOperationFailed, true));
}

// Use this action to set the (shill::Error*) output argument to any
// shill::Error value on mock DBus proxy method calls.
template <int error_argument_index>
::testing::PolymorphicAction<SetErrorTypeInArgumentAction<error_argument_index>>
SetErrorTypeInArgument(Error::Type error_type) {
  return ::testing::MakePolymorphicAction(
      SetErrorTypeInArgumentAction<error_argument_index>(error_type, false));
}

}  // namespace shill

#endif  // SHILL_TESTING_H_

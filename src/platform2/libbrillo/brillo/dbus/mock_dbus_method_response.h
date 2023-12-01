// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_DBUS_MOCK_DBUS_METHOD_RESPONSE_H_
#define LIBBRILLO_BRILLO_DBUS_MOCK_DBUS_METHOD_RESPONSE_H_

#include <memory>
#include <optional>
#include <string>
#include <utility>

#include <base/check.h>
#include <base/logging.h>
#include <brillo/dbus/dbus_method_response.h>
#include <gmock/gmock.h>

namespace brillo {

namespace dbus_utils {

namespace internal {

// CreateSaveArgsOnceFn is simple helper template for generating function that
// will save the content of its parameter into the pointers given to
// CreateSaveArgsOnceFn().

// This is the terminal, boundary condition template when there's only one
// template parameter left.
template <typename T>
base::OnceCallback<void(const T&)> CreateSaveArgsOnceFn(
    std::optional<T>* dest) {
  // This create a Callback by binding in the |dest| pointer so that once the
  // callback is called, it'll save the argument into |dest|.
  return base::BindOnce(
      [](std::optional<T>* dest_ptr, const T& orig) {
        // Ensure that this is called no more than once.
        CHECK(!dest_ptr->has_value());
        *dest_ptr = orig;
      },
      dest);
}

// This is the variadic template that recurse by removing one parameter at a
// time.
template <typename First, typename... Rest>
base::OnceCallback<void(const First&, const Rest&...)> CreateSaveArgsOnceFn(
    std::optional<First>* first_dest, std::optional<Rest>*... rest_dest) {
  // This create a callback by binding in |first_dest|, which is where we are
  // going to save the first parameter when called. After that, this also binds
  // into the callback another callback, named |rest_callback|, that is created
  // by recursively calling CreateSaveArgsOnceFn() with the |rest_dest|
  // pointers. The callback created in this function will only save the first
  // parameter into |first_dest| and call |rest_callback|, which will deal with
  // saving the rest of the parameters into |rest_dest|.
  return base::BindOnce(
      [](base::OnceCallback<void(const Rest&...)> rest_callback,
         std::optional<First>* local_first_dest, const First& first_orig,
         const Rest&... rest_orig) {
        // Ensure that this is called no more than once.
        CHECK(!local_first_dest->has_value());
        *local_first_dest = first_orig;

        // Let |rest_callback| deal with saving |rest_orig| into |rest_dest|.
        std::move(rest_callback).Run(rest_orig...);
      },
      CreateSaveArgsOnceFn<Rest...>(rest_dest...), first_dest);
}

}  // namespace internal

// Mock DBusMethodResponse for capturing the output of async dbus calls.
// There are 2 ways to use this class:
// 1. Hook/Mock ReplyWithError() and Return() to capture the output of Async
//    method calls.
//    For example:
//      std::unique_ptr<MockDBusMethodResponse<bool>> response(
//          new MockDBusMethodResponse<bool>());
//      // If you want to check success case.
//      response->set_return_callback(base::BindOnce(
//          [](bool result) {
//            // Validate result
//          }
//      }));
//      // If you want to check failure case.
//      EXPECT_CALL(*response, ReplyWithError(...)).WillOnce(Return());
//      adaptor_->YourMethod(std::move(response), ...);
//
// 2. Hook the response sender. This is rarely needed and more complex but
//    gives you more control during testing. Especially when your test involves
//    Abort() or SendRawResponse().
//    For example:
//    std::unique_ptr<MockDBusMethodResponse<bool>> response(
//        MockDBusMethodResponse<bool>::CreateWithMethodCall());
//    response->set_response_sender(base::BindOnce(
//        [](std::unique_ptr<dbus::Response> dbus_response) {
//          // Verify |dbus_response|'s content.
//        }));
//      adaptor_->YourMethod(std::move(response), ...);
//
// Note that 2 member methods in this class is not mocked with gmock:
// 1. Return(): It is a variadic template member and thus unsupported by gmock
// for mocking.
// 2. response_sender_: Response sender might be called in destructor, and thus
// cannot be mocked.
template <typename... Types>
class MockDBusMethodResponse
    : public brillo::dbus_utils::DBusMethodResponse<Types...> {
 public:
  // The constructor should be used when you prefer method 1 above, that is
  // hooking/mocking ReplyWithError() and Return(). In this case, pass nullptr
  // for |method_call|.
  explicit MockDBusMethodResponse(::dbus::MethodCall* method_call = nullptr)
      : brillo::dbus_utils::DBusMethodResponse<Types...>(
            method_call,
            base::BindOnce(
                [](MockDBusMethodResponse* mock,
                   std::unique_ptr<dbus::Response> response) {
                  std::move(mock->response_sender_callback_)
                      .Run(std::move(response));
                },
                base::Unretained(this))),
        response_sender_callback_(
            base::BindOnce(
                [](std::unique_ptr<dbus::Response> response) {
                  // By default, sending unsolicited response during testing
                  // will trigger warning.
                  LOG(WARNING)
                      << "Unexpected Response sent in MockDBusMethodResponse.";
                })),
        return_callback_(base::BindOnce([](const Types&...) {
          // By default, unsolicited Return() call during testing will trigger
          // warning.
          LOG(WARNING) << "Unexpected Return in MockDBusMethodResponse";
        })) {}

  MOCK_METHOD1(ReplyWithError, void(const brillo::Error*));
  MOCK_METHOD4(ReplyWithError,
               void(const base::Location&,
                    const std::string&,
                    const std::string&,
                    const std::string&));

  // Override the actual return function so that we can intercept the result of
  // async function call.
  void Return(const Types&... return_values) override {
    std::move(return_callback_).Run(return_values...);
  }

  // Create a MockDBusMethodResponse for use during testing that have a valid
  // |method_call_|, use this if you want to use Method 2 above, that is,
  // hooking the response sender. Note that the caller of this function owns the
  // instance and should ensure its destruction.
  static MockDBusMethodResponse<Types...>* CreateWithMethodCall() {
    // Create a MethodCall so that DBusMethodResponse have something to use when
    // it attempts to send an actual response.
    auto owned_method_call = std::make_unique<dbus::MethodCall>(
        "com.example.Interface", "MockMethod");
    // Set a value to bypass the checks in dbus libraray.
    // Note that is is an arbitrary value.
    owned_method_call->SetSerial(5);

    MockDBusMethodResponse<Types...>* result =
        new MockDBusMethodResponse(owned_method_call.get());
    result->set_owned_method_call(std::move(owned_method_call));

    return result;
  }

  // Set the response sender callback, a callback that is called whenever
  // SendRawResponse() is called.
  void set_response_sender(
      base::OnceCallback<void(std::unique_ptr<dbus::Response>)>
          response_sender) {
    response_sender_callback_ = std::move(response_sender);
  }

  // Set the return callback, a callback that is called whenever Return() is
  // called.
  void set_return_callback(
      base::OnceCallback<void(const Types&...)> return_callback) {
    return_callback_ = std::move(return_callback);
  }

  // Set the return callback to save all arguments passed to the return callback
  // into |destination|.
  void save_return_args(std::optional<Types>*... destination) {
    set_return_callback(
        internal::CreateSaveArgsOnceFn<Types...>(destination...));
  }

 private:
  // Used by CreateWithMethodCall() above to transfer the ownership of
  // |method_call_|.
  void set_owned_method_call(
      std::unique_ptr<dbus::MethodCall> owned_method_call) {
    owned_method_call_ = std::move(owned_method_call);
  }

  // The callback that is called whenever SendRawResponse() is called.
  base::OnceCallback<void(std::unique_ptr<dbus::Response>)>
      response_sender_callback_;

  // The callback to call when Return() is called. Note that it's not mocked
  // because Return() is a variadic template member, and cannot be mocked with
  // gmock.
  base::OnceCallback<void(const Types&...)> return_callback_;

  // Usually |method_call_| is owned by DBus and will have its life cycle
  // managed outside of DBusMethodResponse. However, during testing, we'll need
  // to take care of its life cycle, so this member variable here will hold the
  // |method_call_| and take care of its destruction.
  std::unique_ptr<dbus::MethodCall> owned_method_call_;
};

}  // namespace dbus_utils

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_DBUS_MOCK_DBUS_METHOD_RESPONSE_H_

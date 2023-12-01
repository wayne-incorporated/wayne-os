// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FOUNDATION_UTILITY_TASK_DISPATCHING_FRAMEWORK_H_
#define LIBHWSEC_FOUNDATION_UTILITY_TASK_DISPATCHING_FRAMEWORK_H_

#include <memory>
#include <string>
#include <utility>

#include <base/functional/bind.h>
#include <base/location.h>
#include <base/notreached.h>
#include <base/task/single_thread_task_runner.h>
#include <brillo/dbus/dbus_method_response.h>

namespace hwsec_foundation {
namespace utility {

// This class allows DBusMethodResponse to Return(), ReplyWithError() or
// destruct from any thread. However, it should be noted that the creation of
// this class should be on the original dbus thread, and this class does not
// handle the situation whereby Return() or ReplyWithError() is called from two
// different threads. (It is the task of the caller to ensure that each instance
// returns only once.)
template <typename... Types>
class ThreadSafeDBusMethodResponse
    : public brillo::dbus_utils::DBusMethodResponse<Types...> {
 public:
  using BaseClass = brillo::dbus_utils::DBusMethodResponse<Types...>;
  using DBusMethodResponse = brillo::dbus_utils::DBusMethodResponse<Types...>;

  ThreadSafeDBusMethodResponse(ThreadSafeDBusMethodResponse&& callback) =
      default;
  explicit ThreadSafeDBusMethodResponse(BaseClass&& original_callback)
      : BaseClass::DBusMethodResponse(
            nullptr, base::BindOnce([](std::unique_ptr<dbus::Response>) {
              NOTREACHED();
            })),
        origin_task_runner_(base::SingleThreadTaskRunner::GetCurrentDefault()),
        origin_thread_id_(base::PlatformThread::CurrentId()),
        original_callback_(new BaseClass(std::move(original_callback))) {}

  ~ThreadSafeDBusMethodResponse() override {
    // The base class can only be destroyed on the original thread,
    // because if this method haven't been sent, then it'll try to send an
    // empty response, and that may only happen on the original thread.
    //
    // If we are not on the original thread, we move out the
    // |original_callback_|. The callback will be destruct at original thread,
    // and this class is safe to destruct in current thread.
    if (!IsOnOriginalThread()) {
      origin_task_runner_->PostTask(
          FROM_HERE,
          base::BindOnce([](const std::unique_ptr<BaseClass>& callback) {},
                         std::move(original_callback_)));
    }
  }

  void Return(const Types&... return_values) override {
    if (IsOnOriginalThread()) {
      original_callback_->Return(return_values...);
    } else {
      // We are not on the original thread, so we'll post it back
      origin_task_runner_->PostTask(
          FROM_HERE,
          base::BindOnce(&BaseClass::Return, std::move(original_callback_),
                         return_values...));
    }
  }

  void ReplyWithError(const brillo::Error* error) override {
    if (IsOnOriginalThread()) {
      original_callback_->ReplyWithError(error);
    } else {
      // We are not on the original thread, so we'll post it back.
      origin_task_runner_->PostTask(
          FROM_HERE, base::BindOnce(
                         [](std::unique_ptr<BaseClass> callback,
                            std::unique_ptr<brillo::Error> error) {
                           callback->ReplyWithError(error.get());
                         },
                         std::move(original_callback_), error->Clone()));
    }
  }

  void ReplyWithError(const base::Location& location,
                      const std::string& error_domain,
                      const std::string& error_code,
                      const std::string& error_message) override {
    if (IsOnOriginalThread()) {
      original_callback_->ReplyWithError(location, error_domain, error_code,
                                         error_message);
    } else {
      // We are not on the original thread, so we'll post it back.
      origin_task_runner_->PostTask(
          FROM_HERE,
          base::BindOnce(
              [](std::unique_ptr<BaseClass> original_callback,
                 const base::Location& location,
                 const std::string& error_domain, const std::string& error_code,
                 const std::string& error_message) {
                original_callback->ReplyWithError(location, error_domain,
                                                  error_code, error_message);
              },
              std::move(original_callback_), location, error_domain, error_code,
              error_message));
    }
  }

  static std::unique_ptr<DBusMethodResponse> MakeThreadSafe(
      std::unique_ptr<DBusMethodResponse> response) {
    return std::make_unique<ThreadSafeDBusMethodResponse>(std::move(*response));
  }

 private:
  bool IsOnOriginalThread() const {
    return base::PlatformThread::CurrentId() == origin_thread_id_;
  }

  // We record the task runner and thread id from which this object is created
  // so that when Reply(), ReplyWithError() is called, we can verify if it's on
  // the original thread, if it's not, we can post it.
  scoped_refptr<base::SingleThreadTaskRunner> origin_task_runner_;
  base::PlatformThreadId origin_thread_id_;

  // The instatnce of base class. It is initialized at constructor.
  // Because it should operate on the original thread, we will pass it to the
  // original thread when needed, and it will deconstruct at the original thread
  // when the task is compelete. By the design of original callback, this class
  // is not designed to be called twice, and the caller should handle this.
  std::unique_ptr<BaseClass> original_callback_;
};

}  // namespace utility
}  // namespace hwsec_foundation

#endif  // LIBHWSEC_FOUNDATION_UTILITY_TASK_DISPATCHING_FRAMEWORK_H_

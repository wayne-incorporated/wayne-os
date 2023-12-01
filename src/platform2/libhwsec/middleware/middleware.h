// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_MIDDLEWARE_MIDDLEWARE_H_
#define LIBHWSEC_MIDDLEWARE_MIDDLEWARE_H_

#include <memory>
#include <tuple>
#include <type_traits>
#include <utility>
#include <variant>

#include <absl/base/attributes.h>
#include <base/functional/callback.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <base/memory/scoped_refptr.h>
#include <base/memory/weak_ptr.h>
#include <base/task/bind_post_task.h>
#include <base/task/sequenced_task_runner.h>
#include <base/task/single_thread_task_runner.h>
#include <base/task/task_runner.h>
#include <base/threading/thread.h>

#include "libhwsec/backend/backend.h"
#include "libhwsec/error/tpm_retry_handler.h"
#include "libhwsec/middleware/function_name.h"
#include "libhwsec/middleware/middleware_derivative.h"
#include "libhwsec/middleware/middleware_owner.h"
#include "libhwsec/proxy/proxy.h"
#include "libhwsec/status.h"

#ifndef BUILD_LIBHWSEC
#error "Don't include this file outside libhwsec!"
#endif

// Middleware can be shared by multiple frontends.
// Converts asynchronous and synchronous calls to the backend.
// And doing some generic error handling, for example: communication error and
// auto reload key & session.
//
// Note: The middleware can maintain a standalone thread, or use the same task
// runner as the caller side.
//
// Note2: The move-only function parameters would not be copied, the other kinds
// of function parameters would be copied due to base::BindOnce.

namespace hwsec {

class Middleware {
 public:
  explicit Middleware(MiddlewareDerivative middleware_derivative)
      : middleware_derivative_(middleware_derivative) {}

  MiddlewareDerivative Derive() const { return middleware_derivative_; }

  // Call the backend function synchronously.
  template <auto Func, typename... Args>
  auto CallSync(Args&&... args) const {
    if constexpr (SubClassHelper<decltype(Func)>::type == CallType::kSync) {
      // Calling sync backend function.
      auto task = base::BindOnce(
          &Middleware::DoSyncBackendCall<Func, decltype(ForwareParameter(
                                                   std::declval<Args>()))...>,
          middleware_derivative_.middleware,
          ForwareParameter(std::forward<Args>(args))...);
      return RunBlockingTask(std::move(task));
    } else if constexpr (SubClassHelper<decltype(Func)>::type ==
                         CallType::kAsync) {
      // Calling async backend function.
      using hwsec_foundation::status::MakeStatus;
      using Result = SubClassResult<decltype(Func)>;
      using Callback = SubClassCallback<decltype(Func)>;

      base::WaitableEvent event(
          base::WaitableEvent::ResetPolicy::MANUAL,
          base::WaitableEvent::InitialState::NOT_SIGNALED);

      Result result =
          MakeStatus<TPMError>("Unknown error", TPMRetryAction::kNoRetry);
      Callback callback =
          base::BindOnce([](Result* result_ptr,
                            Result value) { *result_ptr = std::move(value); },
                         &result)
              .Then(base::BindOnce(&base::WaitableEvent::Signal,
                                   base::Unretained(&event)));

      base::OnceClosure task = base::BindOnce(
          &Middleware::DoAsyncBackendCall<Func, decltype(ForwareParameter(
                                                    std::declval<Args>()))...>,
          middleware_derivative_.middleware, std::move(callback),
          ForwareParameter(std::forward<Args>(args))...);

      middleware_derivative_.task_runner->PostTask(FROM_HERE, std::move(task));
      event.Wait();
      return result;
    } else {
      static_assert(always_false_v<decltype(Func)>, "Unsupported function!");
    }
  }

  // Call the backend function asynchronously.
  template <auto Func, typename Callback, typename... Args>
  void CallAsync(Callback callback, Args&&... args) const {
    CHECK(middleware_derivative_.task_runner);

    SubClassCallback<decltype(Func)> reply = std::move(callback);
    reply = base::BindPostTask(GetReplyRunner(), std::move(reply));
    base::OnceClosure task = base::BindOnce(
        &Middleware::CallAsyncInternal<Func, decltype(ForwareParameter(
                                                 std::declval<Args>()))...>,
        middleware_derivative_.middleware, std::move(reply),
        ForwareParameter(std::forward<Args>(args))...);
    middleware_derivative_.task_runner->PostTask(FROM_HERE, std::move(task));
  }

  // Run a blocking task in the middleware.
  template <typename Result>
  Result RunBlockingTask(base::OnceCallback<Result()> task) const {
    if (middleware_derivative_.thread_id == base::PlatformThread::CurrentId()) {
      return std::move(task).Run();
    }

    CHECK(middleware_derivative_.task_runner);

    base::WaitableEvent event(base::WaitableEvent::ResetPolicy::MANUAL,
                              base::WaitableEvent::InitialState::NOT_SIGNALED);

    if constexpr (std::is_same_v<void, Result>) {
      base::OnceClosure closure = std::move(task).Then(base::BindOnce(
          &base::WaitableEvent::Signal, base::Unretained(&event)));
      middleware_derivative_.task_runner->PostTask(FROM_HERE,
                                                   std::move(closure));
      event.Wait();
      return;
    } else if constexpr (std::is_convertible_v<Status, Result>) {
      using hwsec_foundation::status::MakeStatus;
      Result result =
          MakeStatus<TPMError>("Unknown error", TPMRetryAction::kNoRetry);
      base::OnceClosure closure =
          std::move(task)
              .Then(base::BindOnce(
                  [](Result* result_ptr, Result value) {
                    *result_ptr = std::move(value);
                  },
                  &result))
              .Then(base::BindOnce(&base::WaitableEvent::Signal,
                                   base::Unretained(&event)));
      middleware_derivative_.task_runner->PostTask(FROM_HERE,
                                                   std::move(closure));
      event.Wait();
      return result;
    } else {
      static_assert(always_false_v<Result>, "Unsupported blocking task!");
    }
  }

 private:
  // Type of the backend call.
  enum class CallType {
    // Synchronous backend call, and the function signature will be:
    // Result SubClass::Function(Args...);
    kSync,

    // Asynchronous backend call, and the function signature will be:
    // void SubClass::Function(base::OnceCallback<void(Result)>. Args...);
    kAsync,
  };

  template <typename Func, typename = void>
  struct SubClassHelper {
    static_assert(sizeof(Func) == -1, "Unknown member function");
  };

  // SubClass helper for the synchronous backend call.
  template <typename R, typename S, typename... Args>
  struct SubClassHelper<R (S::*)(Args...),
                        std::enable_if_t<std::is_convertible_v<Status, R>>> {
    inline constexpr static CallType type = CallType::kSync;
    using Result = R;
    using SubClass = S;
    using Callback = base::OnceCallback<void(R)>;
  };

  // SubClass helper for the asynchronous backend call.
  template <typename R, typename S, typename... Args>
  struct SubClassHelper<void (S::*)(base::OnceCallback<void(R)>, Args...),
                        std::enable_if_t<std::is_convertible_v<Status, R>>> {
    inline constexpr static CallType type = CallType::kAsync;
    using Result = R;
    using SubClass = S;
    using Callback = base::OnceCallback<void(R)>;
  };

  template <typename Func>
  using SubClassResult = typename SubClassHelper<Func>::Result;
  template <typename Func>
  using SubClassType = typename SubClassHelper<Func>::SubClass;
  template <typename Func>
  using SubClassCallback = typename SubClassHelper<Func>::Callback;

  template <typename>
  inline static constexpr bool always_false_v = false;

  // The custom parameter forwarding rules.
  template <typename T>
  static T ForwareParameter(T&& t) {
    // The rvalue should still be rvalue, because we have the ownership.
    return t;
  }

  template <typename T>
  static const T& ForwareParameter(T& t) {
    // Add const for normal reference, because we don't have the ownership.
    // base::BindOnce will copy const reference parameter when binding.
    return t;
  }

  template <typename T>
  static const T& ForwareParameter(const T& t) {
    // The const reference would still be const reference.
    // base::BindOnce will copy const reference parameter when binding.
    return t;
  }

  // Get the quick result that is not related to the function itself.
  template <auto Func>
  static std::variant<SubClassResult<decltype(Func)>,
                      SubClassType<decltype(Func)>*>
  GetQuickResult(base::WeakPtr<MiddlewareOwner> middleware) {
    using hwsec_foundation::status::MakeStatus;

    if (!middleware) {
      return MakeStatus<TPMError>("No middleware", TPMRetryAction::kNoRetry);
    }

#if USE_FUZZER
    if (middleware->data_provider_) {
      return FuzzedObject<SubClassResult<decltype(Func)>>()(
          *middleware->data_provider_);
    }
#endif

    if (!middleware->backend_) {
      return MakeStatus<TPMError>("No backend", TPMRetryAction::kNoRetry);
    }

    auto* sub = middleware->backend_->Get<SubClassType<decltype(Func)>>();
    if (!sub) {
      return MakeStatus<TPMError>("No sub class in backend",
                                  TPMRetryAction::kNoRetry);
    }

    return sub;
  }

  // Call the synchronous backend call.
  template <auto Func, typename... Args>
  static SubClassResult<decltype(Func)> DoSyncBackendCall(
      base::WeakPtr<MiddlewareOwner> middleware, Args... args) {
    using Result = SubClassResult<decltype(Func)>;
    using Type = SubClassType<decltype(Func)>;

    std::variant<Result, Type*> quick_result = GetQuickResult<Func>(middleware);
    if (Result* result = std::get_if<Result>(&quick_result)) {
      return std::move(*result);
    }

    Type* sub = *std::get_if<Type*>(&quick_result);

    for (TPMRetryHandler retry_handler;;) {
      SubClassResult<decltype(Func)> result = (sub->*Func)(args...);

      if (middleware->metrics_) {
        middleware->metrics_->SendFuncResultToUMA(GetFuncName<Func>(),
                                                  result.status());
      }

      if (retry_handler.HandleResult(result, *middleware->backend_, args...)) {
        return result;
      }
    }
  }

  // Call the asynchronous backend call.
  template <auto Func, typename... Args>
  static void DoAsyncBackendCall(base::WeakPtr<MiddlewareOwner> middleware,
                                 SubClassCallback<decltype(Func)> callback,
                                 Args... args) {
    auto retry_handler = std::make_unique<TPMRetryHandler>();

    // Using the decay type to make sure we are not putting dangling reference
    // in the tuple.
    auto args_tuple =
        std::make_unique<std::tuple<std::decay_t<Args>...>>(std::move(args)...);

    DoAsyncBackendCallInternal<Func>(
        std::move(middleware), std::move(retry_handler), std::move(callback),
        std::move(args_tuple), std::make_index_sequence<sizeof...(Args)>());
  }

  template <auto Func, typename ArgsTuple, std::size_t... I>
  static void DoAsyncBackendCallInternal(
      base::WeakPtr<MiddlewareOwner> middleware,
      std::unique_ptr<TPMRetryHandler> retry_handler,
      SubClassCallback<decltype(Func)> callback,
      std::unique_ptr<ArgsTuple> args,
      std::index_sequence<I...> idx_seq) {
    using Result = SubClassResult<decltype(Func)>;
    using Type = SubClassType<decltype(Func)>;
    using Callback = SubClassCallback<decltype(Func)>;

    std::variant<Result, Type*> quick_result = GetQuickResult<Func>(middleware);
    if (Result* result = std::get_if<Result>(&quick_result)) {
      std::move(callback).Run(std::move(*result));
      return;
    }

    Type* sub = *std::get_if<Type*>(&quick_result);

    // Note: The args tuple will be owned by the retry callback.
    // We will transfer the ownership of the retry callback into the backend
    // function, so the backend functions should be careful about not using the
    // args after call or drop the callback.
    ArgsTuple& args_ref = *args;

    Callback retry_callback =
        base::BindOnce(&HandleAsyncBackendCallRetry<Func, ArgsTuple, I...>,
                       std::move(middleware), std::move(retry_handler),
                       std::move(callback), std::move(args), idx_seq);

    (sub->*Func)(std::move(retry_callback), std::get<I>(args_ref)...);
  }

  template <auto Func, typename ArgsTuple, std::size_t... I>
  static void HandleAsyncBackendCallRetry(
      base::WeakPtr<MiddlewareOwner> middleware,
      std::unique_ptr<TPMRetryHandler> retry_handler,
      SubClassCallback<decltype(Func)> callback,
      std::unique_ptr<ArgsTuple> args,
      std::index_sequence<I...> idx_seq,
      SubClassResult<decltype(Func)> result) {
    using hwsec_foundation::status::MakeStatus;

    if (!middleware) {
      std::move(callback).Run(
          MakeStatus<TPMError>("No middleware", TPMRetryAction::kNoRetry));
      return;
    }

    if (middleware->metrics_) {
      middleware->metrics_->SendFuncResultToUMA(GetFuncName<Func>(),
                                                result.status());
    }

    if (retry_handler->HandleResult(result, *middleware->backend_,
                                    std::get<I>(*args)...)) {
      std::move(callback).Run(std::move(result));
      return;
    }

    DoAsyncBackendCallInternal<Func>(
        std::move(middleware), std::move(retry_handler), std::move(callback),
        std::move(args), idx_seq);
  }

  template <auto Func, typename... Args>
  static void CallAsyncInternal(base::WeakPtr<MiddlewareOwner> middleware,
                                SubClassCallback<decltype(Func)> callback,
                                Args... args) {
    if constexpr (SubClassHelper<decltype(Func)>::type == CallType::kSync) {
      // Calling sync backend function.
      std::move(callback).Run(DoSyncBackendCall<Func, Args...>(
          std::move(middleware), ForwareParameter(std::move(args))...));
    } else if constexpr (SubClassHelper<decltype(Func)>::type ==
                         CallType::kAsync) {
      // Calling async backend function.
      Middleware::DoAsyncBackendCall<Func, Args...>(
          std::move(middleware), std::move(callback),
          ForwareParameter(std::move(args))...);
    } else {
      static_assert(always_false_v<decltype(Func)>, "Unsupported function!");
    }
  }

  static scoped_refptr<base::TaskRunner> GetReplyRunner() {
    CHECK(base::SequencedTaskRunner::HasCurrentDefault());
    return base::SequencedTaskRunner::GetCurrentDefault();
  }

  MiddlewareDerivative middleware_derivative_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_MIDDLEWARE_MIDDLEWARE_H_

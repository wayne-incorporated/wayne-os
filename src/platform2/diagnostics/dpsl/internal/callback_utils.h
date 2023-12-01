// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_DPSL_INTERNAL_CALLBACK_UTILS_H_
#define DIAGNOSTICS_DPSL_INTERNAL_CALLBACK_UTILS_H_

#include <functional>
#include <utility>

#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/location.h>
#include <base/memory/ref_counted.h>
#include <base/task/single_thread_task_runner.h>
#include <base/task/task_runner.h>
#include <grpcpp/grpcpp.h>

namespace diagnostics {

// Transforms base::RepeatingCallback into std::function.
template <typename ReturnType, typename... ArgType>
inline std::function<ReturnType(ArgType...)>
MakeStdFunctionFromRepeatingCallback(
    base::RepeatingCallback<ReturnType(ArgType...)> callback) {
  return [callback](ArgType&&... args) {
    callback.Run(std::forward<ArgType>(args)...);
  };
}

// Transforms base::OnceCallback into std::function (which can be executed only
// at most once).
template <typename ReturnType, typename... ArgType>
inline std::function<ReturnType(ArgType...)> MakeStdFunctionFromOnceCallback(
    base::OnceCallback<ReturnType(ArgType...)> callback) {
  // As `std::function` only supports copyable functors and arguments natively,
  // we first use `base::OwnedRef` to transform the once callback into a
  // repeating callback.
  return MakeStdFunctionFromRepeatingCallback(base::BindRepeating(
      [](base::OnceCallback<ReturnType(ArgType...)>& callback,
         ArgType&&... args) {
        std::move(callback).Run(std::forward<ArgType>(args)...);
      },
      base::OwnedRef(std::move(callback))));
}

// A function that transforms base::OnceCallback into std::function, and
// automatically adds grpc::Status::OK
template <typename ReturnType, typename... ArgType>
inline std::function<ReturnType(ArgType...)> MakeStdFunctionFromCallbackGrpc(
    base::OnceCallback<ReturnType(grpc::Status, ArgType...)> callback) {
  return MakeStdFunctionFromOnceCallback(
      base::BindOnce(std::move(callback), grpc::Status::OK));
}

namespace internal {

template <typename ReturnType, typename... ArgTypes>
inline ReturnType RunStdFunctionWithArgs(
    std::function<ReturnType(ArgTypes...)> function, ArgTypes... args) {
  return function(std::forward<ArgTypes>(args)...);
}

template <typename ReturnType, typename... ArgTypes>
inline ReturnType RunStdFunctionWithArgsGrpc(
    std::function<ReturnType(ArgTypes...)> function,
    grpc::Status status,
    ArgTypes... args) {
  return function(std::forward<ArgTypes>(args)...);
}

}  // namespace internal

// Transforms std::function into base::OnceCallback.
template <typename ReturnType, typename... ArgTypes>
inline base::OnceCallback<ReturnType(ArgTypes...)> MakeCallbackFromStdFunction(
    std::function<ReturnType(ArgTypes...)> function) {
  return base::BindOnce(
      &internal::RunStdFunctionWithArgs<ReturnType, ArgTypes...>,
      std::move(function));
}

// Transforms std::function into base::OnceCallback, and ignores grpc::Status.
template <typename ReturnType, typename... ArgTypes>
inline base::OnceCallback<ReturnType(grpc::Status, ArgTypes...)>
MakeCallbackFromStdFunctionGrpc(
    std::function<ReturnType(ArgTypes...)> function) {
  return base::BindOnce(
      &internal::RunStdFunctionWithArgsGrpc<ReturnType, ArgTypes...>,
      std::move(function));
}

namespace internal {

template <typename... ArgTypes>
inline void RunCallbackOnTaskRunner(
    scoped_refptr<base::TaskRunner> task_runner,
    const base::Location& location,
    base::OnceCallback<void(ArgTypes...)> callback,
    ArgTypes... args) {
  task_runner->PostTask(
      location, base::BindOnce(std::move(callback), std::move(args)...));
}

}  // namespace internal

// Returns a callback that remembers the current task runner and, when called,
// posts |callback| to it (with all arguments forwarded).
template <typename... ArgTypes>
inline base::OnceCallback<void(ArgTypes...)>
MakeOriginTaskRunnerPostingCallback(
    const base::Location& location,
    base::OnceCallback<void(ArgTypes...)> callback) {
  return base::BindOnce(&internal::RunCallbackOnTaskRunner<ArgTypes...>,
                        base::SingleThreadTaskRunner::GetCurrentDefault(),
                        location, std::move(callback));
}

}  // namespace diagnostics

#endif  // DIAGNOSTICS_DPSL_INTERNAL_CALLBACK_UTILS_H_

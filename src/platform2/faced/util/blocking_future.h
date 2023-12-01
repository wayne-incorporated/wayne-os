// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FACED_UTIL_BLOCKING_FUTURE_H_
#define FACED_UTIL_BLOCKING_FUTURE_H_

#include <atomic>
#include <optional>
#include <tuple>
#include <utility>

#include <base/run_loop.h>
#include <base/sequence_checker.h>
#include <base/synchronization/waitable_event.h>
#include <faced/util/template.h>

namespace faced {

// A BlockingFuture provides a method of blocking a thread until a callback
// is called, and returning the value back to the thread.
//
// A typical usage is as follows:
//
//   BlockingFuture<std::string> result;
//   AsyncFunction(/*on_complete=*/result.PromiseCallback());
//   std::cout << "Got the result: " << result.Wait();
//
// Multiple arguments are supported, returning a `std::tuple` instead of
// a single value, as follows:
//
//   BlockingFuture<int, std::string> result;
//
//   base::OnceCallback<void(int, std::string)> callback =
//       result.PromiseCallback();
//   AsyncFunction(/*on_complete=*/std::move(callback));
//
//   std::tuple<int, std::string> = result.Wait();
//
// BlockingFuture<void> is also supported, in which case Wait() does not
// return a value, and `PromiseCallback` returns a closure.
//
// Under the hood, a BlockingFuture uses a `base::RunLoop`. Calling `Wait`
// will run the loop until `PromiseCallback` is called.
//
// While BlockingFuture itself is not thread-safe, the callback produced
// by `PromiseCallback` may be called on any thread.
//
// WARNING: BlockingFuture should only be used in tests, or at the top-level
// of a program (e.g., in main). Using it when already running inside a loop
// may lead to deadlocks.
template <typename... Args>
class BlockingFuture {
 public:
  // The type returned by calls such as `Wait`.
  //
  // A simple value `T` if only a single template type is given, or
  // `std::tuple<Args...>` if multiple template types are given.
  using value_type = typename TupleOrSingleton<Args...>::type;

  // Wait for the callback `PromiseCallback` to be called.
  value_type& Wait();

  // Return a callback that, when called, will save the return value and unblock
  // the thread calling `Wait`.
  //
  // The callback may be freely called on another thread.
  base::OnceCallback<void(Args...)> PromiseCallback();

  // Return the value. Only valid after `Wait` has been called and
  // returned.
  const value_type& value() const;
  value_type& value();

 private:
  base::RunLoop loop_;

  // Ensure construction/calls to Wait/destruction happens on the same sequence.
  base::SequenceChecker sequence_checker_;

  // The final value.
  //
  // We rely on `RunLoop::Quit()` / `RunLoop::Run()` to ensure writes to
  // this variable from another thread are visible to the main thread.
  // Thus, this variable is only safe to read once Run() has
  // successfully quit.
  std::optional<value_type> value_;
};

//
// Implementation details follow.
//

template <typename... Args>
typename BlockingFuture<Args...>::value_type& BlockingFuture<Args...>::Wait() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  loop_.Run();
  CHECK(value_.has_value());
  return value_.value();
}

template <typename... Args>
base::OnceCallback<void(Args...)> BlockingFuture<Args...>::PromiseCallback() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return base::BindOnce(
      [](BlockingFuture* future, Args... result) {
        future->value_.emplace(std::forward<Args>(result)...);
        future->loop_.Quit();
      },
      base::Unretained(this));
}

template <typename... Args>
typename BlockingFuture<Args...>::value_type& BlockingFuture<Args...>::value() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  CHECK(value_.has_value());
  return value_.value();
}

template <typename... Args>
const typename BlockingFuture<Args...>::value_type&
BlockingFuture<Args...>::value() const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  CHECK(value_.has_value());
  return value_.value();
}

// Specialisation of BlockingFuture for no arguments.
//
// We can avoid having to store any state around, and just using
// `base::RunLoop::Run()` and `base::RunLoop::QuitClosure()` directly.
template <>
class BlockingFuture<void> {
 public:
  void Wait() { future_.Wait(); }

  base::OnceClosure PromiseCallback() {
    return base::BindOnce(future_.PromiseCallback(), Empty{});
  }

  // The `value` functions don't make a lot of sense for the `void`
  // type, but we implement them for consistency.
  //
  // We additionally perform the same checks a normal BlockingFuture
  // would perform (i.e., checking that the promise callback has been
  // called prior to `value` being called).
  void value() const { (void)future_.value(); }
  void value() { (void)future_.value(); }

 private:
  struct Empty {};
  BlockingFuture<Empty> future_;
};

}  // namespace faced

#endif  // FACED_UTIL_BLOCKING_FUTURE_H_

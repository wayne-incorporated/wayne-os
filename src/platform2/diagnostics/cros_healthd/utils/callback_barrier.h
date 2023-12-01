// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_UTILS_CALLBACK_BARRIER_H_
#define DIAGNOSTICS_CROS_HEALTHD_UTILS_CALLBACK_BARRIER_H_

#include <utility>

#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/memory/ref_counted.h>
#include <base/memory/scoped_refptr.h>

namespace diagnostics {

// Calls |base::OnceClosure| after all the dependent |base::OnceCallback<T>|
// are called. This is useful when tracking multiple async calls.
//
// It takes a callback / callbacks which is guaranteed to be called after all
// the dependencies are called or dropped, so the error can be handled. E.g. A
// dependency could be dropped if it is passed to a mojo interface and the
// interface is disconnected. See constructor below for details.
//
// The CallbackBarrier and each dependencies holds a shared reference to the
// final callbacks. So the final callbacks are valid until all the dependencies
// are called / destructed. This means the dependencies can use the objects
// holded by the final callbacks without worry about the objects' lifetime.
// Once all the references are gone (includes the one in CallbackBarrier), the
// internal state is checked to determine which final callbacks to be called.
//
// Caveat:
//   1. This is not thread-safe.
//   2. |CallbackBarrier| should be dropped once we add all the dependencies.
//      Otherwise, it will keep the last reference to the final callbacks and
//      they won't be called.
//   3. Sometimes, calling a callback may do nothing (e.g. a method bind to an
//      invalidated |WeakPtr|, a canceled |CancelableCallback|), but it is still
//      considered as "called". This is because we only track if the caller
//      has called the callback or not. The users need to maintain the state
//      (e.g. the callback being canceled) themselves.
//
// Example: Basic usage:
//   // Use local variable to ensure that |barrier| will be destructed
//   CallbackBarrier barrier{/*on_success*/base::BindOnce(...),
//                           /*on_error=*/base::BindOnce(...)};
//   foo->DoSomeThing(barrier.Depend(base::BindOnce(...)));
//   foo->DoOtherThing(barrier.Depend(base::BindOnce(...)));
//
// Example: Access member variable:
//    class MyState {
//      void HandleXXX() {...}
//      void HandleYYY() {...}
//      void HandleResult(CallbackType callback, bool success) {...}
//    };
//
//    void DoStuff(CallbackType callback) {
//      // Use unique_ptr so the address of |state| won't be changed.
//      auto state = std::make_unique<MyState>();
//      auto state_ptr = state.get();
//
//      // The |state| is moved into the result callback so it will be valid
//      // until all the dependencies are called or dropped.
//      CallbackBarrier barrier{
//        base::BindOnce(&MyState::HandleResult,
//          std::move(state) std::move(callback))};
//
//      // Using |base::Unretained()| is safe because it is guaranteed to be
//      // valid.
//      AsyncXXX(
//        barrier.Depend(base::BindOnce(&MyState::HandleXXX,
//          base::Unretained(state_ptr))));
//      AsyncYYY(
//        barrier.Depend(base::BindOnce(&MyState::HandleYYY,
//          base::Unretained(state_ptr))));
//    }
//
class CallbackBarrier {
 public:
  // |on_finish| will be called with a boolean indicates whether all the
  // dependency are called.
  explicit CallbackBarrier(base::OnceCallback<void(bool)> on_finish);
  // Just like above, but call |on_success| if result is true, or |on_error|
  // otherwise.
  CallbackBarrier(base::OnceClosure on_success, base::OnceClosure on_error);
  CallbackBarrier(const CallbackBarrier&) = delete;
  const CallbackBarrier& operator=(const CallbackBarrier&) = delete;
  ~CallbackBarrier();

  // Creates a closure and makes it a dependency.
  base::OnceClosure CreateDependencyClosure();

  // Makes a |base::OnceCallback<T>| a dependency. Returns the wrapped once
  // callback to be used.
  template <typename T>
  base::OnceCallback<T> Depend(base::OnceCallback<T> callback) {
    return std::move(callback).Then(CreateDependencyClosure());
  }

 private:
  // Tracks each dependency. When all the references are gone, it checks the
  // number of uncalled callbacks and calls the result handler with a boolean
  // indicates whether all the dependency are called.
  class Tracker : public base::RefCounted<Tracker> {
   public:
    explicit Tracker(base::OnceCallback<void(bool)> on_finish);
    Tracker(const Tracker&) = delete;
    const Tracker& operator=(const Tracker&) = delete;

    // Increases the number of uncalled callbacks.
    void IncreaseUncalledCallbackNum();

    // Decreases the number of uncalled callbacks.
    void DecreaseUncalledCallbackNum();

   private:
    ~Tracker();

    // The number of the uncalled callbacks.
    uint32_t num_uncalled_callback_ = 0;
    // The result handler.
    base::OnceCallback<void(bool)> on_finish_;

    friend class base::RefCounted<Tracker>;
  };

  scoped_refptr<Tracker> tracker_;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_UTILS_CALLBACK_BARRIER_H_

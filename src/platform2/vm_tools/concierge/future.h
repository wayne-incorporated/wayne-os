// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CONCIERGE_FUTURE_H_
#define VM_TOOLS_CONCIERGE_FUTURE_H_

#include <atomic>
#include <memory>
#include <tuple>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/run_loop.h>
#include <base/synchronization/condition_variable.h>
#include <base/task/sequenced_task_runner.h>
#include <base/task/task_runner.h>

#include "vm_tools/concierge/apply_impl.h"

// A future class and utilities adapted to the Chrome OS code base. It can be
// used to post jobs to the same/different threads, and to add async support
// to methods. Please refer to FutureTest_Tutorial of future_test.cc on how to
// use this class.
//
// * Regarding "NoReject" (|Then| vs |ThenNoReject|,
//                       and |Async| vs |AsyncNoReject|)
//
// Use the NoReject variant if there is no need to reject a promise in your
// function. It allows you to return the output directly without using
// `return vm_tools::Resolve<T>(val);`, which reduces the amount of boilerplate
// code.
//
// The non "NoReject" func gives the freedom to use both |Resolve| and |Reject|.
//
// * Support of std::tuple and std::array
//
// If the value type of the Future is either std::tuple or std::array, the value
// is unpacked automatically for the next |Then| func. See FutureTest_Tuple
// and FutureTest_Array for example.
namespace vm_tools {

template <typename T, typename Error>
class Future;

template <typename T, typename Error>
class Promise;

// A struct to store both the value and the error for |Future::Get|.
// In a common C++ implementation of futures, this is not need as the exception
// is thrown if any when |Get| is called.
template <typename T,
          typename Error = void,
          class Enable1 = void,
          class Enable2 = void>
struct GetResult;

template <typename T, typename Error>
struct GetResult<T,
                 Error,
                 typename std::enable_if_t<!std::is_void<T>::value>,
                 typename std::enable_if_t<!std::is_void<Error>::value>> {
  T val;
  Error err;
  bool rejected = false;
};

template <typename T, typename Error>
struct GetResult<T,
                 Error,
                 typename std::enable_if_t<std::is_void<T>::value>,
                 typename std::enable_if_t<!std::is_void<Error>::value>> {
  Error err;
  bool rejected = false;
};

template <typename T, typename Error>
struct GetResult<T,
                 Error,
                 typename std::enable_if_t<!std::is_void<T>::value>,
                 typename std::enable_if_t<std::is_void<Error>::value>> {
  T val;
  bool rejected = false;
};

template <typename T, typename Error>
struct GetResult<T,
                 Error,
                 typename std::enable_if_t<std::is_void<T>::value>,
                 typename std::enable_if_t<std::is_void<Error>::value>> {
  bool rejected = false;
};

template <typename T, typename Error = void>
static typename std::enable_if_t<!std::is_void<T>::value, GetResult<T, Error>>
Resolve(T val) {
  GetResult<T, Error> ret;
  ret.val = std::move(val);
  ret.rejected = false;
  return ret;
}

template <typename T, typename Error = void>
static typename std::enable_if_t<std::is_void<T>::value, GetResult<T, Error>>
Resolve() {
  GetResult<void, Error> ret;
  ret.rejected = false;
  return ret;
}

template <typename T, typename Error = void>
typename std::enable_if_t<!std::is_void<Error>::value, GetResult<T, Error>>
Reject(Error err) {
  GetResult<T, Error> ret;
  ret.err = std::move(err);
  ret.rejected = true;
  return ret;
}

template <typename T, typename Error = void>
typename std::enable_if_t<std::is_void<Error>::value, GetResult<T, void>>
Reject() {
  GetResult<T, void> ret;
  ret.rejected = true;
  return ret;
}

namespace internal {

template <typename T, typename Error>
struct SharedState {
  SharedState() : cv(&mutex) {}
  mutable base::Lock mutex;
  base::ConditionVariable cv;
  GetResult<T, Error> ret;
  bool done = false;
  scoped_refptr<base::TaskRunner> task_runner;
  base::OnceClosure then_func;
};

template <typename F>
struct get_future_type;

template <template <typename, typename> class F, typename T, typename Error>
struct get_future_type<F<T, Error>> {
  using type = T;
};

template <class T, class Error, class U = T>
struct is_future : std::false_type {};

template <class F, class Error>
struct is_future<F, Error, Future<typename get_future_type<F>::type, Error>>
    : std::true_type {};
};  // namespace internal

// Error: User defined error type used in |Reject| and |OnReject|.
template <typename T, typename Error = void>
class Future {
 public:
  Future() = default;
  explicit Future(std::shared_ptr<internal::SharedState<T, Error>> state)
      : state_(std::move(state)) {}
  Future(Future&&) = default;
  Future(const Future&) = delete;
  Future& operator=(const Future&) = delete;

  Future& operator=(Future&&) = default;

  // |func| will be posted to the task_runner when this future is fulfilled by
  // returning |vm_tools::Resolve<T>(val)| or |vm_tools::Reject<T>(err)|.
  //
  // Returns the future of the posted func. Task_runner of this future class is
  // inherited by the returned future.
  //
  // |OnReject| can be used to handle the rejection if there was a reject. If
  // the rejection is not handled, the subsequent Then funcs will be bypassed
  // and rejection signal will be propagated.
  template <typename T_then, typename... Ts>
  Future<T_then, Error> Then(
      base::OnceCallback<GetResult<T_then, Error>(Ts...)> func);
  template <typename T_then, typename... Ts>
  Future<T_then, Error> ThenNoReject(base::OnceCallback<T_then(Ts...)> func);

  // |func| is triggered if |vm_tools::Reject<T>(err)| is returned by previous
  // |Then| func. The chain can be resumed by returning
  // |vm_tools::Resolve<T>(val)|, or keep skipping by returning
  // |vm_tools::Reject<T>(err)| within |func|.
  //
  // Returns the future of the posted func. task_runner of this future class is
  // inherited by the returned future.
  template <typename... ErrorOrVoid>
  Future<T, Error> OnReject(
      base::OnceCallback<GetResult<T, Error>(ErrorOrVoid...)> func);

  // Wait for the promise to be fulfilled, return the result and reset the
  // shared state. In other words, the future becomes invalid after Get()
  // returns.
  //
  // Use this method if all the tasks in the chain are posted to other threads,
  // not the current thread. If not, use |GetWithRunLoop|.
  GetResult<T, Error> Get();

  // Wait for the result. Returns true if the result is ready before the
  // timeout, and false otherwise.
  //
  // Same as |Get|, this method can only be used if all the tasks in the chain
  // are posted to other threads, not the current thread.
  bool WaitFor(base::TimeDelta duration);

  // This function is the same as |Get|, except that it uses a RunLoop to yield
  // the current thread to the tasks posted in the chain. It is essentially a
  // nested run loop because the current thread should already have one.
  //
  // WARNING: Use this at your own risk. It is easy to run into deadlocks (non
  // recursive mutex) and other problems with a nested run loop.
  GetResult<T, Error> GetWithRunLoop(
      base::RunLoop::Type type = base::RunLoop::Type::kNestableTasksAllowed);

  // Update the |task_runner|. |Then|/|OnReject| functions will be posted to
  // this task_runner
  Future<T, Error> Via(scoped_refptr<base::TaskRunner> task_runner) {
    DCHECK(task_runner);
    base::AutoLock guard(state_->mutex);
    state_->task_runner = task_runner;
    return std::move(*this);
  }

  // Returns true if the promise has been fulfilled. False otherwise.
  bool IsDone() const {
    base::AutoLock guard(state_->mutex);
    return state_->done;
  }

  // Flatten a nested future. Useful when making an async call within an async
  // function.
  template <typename U = T, typename UError = Error>
  typename std::enable_if_t<internal::is_future<U, UError>::value, T>
  Flatten() {
    return std::move(*this).Then(base::BindOnce([](T f) { return f.Get(); }));
  }

 private:
  template <typename U = T, typename UError = Error>
  static typename std::enable_if_t<std::is_void<UError>::value>
  RejectFuncHelper(base::OnceCallback<GetResult<T, void>()> reject_func,
                   Promise<T, void> p,
                   GetResult<T, void> ret) {
    p.SetResult(std::move(reject_func).Run());
  }
  template <typename U = T, typename UError = Error>
  static typename std::enable_if_t<!std::is_void<UError>::value>
  RejectFuncHelper(base::OnceCallback<GetResult<T, UError>(UError)> reject_func,
                   Promise<T, UError> p,
                   GetResult<T, UError> ret) {
    p.SetResult(std::move(reject_func).Run(std::move(ret.err)));
  }

  template <typename T_then, typename UError = Error>
  static typename std::enable_if_t<std::is_void<UError>::value>
  ResolveFuncHelper(base::OnceCallback<GetResult<T_then, Error>()> resolve_func,
                    Promise<T_then, Error> p,
                    GetResult<T, Error> ret) {
    p.SetResult(std::move(resolve_func).Run());
  }

  template <typename T_then, typename... Ts, typename UError = Error>
  static typename std::enable_if_t<std::is_void<UError>::value>
  ResolveFuncHelper(
      base::OnceCallback<GetResult<T_then, Error>(Ts...)> resolve_func,
      Promise<T_then, Error> p,
      GetResult<T, Error> ret) {
    p.SetResult(internal::Apply(std::move(resolve_func), std::move(ret.val)));
  }

  template <typename T_then, typename UError = Error>
  static typename std::enable_if_t<std::is_void<UError>::value> PropagateReject(
      Promise<T_then, void> p, GetResult<T, void> ret) {
    p.SetResult(Reject<T_then>());
  }

  template <typename T_then, typename UError = Error>
  static typename std::enable_if_t<!std::is_void<UError>::value>
  PropagateReject(Promise<T_then, UError> p, GetResult<T, UError> ret) {
    p.SetResult(Reject<T_then, Error>(ret.err));
  }

  template <typename T_then, typename... Ts>
  Future<T_then, Error> ThenHelper(
      scoped_refptr<base::TaskRunner> task_runner,
      base::OnceCallback<void(Promise<T_then, Error>, GetResult<T, Error>)>
          resolve_func,
      base::OnceCallback<void(Promise<T_then, Error>, GetResult<T, Error>)>
          reject_func);

  std::shared_ptr<internal::SharedState<T, Error>> state_;
};

template <typename T, typename Error = void>
class Promise {
 public:
  Promise() { state_ = std::make_shared<internal::SharedState<T, Error>>(); }
  explicit Promise(std::shared_ptr<internal::SharedState<T, Error>> state)
      : state_(std::move(state)) {}
  Promise(Promise&&) = default;
  Promise(const Promise&) = delete;
  Promise& operator=(const Promise&) = delete;

  Promise& operator=(Promise&&) = default;

  // Returns a future that can be used to wait for this promise to be fulfilled.
  Future<T, Error> GetFuture(scoped_refptr<base::TaskRunner> task_runner) {
    base::AutoLock guard(state_->mutex);
    state_->task_runner = task_runner;
    return Future<T, Error>(state_);
  }

  // Fulfill this promise. The shared state will be released upon this.
  template <typename U = T>
  typename std::enable_if_t<std::is_void<U>::value> SetValue();
  template <typename U = T>
  typename std::enable_if_t<!std::is_void<U>::value> SetValue(U val);

  // Reject this promise. The shared state will be released upon this.
  template <typename UError = Error>
  typename std::enable_if_t<std::is_void<UError>::value> Reject();
  template <typename UError = Error>
  typename std::enable_if_t<!std::is_void<UError>::value> Reject(UError err);

  void SetResult(GetResult<T, Error> ret);

 private:
  // Lock state_.mutex before calling this
  void SetValueHelperLocked();

  std::shared_ptr<internal::SharedState<T, Error>> state_;
};

// ------ Promise impl ------

template <typename T, typename Error>
void Promise<T, Error>::SetValueHelperLocked() {
  DCHECK(!state_->done);
  state_->done = true;
  state_->cv.Signal();

  // Handle "then"
  if (!state_->then_func.is_null()) {
    std::move(state_->then_func).Run();
  }
}

template <typename T, typename Error>
template <typename U>
typename std::enable_if_t<std::is_void<U>::value>
Promise<T, Error>::SetValue() {
  base::AutoLock guard(state_->mutex);
  state_->ret = vm_tools::Resolve<void, Error>();
  SetValueHelperLocked();
}

template <typename T, typename Error>
template <typename U>
typename std::enable_if_t<!std::is_void<U>::value> Promise<T, Error>::SetValue(
    U val) {
  base::AutoLock guard(state_->mutex);
  state_->ret = vm_tools::Resolve<T, Error>(std::move(val));
  SetValueHelperLocked();
}

template <typename T, typename Error>
template <typename UError>
typename std::enable_if_t<std::is_void<UError>::value>
Promise<T, Error>::Reject() {
  base::AutoLock guard(state_->mutex);
  state_->ret = vm_tools::Reject<T, void>();
  state_->done = true;
  state_->cv.Signal();

  if (!state_->then_func.is_null()) {
    std::move(state_->then_func).Run();
  }
}

template <typename T, typename Error>
template <typename UError>
typename std::enable_if_t<!std::is_void<UError>::value>
Promise<T, Error>::Reject(UError err) {
  base::AutoLock guard(state_->mutex);
  state_->ret = vm_tools::Reject<T, Error>(std::move(err));
  state_->done = true;
  state_->cv.Signal();

  if (!state_->then_func.is_null()) {
    std::move(state_->then_func).Run();
  }
}

template <typename T, typename Error>
void Promise<T, Error>::SetResult(GetResult<T, Error> ret) {
  base::AutoLock guard(state_->mutex);
  state_->ret = std::move(ret);
  SetValueHelperLocked();
}

// ------ Future impl ------

template <typename T, typename Error>
template <typename T_then, typename... Ts>
Future<T_then, Error> Future<T, Error>::ThenHelper(
    scoped_refptr<base::TaskRunner> task_runner,
    base::OnceCallback<void(Promise<T_then, Error>, GetResult<T, Error>)>
        resolve_func,
    base::OnceCallback<void(Promise<T_then, Error>, GetResult<T, Error>)>
        reject_func) {
  base::AutoLock guard(state_->mutex);
  if (task_runner) {
    state_->task_runner = task_runner;
  }
  Promise<T_then, Error> promise;
  Future<T_then, Error> future = promise.GetFuture(state_->task_runner);
  internal::SharedState<T, Error>* pState = state_.get();
  base::OnceCallback<void(Future<T, Error>, Promise<T_then, Error>)>
      wrapped_func = base::BindOnce(
          [](base::OnceCallback<void(Promise<T_then, Error>,
                                     GetResult<T, Error>)> resolve_func,
             base::OnceCallback<void(Promise<T_then, Error>,
                                     GetResult<T, Error>)> reject_func,
             Future<T, Error> old_future, Promise<T_then, Error> p) {
            GetResult<T, Error> ret = old_future.Get();
            if (ret.rejected) {
              std::move(reject_func).Run(std::move(p), std::move(ret));
            } else {
              std::move(resolve_func).Run(std::move(p), std::move(ret));
            }
          },
          std::move(resolve_func), std::move(reject_func));

  base::OnceClosure post_func = base::BindOnce(
      [](scoped_refptr<base::TaskRunner> task_runner, base::OnceClosure func) {
        CHECK(task_runner);
        task_runner->PostTask(FROM_HERE, std::move(func));
      },
      state_->task_runner,
      base::BindOnce(std::move(wrapped_func), std::move(*this),
                     std::move(promise)));
  if (pState->done) {
    // post immediately
    std::move(post_func).Run();
  } else {
    // Promise::SetValue/Reject will run this func
    pState->then_func = std::move(post_func);
  }
  return future;
}

template <typename T, typename Error>
template <typename T_then, typename... Ts>
Future<T_then, Error> Future<T, Error>::Then(
    base::OnceCallback<GetResult<T_then, Error>(Ts...)> func) {
  return ThenHelper<T_then, Ts...>(
      nullptr,
      base::BindOnce(
          [](base::OnceCallback<GetResult<T_then, Error>(Ts...)> resolve_func,
             Promise<T_then, Error> p, GetResult<T, Error> ret) {
            ResolveFuncHelper(std::move(resolve_func), std::move(p),
                              std::move(ret));
          },
          std::move(func)),
      base::BindOnce(&Future<T, Error>::PropagateReject<T_then>));
}

namespace internal {

template <typename Error, typename T_then, typename... Ts>
typename std::enable_if_t<!std::is_void<T_then>::value,
                          base::OnceCallback<GetResult<T_then, Error>(Ts...)>>
FutureBind(base::OnceCallback<T_then(Ts...)> func) {
  return base::BindOnce(
      [](base::OnceCallback<T_then(Ts...)> func, Ts... args) {
        return Resolve<T_then, Error>(std::move(func).Run(std::move(args)...));
      },
      std::move(func));
}

template <typename Error, typename T_then, typename... Ts>
typename std::enable_if_t<std::is_void<T_then>::value,
                          base::OnceCallback<GetResult<T_then, Error>(Ts...)>>
FutureBind(base::OnceCallback<T_then(Ts...)> func) {
  return base::BindOnce(
      [](base::OnceCallback<void(Ts...)> func, Ts... args) {
        std::move(func).Run(std::move(args)...);
        return Resolve<void, Error>();
      },
      std::move(func));
}
};  // namespace internal

template <typename T, typename Error>
template <typename T_then, typename... Ts>
Future<T_then, Error> Future<T, Error>::ThenNoReject(
    base::OnceCallback<T_then(Ts...)> func) {
  return Then(internal::FutureBind<Error>(std::move(func)));
}

template <typename T, typename Error>
template <typename... ErrorOrVoid>
Future<T, Error> Future<T, Error>::OnReject(
    base::OnceCallback<GetResult<T, Error>(ErrorOrVoid...)> func) {
  return ThenHelper<T, T>(
      nullptr, base::BindOnce([](Promise<T, Error> p, GetResult<T, Error> ret) {
        p.SetResult(std::move(ret));
      }),
      base::BindOnce(
          [](base::OnceCallback<GetResult<T, Error>(ErrorOrVoid...)> func,
             Promise<T, Error> p, GetResult<T, Error> ret) {
            Future<T, Error>::RejectFuncHelper(std::move(func), std::move(p),
                                               std::move(ret));
          },
          std::move(func)));
}

template <typename T, typename Error>
GetResult<T, Error> Future<T, Error>::GetWithRunLoop(base::RunLoop::Type type) {
  state_->mutex.Acquire();
  if (!state_->done) {
    base::RunLoop loop(type);
    DCHECK(state_->then_func.is_null());
    state_->then_func = loop.QuitClosure();
    state_->mutex.Release();
    loop.Run();
    state_->mutex.Acquire();
  }

  DCHECK(state_->done);
  GetResult<T, Error> ret = std::move(state_->ret);
  state_->mutex.Release();
  state_.reset();

  return ret;
}

template <typename T, typename Error>
bool Future<T, Error>::WaitFor(base::TimeDelta duration) {
  base::AutoLock guard(state_->mutex);
  if (!state_->done)
    state_->cv.TimedWait(duration);

  return state_->done;
}

template <typename T, typename Error>
GetResult<T, Error> Future<T, Error>::Get() {
  state_->mutex.Acquire();
  while (!state_->done)
    state_->cv.Wait();
  // There should only be one thread waiting for the cv. No need to signal
  GetResult<T, Error> ret = std::move(state_->ret);
  state_->mutex.Release();
  state_.reset();
  return ret;
}

/* ------ Non class method declarations ------*/

// Post |func| to |task_runner|, and return a future that will be ready upon
// completion of the posted |func|
template <typename T, typename Error = void>
Future<T, Error> Async(scoped_refptr<base::TaskRunner> task_runner,
                       base::OnceCallback<GetResult<T, Error>()> func);
template <typename T, typename Error = void>
Future<T, Error> AsyncNoReject(scoped_refptr<base::TaskRunner> task_runner,
                               base::OnceCallback<T()> func);

// Returns a future that will be ready when all the given futures are ready
// If any of the given futures is rejected, the returned future will be rejected
// as well
template <typename T, typename Error>
Future<std::vector<T>, Error> Collect(
    scoped_refptr<base::TaskRunner> task_runner,
    std::vector<Future<T, Error>> futures);

// Returns a future that has already been resolved with the given |val|.
// This is useful for removing boilerplate code
template <typename T, typename Error = void>
std::enable_if_t<!std::is_void<T>::value, Future<T, Error>> ResolvedFuture(
    T val,
    scoped_refptr<base::TaskRunner> task_runner =
        base::SequencedTaskRunner::GetCurrentDefault());
template <typename T, typename Error = void>
std::enable_if_t<std::is_void<T>::value, Future<T, Error>> ResolvedFuture(
    scoped_refptr<base::TaskRunner> task_runner =
        base::SequencedTaskRunner::GetCurrentDefault());

/* ------ Non class method implementation ------ */

template <typename T, typename Error>
Future<T, Error> Flatten(Future<Future<T, Error>, Error> f) {
  return f.Then(base::BindOnce([](Future<T, Error> f) { return f.Get(); }));
}

template <typename T, typename Error>
Future<T, Error> Async(scoped_refptr<base::TaskRunner> task_runner,
                       base::OnceCallback<GetResult<T, Error>()> func) {
  Promise<T, Error> p;
  Future<T, Error> future = p.GetFuture(task_runner);
  task_runner->PostTask(FROM_HERE,
                        base::BindOnce(
                            [](Promise<T, Error> p,
                               base::OnceCallback<GetResult<T, Error>()> func) {
                              p.SetResult(std::move(func).Run());
                            },
                            std::move(p), std::move(func)));
  return future;
}

template <typename T, typename Error>
Future<T, Error> AsyncNoReject(scoped_refptr<base::TaskRunner> task_runner,
                               base::OnceCallback<T()> func) {
  Promise<T, Error> p;
  Future<T, Error> future = p.GetFuture(task_runner);
  task_runner->PostTask(
      FROM_HERE,
      base::BindOnce(
          [](Promise<T, Error> p,
             base::OnceCallback<GetResult<T, Error>()> func) {
            p.SetResult(std::move(func).Run());
          },
          std::move(p), internal::FutureBind<Error>(std::move(func))));
  return future;
}

template <typename T, typename Error>
Future<std::vector<T>, Error> Collect(
    scoped_refptr<base::TaskRunner> task_runner,
    std::vector<Future<T, Error>> futures) {
  struct Context {
    explicit Context(size_t n) { values.resize(n); }
    void Reject(Error e) {
      if (!rejected.fetch_or(1)) {  // only reject once
        promise.Reject(std::move(e));
      }
    }
    ~Context() {
      if (!rejected.load()) {
        promise.SetValue(std::move(values));
      }
    }
    std::atomic<uint8_t> rejected{0};
    Promise<std::vector<T>> promise;
    std::vector<T> values;
  };

  std::shared_ptr<Context> ctx = std::make_shared<Context>(futures.size());

  for (size_t i = 0; i < futures.size(); ++i) {
    futures[i]
        .Via(task_runner)
        .Then(base::BindOnce(
            [](std::shared_ptr<Context> ctx, size_t i, T val) {
              ctx->values[i] = std::move(val);
              return Resolve<void>();
            },
            ctx, i))
        .OnReject(base::BindOnce(
            [](std::shared_ptr<Context> ctx, Error e) {
              ctx->Reject(std::move(e));
              // Whatever as the future returned by this OnReject is not used
              return Resolve<void>();
            },
            ctx));
  }

  return ctx->promise.GetFuture(task_runner);
}

template <typename T>
Future<std::vector<T>, void> Collect(
    scoped_refptr<base::TaskRunner> task_runner,
    std::vector<Future<T, void>> futures) {
  struct Context {
    explicit Context(size_t n) { values.resize(n); }
    void Reject() {
      if (!rejected.fetch_or(1)) {  // only reject once
        promise.Reject();
      }
    }
    ~Context() {
      if (!rejected.load()) {
        promise.SetValue(std::move(values));
      }
    }
    std::atomic<uint8_t> rejected{0};
    Promise<std::vector<T>> promise;
    std::vector<T> values;
  };

  std::shared_ptr<Context> ctx = std::make_shared<Context>(futures.size());

  for (size_t i = 0; i < futures.size(); ++i) {
    futures[i]
        .Via(task_runner)
        .Then(base::BindOnce(
            [](std::shared_ptr<Context> ctx, size_t i, T val) {
              ctx->values[i] = std::move(val);
              return Resolve<void>();
            },
            ctx, i))
        .OnReject(base::BindOnce(
            [](std::shared_ptr<Context> ctx) {
              ctx->Reject();
              // Whatever as the future returned by this OnReject is not used
              return Resolve<void>();
            },
            ctx));
  }

  return ctx->promise.GetFuture(task_runner);
}

template <typename T, typename Error>
std::enable_if_t<!std::is_void<T>::value, Future<T, Error>> ResolvedFuture(
    T val, scoped_refptr<base::TaskRunner> task_runner) {
  Promise<T, Error> promise;
  Future<T, Error> future = promise.GetFuture(task_runner);
  promise.SetValue(std::move(val));
  return future;
}

template <typename T, typename Error>
std::enable_if_t<std::is_void<T>::value, Future<T, Error>> ResolvedFuture(
    scoped_refptr<base::TaskRunner> task_runner) {
  Promise<void, Error> promise;
  Future<void, Error> future = promise.GetFuture(task_runner);
  promise.SetValue();
  return future;
}

}  // namespace vm_tools

#endif  // VM_TOOLS_CONCIERGE_FUTURE_H_

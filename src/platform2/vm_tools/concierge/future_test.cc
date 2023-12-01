// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <array>
#include <base/task/sequenced_task_runner.h>
#include <base/test/task_environment.h>
#include <base/threading/platform_thread.h>
#include <base/threading/thread.h>
#include <gtest/gtest.h>
#include <string>

#include <base/test/test_timeouts.h>

#include "vm_tools/concierge/future.h"

namespace vm_tools {

class FutureTest : public ::testing::Test {
 private:
  void SetUp() override {
    ASSERT_TRUE(worker_thread_.Start());
    task_runner_ = worker_thread_.task_runner();
  }
  void TearDown() override {
    task_runner_ = nullptr;
    worker_thread_.Stop();
  }

 protected:
  // Both single and multi threaded usage of future is tested
  base::test::TaskEnvironment task_environment_;
  base::Thread worker_thread_{"worker thread"};
  scoped_refptr<base::SequencedTaskRunner> task_runner_;
};

// The comments below assume basic knowledge of the promise/future programming
// model.
TEST_F(FutureTest, Tutorial) {
  {
    // Dispatching a basic function to |task_runner_|, and returns a future to
    // wait on
    auto sum = Async<int>(
        task_runner_,  // Either the current or a different thread would work
        base::BindOnce([](int x, int y) { return Resolve<int>(x + y); }, 4, 3));
    // Blocking wait on the future returned by the |Async| function.
    // A |RunLoop| with |kNestableTasksAllowed| is used in Get() to prevent
    // deadlock while waiting for the task to finish on the same thread.
    EXPECT_EQ(sum.Get().val, 7);
  }

  {
    auto sum =
        AsyncNoReject<int>(
            task_runner_,
            base::BindOnce(
                [](int x, int y) {
                  return x +
                         y;  // Use AsyncNoReject here to avoid boiletplate code
                },
                1, 2))
            // Chain another async function. The return of the previous func |x
            // + y| needs to match the type of |z|.
            //
            // The Then func will be posted to the same task_runner by default.
            // Use |future.Via(another_task_runner)| to change the task_runner
            // in the middle of a chain if needed.
            .ThenNoReject(base::BindOnce([](int z) { return z + 5; }));
    EXPECT_EQ(sum.Get().val, 8);
  }

  {
    Future<int> future =
        Async(task_runner_, base::BindOnce([]() {
                // Reject, bypass any |Then| after here and before the first
                // |OnReject|
                return Reject<int>();
              }))
            .Then(base::BindOnce([](int x) {
              // no-op, as any |Then| func after a reject is bypassed
              return Resolve<int>(1);
            }))
            // Here, the default error type is void. If a user defined error
            // type is used, the reject handling func will take an Error arg.
            // See FutureTest - RejectTypes for an example of that
            .OnReject(base::BindOnce([]() {
              // Can either |Resolve| or |Reject| here.
              return Resolve<int>(2);
            }));
    GetResult<int> ret = future.Get();
    EXPECT_EQ(ret.val, 2);
    EXPECT_FALSE(ret.rejected);  // handled, therefore false
  }
}

TEST_F(FutureTest, VoidType) {
  {
    Async(task_runner_, base::BindOnce([]() { return Resolve<void>(); })).Get();
  }
}

TEST_F(FutureTest, Chaining) {
  {
    auto future =
        Async(task_runner_,
              base::BindOnce([](int x, int y) { return Resolve<int>(x + y); },
                             4, 3))
            .Then(base::BindOnce([](int z) { return Resolve<int>(z * 2); }));
    EXPECT_EQ(future.Get().val, 14);
  }

  {
    auto future =
        Async(task_runner_,
              base::BindOnce([](int x, int y) { return Resolve<int>(x + y); },
                             4, 3))
            .Then(base::BindOnce([](int z) { return Resolve<int>(z * 2); }))
            .Then(base::BindOnce([](int z) { return Resolve<int>(z * 3); }));
    EXPECT_EQ(future.Get().val, 42);
  }
}

TEST_F(FutureTest, Reject) {
  // Reject, Future<void>
  {
    int x = 1;
    Future<void> future =
        Async(task_runner_, base::BindOnce([]() { return Reject<void>(); }))
            .ThenNoReject(base::BindOnce(
                [](int* x) {
                  *x *=
                      2;  // no-op, as Reject above should break the then chain
                },
                base::Unretained(&x)))
            .OnReject(base::BindOnce(
                [](int* x) {
                  *x *= 3;
                  return Resolve<void>();
                },
                base::Unretained(&x)));

    EXPECT_FALSE(future.Get().rejected);
    EXPECT_EQ(x, 3);
  }

  // Reject again, Future<int>
  {
    Future<int> future =
        Async(task_runner_, base::BindOnce([]() { return Reject<int>(); }))
            .Then(base::BindOnce([](int x) {
              // no-op, as Reject above should break the then chain
              return Resolve<int>(1);
            }))
            .OnReject(base::BindOnce([]() { return Reject<int>(); }));
    EXPECT_TRUE(future.Get().rejected);
  }

  // Resolve, Future<int>
  {
    Future<int> future =
        Async(task_runner_, base::BindOnce([]() { return Resolve<int>(1); }))
            .Then(base::BindOnce([](int x) { return Resolve<int>(x * 2); }))
            .OnReject(base::BindOnce([]() {
              return Resolve<int>(
                  3);  // should be no-op as no promise is rejected
            }));
    GetResult<int> ret = future.Get();
    EXPECT_FALSE(ret.rejected);
    EXPECT_EQ(ret.val, 2);
  }
}

TEST_F(FutureTest, RejectTypes) {
  {
    Future<int, std::string> future =
        Async(task_runner_,
              base::BindOnce([]() { return Reject<int, std::string>("a"); }))
            .OnReject(base::BindOnce([](std::string err) {
              if (err == "a") {
                return Resolve<int, std::string>(5);
              } else {
                return Reject<int, std::string>("noooo");
              }
            }));
    GetResult<int, std::string> ret = future.Get();
    EXPECT_FALSE(ret.rejected);
    EXPECT_EQ(ret.val, 5);
  }

  {
    Future<int, std::string> future =
        Async(task_runner_,
              base::BindOnce([]() { return Reject<int, std::string>("b"); }))
            .OnReject(base::BindOnce([](std::string err) {
              if (err == "a") {
                return Resolve<int, std::string>(5);
              } else {
                return Reject<int, std::string>("noooo");
              }
            }));
    GetResult<int, std::string> ret = future.Get();
    EXPECT_TRUE(ret.rejected);
    EXPECT_EQ(ret.err, "noooo");
  }
}

TEST_F(FutureTest, Tuple) {
  {
    auto future =
        Async(task_runner_, base::BindOnce([]() {
                return Resolve<
                    std::tuple<int, int8_t, int16_t, int32_t, int64_t>>(
                    {1, 2, 3, 4, 5});
              }))
            .Then(
                // tuple is automatically unpacked
                base::BindOnce([](int a, int b, int c, int d, int e) {
                  return Resolve<int>(a + b + c + d + e);
                }));
    EXPECT_EQ(future.Get().val, 15);
  }

  {
    auto future =
        Async(task_runner_, base::BindOnce([]() {
                return Resolve<
                    std::tuple<int, int8_t, int16_t, int32_t, int64_t>>(
                    {1, 2, 3, 4, 5});
              }))
            .ThenNoReject(
                // Taking a std::tuple without unpacking should still work
                base::BindOnce(
                    [](std::tuple<int, int8_t, int16_t, int32_t, int64_t> t) {
                      return std::get<0>(t) + std::get<1>(t) + std::get<2>(t) +
                             std::get<3>(t) + std::get<4>(t);
                    }));
    EXPECT_EQ(future.Get().val, 15);
  }
}

TEST_F(FutureTest, Array) {
  {
    auto future =
        Async(task_runner_, base::BindOnce([]() {
                return Resolve<std::array<int, 5>>({1, 2, 3, 4, 5});
                // std::array is automatically unpacked
              }))
            .Then(base::BindOnce([](int a, int b, int c, int d, int e) {
              return Resolve<int>(a * b * c * d * e);
            }));

    EXPECT_EQ(future.Get().val, 120);
  }

  {
    auto future = Async(task_runner_, base::BindOnce([]() {
                          return Resolve<std::array<int, 5>>({1, 2, 3, 4, 5});
                        }))
                      .Then(base::BindOnce([](std::array<int, 5> a) {
                        // Taking a std::array without unpacking should still
                        // work
                        return Resolve<int>(a[0] * a[1] * a[2] * a[3] * a[4]);
                      }));

    EXPECT_EQ(future.Get().val, 120);
  }
}

TEST_F(FutureTest, Collect) {
  // Different threads
  {
    std::vector<Future<int>> futures;

    constexpr int n = 10;
    for (int i = 0; i < n; ++i) {
      futures.push_back(
          Async(task_runner_,
                base::BindOnce([](int x) { return Resolve<int>(x); }, i)));
    }

    Future<std::vector<int>> future = Collect(task_runner_, std::move(futures));
    GetResult<std::vector<int>> ret = future.Get();
    for (int i = 0; i < n; ++i) {
      EXPECT_EQ(ret.val[i], i);
    }
    EXPECT_FALSE(ret.rejected);
  }

  // Same thread
  {
    std::vector<Future<int>> futures;

    constexpr int n = 10;
    for (int i = 0; i < n; ++i) {
      futures.push_back(
          Async(base::SequencedTaskRunner::GetCurrentDefault(),
                base::BindOnce([](int x) { return Resolve<int>(x); }, i)));
    }

    Future<std::vector<int>> future = Collect(
        base::SequencedTaskRunner::GetCurrentDefault(), std::move(futures));
    GetResult<std::vector<int>> ret = future.GetWithRunLoop();
    for (int i = 0; i < n; ++i) {
      EXPECT_EQ(ret.val[i], i);
    }
    EXPECT_FALSE(ret.rejected);
  }

  // Same thread, rejected
  {
    std::vector<Future<int>> futures;

    constexpr int n = 10;
    for (int i = 0; i < n; ++i) {
      futures.push_back(Async(base::SequencedTaskRunner::GetCurrentDefault(),
                              base::BindOnce(
                                  [](int x) {
                                    if (x == 7) {
                                      return Reject<int>();
                                    } else {
                                      return Resolve<int>(x);
                                    }
                                  },
                                  i)));
    }

    Future<std::vector<int>> future = Collect(
        base::SequencedTaskRunner::GetCurrentDefault(), std::move(futures));
    GetResult<std::vector<int>> ret = future.GetWithRunLoop();
    EXPECT_TRUE(ret.rejected);
  }
}

TEST_F(FutureTest, Flatten) {
  // Worker thread
  AsyncNoReject(task_runner_,
                base::BindOnce([]() { return ResolvedFuture(true); }))
      .Flatten()
      .Get();

  // Same thread
  EXPECT_TRUE(
      AsyncNoReject(base::SequencedTaskRunner::GetCurrentDefault(),
                    base::BindOnce([]() { return ResolvedFuture(true); }))
          .Flatten()
          .GetWithRunLoop()
          .val);

  AsyncNoReject(base::SequencedTaskRunner::GetCurrentDefault(),
                base::BindOnce([]() { return ResolvedFuture<void>(); }))
      .Flatten()
      .GetWithRunLoop();

  {
    auto ret = AsyncNoReject(base::SequencedTaskRunner::GetCurrentDefault(),
                             base::BindOnce([]() { return 2; }))
                   .ThenNoReject(base::BindOnce([](int x) {
                     return AsyncNoReject(
                         base::SequencedTaskRunner::GetCurrentDefault(),
                         base::BindOnce([](int x) { return x * 3; }, x));
                   }))
                   .Flatten()
                   .GetWithRunLoop();
    EXPECT_EQ(ret.val, 6);
    EXPECT_FALSE(ret.rejected);
  }

  {
    auto ret =
        AsyncNoReject(base::SequencedTaskRunner::GetCurrentDefault(),
                      base::BindOnce([]() { return 2; }))
            .ThenNoReject(base::BindOnce([](int x) {
              return Async(
                  base::SequencedTaskRunner::GetCurrentDefault(),
                  base::BindOnce([](int x) { return Reject<int>(); }, x));
            }))
            .Flatten()
            .GetWithRunLoop();
    EXPECT_TRUE(ret.rejected);
  }
}

TEST_F(FutureTest, NoDeadlock) {
  // Fulfill promise in another thread
  {
    Promise<bool> promise;
    Future<bool> future = promise.GetFuture(task_runner_);
    task_runner_->PostDelayedTask(
        FROM_HERE,
        base::BindOnce([](Promise<bool> promise) { promise.SetValue(true); },
                       std::move(promise)),
        base::Milliseconds(10));
    EXPECT_TRUE(future.Get().val);
  }

  // Nested run loops
  {
    base::RunLoop loop;
    base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE,
        base::BindOnce(
            [](base::RepeatingClosure closure) {
              Promise<bool> promise;
              Future<bool> future = promise.GetFuture(
                  base::SequencedTaskRunner::GetCurrentDefault());
              base::SequencedTaskRunner::GetCurrentDefault()->PostDelayedTask(
                  FROM_HERE,
                  base::BindOnce(
                      [](Promise<bool> promise) { promise.SetValue(true); },
                      std::move(promise)),
                  base::Milliseconds(10));
              EXPECT_TRUE(future.GetWithRunLoop().val);
              closure.Run();
            },
            loop.QuitClosure()));
    loop.Run();
  }

  {
    Promise<bool> promise;
    Future<bool> future =
        promise.GetFuture(base::SequencedTaskRunner::GetCurrentDefault());
    task_runner_->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(
            [](Promise<bool> promise,
               scoped_refptr<base::SequencedTaskRunner> main_thread_runner) {
              main_thread_runner->PostTask(
                  FROM_HERE,
                  base::BindOnce(
                      [](Promise<bool> promise) { promise.SetValue(true); },
                      std::move(promise)));
            },
            std::move(promise), base::SequencedTaskRunner::GetCurrentDefault()),
        base::Milliseconds(10));
    EXPECT_TRUE(future.GetWithRunLoop().val);
  }

  {
    Promise<bool> promise;
    Future<bool> future =
        promise.GetFuture(base::SequencedTaskRunner::GetCurrentDefault());
    task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(
            [](Promise<bool> promise,
               scoped_refptr<base::SequencedTaskRunner> main_thread_runner) {
              base::PlatformThread::Sleep(base::Milliseconds(10));
              main_thread_runner->PostTask(
                  FROM_HERE,
                  base::BindOnce(
                      [](Promise<bool> promise) { promise.SetValue(true); },
                      std::move(promise)));
            },
            std::move(promise),
            base::SequencedTaskRunner::GetCurrentDefault()));
    EXPECT_TRUE(future.GetWithRunLoop().val);
  }
}

TEST_F(FutureTest, SameThread) {
  {
    auto sum = Async(
        base::SequencedTaskRunner::GetCurrentDefault(),
        base::BindOnce([](int x, int y) { return Resolve<int>(x + y); }, 4, 3));
    EXPECT_EQ(sum.GetWithRunLoop().val, 7);
  }

  {
    auto future = Async(base::SequencedTaskRunner::GetCurrentDefault(),
                        base::BindOnce([]() { return Resolve<void>(); }));
    future.GetWithRunLoop();
  }

  {
    Promise<bool> promise;
    Future<bool> future =
        promise.GetFuture(base::SequencedTaskRunner::GetCurrentDefault());
    promise.SetValue(true);
    EXPECT_EQ(future.GetWithRunLoop().val, true);
  }

  {
    auto func = []() {
      Promise<bool> promise;
      Future<bool> future =
          promise.GetFuture(base::SequencedTaskRunner::GetCurrentDefault());
      promise.SetValue(true);
      return future;
    };
    func().GetWithRunLoop();
  }

  {
    Promise<void> promise;
    Future<void> future =
        promise.GetFuture(base::SequencedTaskRunner::GetCurrentDefault());
    base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE,
        base::BindOnce([](Promise<void> promise) { promise.SetValue(); },
                       std::move(promise)));
    future.GetWithRunLoop();
  }
}

TEST_F(FutureTest, WaitFor) {
  {
    Promise<bool> promise;
    Future<bool> future = promise.GetFuture(task_runner_);
    task_runner_->PostDelayedTask(
        FROM_HERE,
        base::BindOnce([](Promise<bool> promise) { promise.SetValue(true); },
                       std::move(promise)),
        base::Milliseconds(1000));
    EXPECT_FALSE(future.WaitFor(base::Milliseconds(200)));
    EXPECT_FALSE(future.WaitFor(base::Milliseconds(400)));
    EXPECT_TRUE(future.WaitFor(base::Milliseconds(600)));
    EXPECT_TRUE(future.Get().val);
  }
}

}  // namespace vm_tools

// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/logging.h>
#include <base/threading/platform_thread.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libhwsec-foundation/utility/synchronized.h"

namespace hwsec_foundation::utility {

namespace {

class ThreadUnsafeCounter {
 public:
  ThreadUnsafeCounter() = default;

  void Update(int n) {
    int old = value_;
    int multiplier = 1;
    for (int i = 0; i < n; i++) {
      multiplier = multiplier * kMultiplier % kModulo;
      ++updated_times_;
      // Sleep so that race condition will happen with higher probability.
      base::PlatformThread::Sleep(base::Microseconds(1));
    }
    value_ = old * multiplier % kModulo;
  }

  void Reset() {
    value_ = 1;
    updated_times_ = 0;
  }

  int value() { return value_; }

  int updated_times() { return updated_times_; }

 private:
  const int kMultiplier = 37, kModulo = 1003;

  int value_ = 1;
  int updated_times_ = 0;
};

template <class T>
struct IsSynchronized : std::false_type {};
template <class T>
struct IsSynchronized<Synchronized<T>> : std::true_type {};
template <class T>
struct IsSynchronized<MaybeSynchronized<T>> : std::true_type {};

template <typename Counter>
class UpdateCounterThread : public base::PlatformThread::Delegate {
 public:
  UpdateCounterThread(Counter* counter, int times)
      : counter_(counter), times_(times) {}

  UpdateCounterThread(const UpdateCounterThread&) = delete;
  UpdateCounterThread& operator=(const UpdateCounterThread&) = delete;

  ~UpdateCounterThread() override = default;

  void ThreadMain() override {
    if constexpr (IsSynchronized<Counter>::value) {
      counter_->Lock()->Update(times_);
    } else {
      counter_->Update(times_);
    }
  }

 private:
  Counter* counter_ = nullptr;
  int times_;
};

template <typename Counter>
struct ThreadInfo {
  base::PlatformThreadHandle handle;
  std::unique_ptr<UpdateCounterThread<Counter>> thread;
};

}  // namespace

using SynchronizedUtilityTest = testing::Test;

TEST_F(SynchronizedUtilityTest, Trivial) {
  Synchronized<std::string> str("Hello");

  EXPECT_EQ(str.Lock()->length(), 5);

  str.Lock()->push_back('!');
  EXPECT_EQ(str.Lock()->length(), 6);
}

TEST_F(SynchronizedUtilityTest, ThreadSafeAccess) {
  using Counter = Synchronized<ThreadUnsafeCounter>;
  Counter counter;

  for (int i = 0; i < 10; i++) {
    counter.Lock()->Update(1000);
  }
  int single_thread_result = counter.Lock()->value();

  counter.Lock()->Reset();

  std::vector<ThreadInfo<Counter>> thread_infos(10);
  for (int i = 0; i < 10; i++) {
    thread_infos[i].thread =
        std::make_unique<UpdateCounterThread<Counter>>(&counter, 1000);
    base::PlatformThread::Create(0, thread_infos[i].thread.get(),
                                 &thread_infos[i].handle);
  }
  for (auto& thread_info : thread_infos) {
    base::PlatformThread::Join(thread_info.handle);
  }

  EXPECT_EQ(single_thread_result, counter.Lock()->value());
}

TEST_F(SynchronizedUtilityTest, ThreadSafeCriticalSection) {
  using Counter = Synchronized<ThreadUnsafeCounter>;
  Counter counter;

  std::vector<ThreadInfo<Counter>> thread_infos(10);
  for (int i = 0; i < 10; i++) {
    thread_infos[i].thread =
        std::make_unique<UpdateCounterThread<Counter>>(&counter, 1000);
    base::PlatformThread::Create(0, thread_infos[i].thread.get(),
                                 &thread_infos[i].handle);
  }

  bool success;
  {
    auto handle = counter.Lock();
    int updated_times = handle->updated_times();
    handle->Update(100);
    success = (updated_times + 100 == handle->updated_times());
  }

  for (auto& thread_info : thread_infos) {
    base::PlatformThread::Join(thread_info.handle);
  }

  EXPECT_TRUE(success);
}

using MaybeSynchronizedUtilityTest = testing::Test;

TEST_F(MaybeSynchronizedUtilityTest, Trivial) {
  MaybeSynchronized<std::string> str("Hello");
  str.synchronize();

  EXPECT_EQ(str.Lock()->length(), 5);

  str.Lock()->push_back('!');
  EXPECT_EQ(str.Lock()->length(), 6);
}

TEST_F(MaybeSynchronizedUtilityTest, ThreadSafeAccess) {
  using Counter = MaybeSynchronized<ThreadUnsafeCounter>;
  Counter counter;
  counter.synchronize();

  for (int i = 0; i < 10; i++) {
    counter.Lock()->Update(1000);
  }
  int single_thread_result = counter.Lock()->value();

  counter.Lock()->Reset();

  std::vector<ThreadInfo<Counter>> thread_infos(10);
  for (int i = 0; i < 10; i++) {
    thread_infos[i].thread =
        std::make_unique<UpdateCounterThread<Counter>>(&counter, 1000);
    base::PlatformThread::Create(0, thread_infos[i].thread.get(),
                                 &thread_infos[i].handle);
  }
  for (auto& thread_info : thread_infos) {
    base::PlatformThread::Join(thread_info.handle);
  }

  EXPECT_EQ(single_thread_result, counter.Lock()->value());
}

TEST_F(MaybeSynchronizedUtilityTest, ThreadSafeCriticalSection) {
  using Counter = MaybeSynchronized<ThreadUnsafeCounter>;
  Counter counter;
  counter.synchronize();

  std::vector<ThreadInfo<Counter>> thread_infos(10);
  for (int i = 0; i < 10; i++) {
    thread_infos[i].thread =
        std::make_unique<UpdateCounterThread<Counter>>(&counter, 1000);
    base::PlatformThread::Create(0, thread_infos[i].thread.get(),
                                 &thread_infos[i].handle);
  }

  bool success;
  {
    auto handle = counter.Lock();
    int updated_times = handle->updated_times();
    handle->Update(100);
    success = (updated_times + 100 == handle->updated_times());
  }

  for (auto& thread_info : thread_infos) {
    base::PlatformThread::Join(thread_info.handle);
  }

  EXPECT_TRUE(success);
}

TEST_F(MaybeSynchronizedUtilityTest, ThreadSafeAccessLate) {
  using Counter = MaybeSynchronized<ThreadUnsafeCounter>;
  Counter counter;

  for (int i = 0; i < 10; i++) {
    counter.Lock()->Update(1000);
  }
  int single_thread_result = counter.Lock()->value();

  counter.Lock()->Reset();

  counter.synchronize();

  std::vector<ThreadInfo<Counter>> thread_infos(10);
  for (int i = 0; i < 10; i++) {
    thread_infos[i].thread =
        std::make_unique<UpdateCounterThread<Counter>>(&counter, 1000);
    base::PlatformThread::Create(0, thread_infos[i].thread.get(),
                                 &thread_infos[i].handle);
  }
  for (auto& thread_info : thread_infos) {
    base::PlatformThread::Join(thread_info.handle);
  }

  EXPECT_EQ(single_thread_result, counter.Lock()->value());
}

class SynchronizedUtilityRaceConditionTest : public testing::Test {
 public:
  ~SynchronizedUtilityRaceConditionTest() override = default;

  void SetUp() override {
    // These race condition tests are for ensuring the parameters used in the
    // tests for the Synchronized wrapper will cause race conditions and fail
    // the checks, if no synchronization mechanisms were used. We skip these
    // tests because their results are probabilistic.
    GTEST_SKIP();
  }
};

TEST_F(SynchronizedUtilityRaceConditionTest, ThreadUnsafeAccess) {
  using Counter = ThreadUnsafeCounter;
  Counter counter;

  for (int i = 0; i < 10; i++) {
    counter.Update(1000);
  }
  int single_thread_result = counter.value();

  counter.Reset();

  std::vector<ThreadInfo<Counter>> thread_infos(10);
  for (int i = 0; i < 10; i++) {
    thread_infos[i].thread =
        std::make_unique<UpdateCounterThread<Counter>>(&counter, 1000);
    base::PlatformThread::Create(0, thread_infos[i].thread.get(),
                                 &thread_infos[i].handle);
  }
  for (auto& thread_info : thread_infos) {
    base::PlatformThread::Join(thread_info.handle);
  }

  int multi_thread_result = counter.value();

  EXPECT_NE(single_thread_result, multi_thread_result);
}

TEST_F(SynchronizedUtilityRaceConditionTest, ThreadUnsafeCriticalSection) {
  using Counter = ThreadUnsafeCounter;
  Counter counter;

  std::vector<ThreadInfo<Counter>> thread_infos(10);
  for (int i = 0; i < 10; i++) {
    thread_infos[i].thread =
        std::make_unique<UpdateCounterThread<Counter>>(&counter, 1000);
    base::PlatformThread::Create(0, thread_infos[i].thread.get(),
                                 &thread_infos[i].handle);
  }

  int updated_times = counter.updated_times();
  counter.Update(1000);
  bool success = (updated_times + 1000 == counter.updated_times());

  for (auto& thread_info : thread_infos) {
    base::PlatformThread::Join(thread_info.handle);
  }

  EXPECT_FALSE(success);
}

TEST_F(SynchronizedUtilityRaceConditionTest,
       MaybeSynchronizedThreadUnsafeAccess) {
  using Counter = MaybeSynchronized<ThreadUnsafeCounter>;
  Counter counter;

  for (int i = 0; i < 10; i++) {
    counter.Lock()->Update(1000);
  }
  int single_thread_result = counter.Lock()->value();

  counter.Lock()->Reset();

  std::vector<ThreadInfo<Counter>> thread_infos(10);
  for (int i = 0; i < 10; i++) {
    thread_infos[i].thread =
        std::make_unique<UpdateCounterThread<Counter>>(&counter, 1000);
    base::PlatformThread::Create(0, thread_infos[i].thread.get(),
                                 &thread_infos[i].handle);
  }
  for (auto& thread_info : thread_infos) {
    base::PlatformThread::Join(thread_info.handle);
  }

  EXPECT_NE(single_thread_result, counter.Lock()->value());
}

TEST_F(SynchronizedUtilityRaceConditionTest,
       MaybeSynchronizedThreadUnsafeCriticalSection) {
  using Counter = MaybeSynchronized<ThreadUnsafeCounter>;
  Counter counter;

  std::vector<ThreadInfo<Counter>> thread_infos(10);
  for (int i = 0; i < 10; i++) {
    thread_infos[i].thread =
        std::make_unique<UpdateCounterThread<Counter>>(&counter, 1000);
    base::PlatformThread::Create(0, thread_infos[i].thread.get(),
                                 &thread_infos[i].handle);
  }

  bool success;
  {
    auto handle = counter.Lock();
    int updated_times = handle->updated_times();
    handle->Update(100);
    success = (updated_times + 100 == handle->updated_times());
  }

  for (auto& thread_info : thread_infos) {
    base::PlatformThread::Join(thread_info.handle);
  }

  EXPECT_FALSE(success);
}

}  // namespace hwsec_foundation::utility

// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/barrier_closure.h>
#include <base/check.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/run_loop.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "diagnostics/dpsl/internal/dpsl_global_context_impl.h"
#include "diagnostics/dpsl/internal/dpsl_thread_context_impl.h"
#include "diagnostics/dpsl/internal/test_dpsl_background_thread.h"
#include "diagnostics/dpsl/public/dpsl_global_context.h"
#include "diagnostics/dpsl/public/dpsl_thread_context.h"

namespace diagnostics {
namespace {

class DpslThreadContextImplBaseTest : public testing::Test {
 public:
  DpslThreadContextImplBaseTest() = default;
  DpslThreadContextImplBaseTest(const DpslThreadContextImplBaseTest&) = delete;
  DpslThreadContextImplBaseTest& operator=(
      const DpslThreadContextImplBaseTest&) = delete;

  ~DpslThreadContextImplBaseTest() override {
    DpslThreadContextImpl::CleanThreadCounterForTesting();
    DpslGlobalContextImpl::CleanGlobalCounterForTesting();
  }

  void SetUp() override {
    global_context_ = DpslGlobalContext::Create();
    ASSERT_TRUE(global_context_);
  }

 protected:
  std::unique_ptr<DpslGlobalContext> global_context_;
};

using DpslThreadContextImplBaseDeathTest = DpslThreadContextImplBaseTest;

TEST_F(DpslThreadContextImplBaseDeathTest, CreateWithNullptrGlobalContext) {
  ASSERT_DEATH(DpslThreadContext::Create(nullptr), "GlobalContext is nullptr");
}

TEST_F(DpslThreadContextImplBaseDeathTest, CreateAndForget) {
  ASSERT_TRUE(DpslThreadContext::Create(global_context_.get()));

  ASSERT_DEATH(DpslThreadContext::Create(global_context_.get()),
               "Duplicate DpslThreadContext instances");
}

TEST_F(DpslThreadContextImplBaseDeathTest, CreateAndSave) {
  auto thread_context = DpslThreadContext::Create(global_context_.get());
  ASSERT_TRUE(thread_context);

  ASSERT_DEATH(DpslThreadContext::Create(global_context_.get()),
               "Duplicate DpslThreadContext instances");
}

TEST_F(DpslThreadContextImplBaseDeathTest, RunLoopTwice) {
  ASSERT_DEATH(
      [global_context = global_context_.get()]() {
        auto thread_context = DpslThreadContext::Create(global_context);
        thread_context->PostTask(
            std::function<void()>([thread_context = thread_context.get()]() {
              thread_context->RunEventLoop();
            }));
        thread_context->RunEventLoop();
      }(),
      "Called from already running message loop");
}

class DpslThreadContextImplMainThreadTest
    : public DpslThreadContextImplBaseTest {
 public:
  DpslThreadContextImplMainThreadTest() = default;
  DpslThreadContextImplMainThreadTest(
      const DpslThreadContextImplMainThreadTest&) = delete;
  DpslThreadContextImplMainThreadTest& operator=(
      const DpslThreadContextImplMainThreadTest&) = delete;

  void SetUp() override {
    DpslThreadContextImplBaseTest::SetUp();

    main_thread_context_ = DpslThreadContext::Create(global_context_.get());
    ASSERT_TRUE(main_thread_context_);
  }

  void QuitEventLoop() {
    EXPECT_TRUE(main_thread_context_->IsEventLoopRunning());
    main_thread_context_->QuitEventLoop();
  }

  void AddToQueueTask(int task_id) { task_id_queue_.push_back(task_id); }

  void GenerateFailure() {
    ADD_FAILURE() << "This function shouldn't be called";
  }

 protected:
  std::unique_ptr<DpslThreadContext> main_thread_context_;

  std::vector<int> task_id_queue_;
};

TEST_F(DpslThreadContextImplMainThreadTest, BelongsToCurrentThread) {
  EXPECT_TRUE(main_thread_context_->BelongsToCurrentThread());
}

TEST_F(DpslThreadContextImplMainThreadTest, PostTask) {
  main_thread_context_->PostTask(
      std::bind(&DpslThreadContextImplMainThreadTest::QuitEventLoop, this));

  EXPECT_FALSE(main_thread_context_->IsEventLoopRunning());
  main_thread_context_->RunEventLoop();
  EXPECT_FALSE(main_thread_context_->IsEventLoopRunning());
}

TEST_F(DpslThreadContextImplMainThreadTest, PostDelayedTask) {
  main_thread_context_->PostDelayedTask(
      std::bind(&DpslThreadContextImplMainThreadTest::QuitEventLoop, this),
      100);

  EXPECT_FALSE(main_thread_context_->IsEventLoopRunning());
  main_thread_context_->RunEventLoop();
  EXPECT_FALSE(main_thread_context_->IsEventLoopRunning());
}

TEST_F(DpslThreadContextImplMainThreadTest, PostDelayedTaskDifferentDelays) {
  main_thread_context_->PostDelayedTask(
      std::bind(&DpslThreadContextImplMainThreadTest::AddToQueueTask, this, 3),
      200);
  main_thread_context_->PostDelayedTask(
      std::bind(&DpslThreadContextImplMainThreadTest::AddToQueueTask, this, 2),
      100);
  main_thread_context_->PostDelayedTask(
      std::bind(&DpslThreadContextImplMainThreadTest::AddToQueueTask, this, 1),
      0);

  main_thread_context_->PostDelayedTask(
      std::bind(&DpslThreadContextImplMainThreadTest::QuitEventLoop, this),
      200);

  // Should not be processsed after quit from event loop.
  main_thread_context_->PostDelayedTask(
      std::bind(&DpslThreadContextImplMainThreadTest::GenerateFailure, this),
      200);

  EXPECT_FALSE(main_thread_context_->IsEventLoopRunning());
  main_thread_context_->RunEventLoop();
  EXPECT_FALSE(main_thread_context_->IsEventLoopRunning());

  EXPECT_THAT(task_id_queue_, testing::ElementsAreArray({1, 2, 3}));
}

TEST_F(DpslThreadContextImplMainThreadTest, PostDelayedTaskSameDelays) {
  main_thread_context_->PostDelayedTask(
      std::bind(&DpslThreadContextImplMainThreadTest::AddToQueueTask, this, 1),
      100);
  main_thread_context_->PostDelayedTask(
      std::bind(&DpslThreadContextImplMainThreadTest::AddToQueueTask, this, 2),
      100);
  main_thread_context_->PostDelayedTask(
      std::bind(&DpslThreadContextImplMainThreadTest::AddToQueueTask, this, 3),
      100);

  main_thread_context_->PostDelayedTask(
      std::bind(&DpslThreadContextImplMainThreadTest::QuitEventLoop, this),
      100);

  // Should not be processsed after quit from event loop.
  main_thread_context_->PostDelayedTask(
      std::bind(&DpslThreadContextImplMainThreadTest::GenerateFailure, this),
      200);

  EXPECT_FALSE(main_thread_context_->IsEventLoopRunning());
  main_thread_context_->RunEventLoop();
  EXPECT_FALSE(main_thread_context_->IsEventLoopRunning());

  EXPECT_THAT(task_id_queue_, testing::ElementsAreArray({1, 2, 3}));
}

using DpslThreadContextImplDeathTest = DpslThreadContextImplMainThreadTest;

TEST_F(DpslThreadContextImplDeathTest, PostDelayedTaskInvalidDelay) {
  ASSERT_DEATH(
      main_thread_context_->PostDelayedTask(
          std::bind(&DpslThreadContextImplMainThreadTest::QuitEventLoop, this),
          -5),
      "Delay must be non-negative");
}

class DpslThreadContextImplMultiThreadTest
    : public DpslThreadContextImplMainThreadTest {
 public:
  DpslThreadContextImplMultiThreadTest() {
    // The default style "fast" does not support multi-threaded tests.
    ::testing::FLAGS_gtest_death_test_style = "threadsafe";
  }
  DpslThreadContextImplMultiThreadTest(
      const DpslThreadContextImplMultiThreadTest&) = delete;
  DpslThreadContextImplMultiThreadTest& operator=(
      const DpslThreadContextImplMultiThreadTest&) = delete;

  ~DpslThreadContextImplMultiThreadTest() override = default;

  void SetUp() override {
    DpslThreadContextImplMainThreadTest::SetUp();

    background_thread_ = std::make_unique<TestDpslBackgroundThread>(
        "background" /* name */, global_context_.get(),
        main_thread_context_.get());
  }

  DpslThreadContext* background_thread_context() const {
    DCHECK(background_thread_);
    DpslThreadContext* thread_context = background_thread_->thread_context();
    DCHECK(thread_context);
    return thread_context;
  }

  std::function<void()> CreateAddToQueueTaskForBackground(
      int task_id, base::OnceClosure main_thread_callback) {
    base::OnceClosure main_thread_add_to_queue_task = base::BindOnce(
        [](base::OnceClosure task, base::OnceClosure main_thread_callback) {
          std::move(task).Run();
          std::move(main_thread_callback).Run();
        },
        base::BindOnce(&DpslThreadContextImplMultiThreadTest::AddToQueueTask,
                       base::Unretained(this), task_id),
        std::move(main_thread_callback));

    return background_thread_->WrapTaskToReplyOnMainThread(
        base::OnceClosure(), main_thread_context_.get(),
        std::move(main_thread_add_to_queue_task));
  }

 protected:
  std::unique_ptr<TestDpslBackgroundThread> background_thread_;
};

TEST_F(DpslThreadContextImplMultiThreadTest, PostTask) {
  base::RepeatingClosure quit_closure =
      base::BarrierClosure(3, base::BindOnce(
                                  [](DpslThreadContext* main_thread_context) {
                                    main_thread_context->QuitEventLoop();
                                  },
                                  main_thread_context_.get()));

  background_thread_context()->PostTask(
      CreateAddToQueueTaskForBackground(1, quit_closure));
  background_thread_context()->PostTask(
      CreateAddToQueueTaskForBackground(2, quit_closure));
  background_thread_context()->PostTask(
      CreateAddToQueueTaskForBackground(3, quit_closure));

  background_thread_->StartEventLoop();
  main_thread_context_->RunEventLoop();

  EXPECT_THAT(task_id_queue_, testing::ElementsAreArray({1, 2, 3}));
}

TEST_F(DpslThreadContextImplMultiThreadTest, PostDelayedTask) {
  base::RepeatingClosure quit_closure =
      base::BarrierClosure(3, base::BindOnce(
                                  [](DpslThreadContext* main_thread_context) {
                                    main_thread_context->QuitEventLoop();
                                  },
                                  main_thread_context_.get()));

  background_thread_context()->PostDelayedTask(
      CreateAddToQueueTaskForBackground(3, quit_closure), 200);
  background_thread_context()->PostDelayedTask(
      CreateAddToQueueTaskForBackground(2, quit_closure), 100);
  background_thread_context()->PostDelayedTask(
      CreateAddToQueueTaskForBackground(1, quit_closure), 0);

  background_thread_->StartEventLoop();
  main_thread_context_->RunEventLoop();

  EXPECT_THAT(task_id_queue_, testing::ElementsAreArray({1, 2, 3}));
}

TEST_F(DpslThreadContextImplMultiThreadTest, BelongsToCurrentThread) {
  EXPECT_FALSE(background_thread_context()->BelongsToCurrentThread());
}

using DpslThreadContextImplMultiThreadDeathTest =
    DpslThreadContextImplMultiThreadTest;

TEST_F(DpslThreadContextImplMultiThreadDeathTest, RunEventLoopCrash) {
  ASSERT_DEATH(background_thread_context()->RunEventLoop(),
               "Called from wrong thread");
}

TEST_F(DpslThreadContextImplMultiThreadDeathTest, IsEventLoopRunningCrash) {
  ASSERT_DEATH(background_thread_context()->IsEventLoopRunning(),
               "Called from wrong thread");
}

TEST_F(DpslThreadContextImplMultiThreadDeathTest, QuitEventLoopCrash) {
  ASSERT_DEATH(background_thread_context()->QuitEventLoop(),
               "Called from wrong thread");
}

TEST_F(DpslThreadContextImplMultiThreadDeathTest, DestructorCrash) {
  ASSERT_DEATH(delete background_thread_context(), "Called from wrong thread");
}

}  // namespace
}  // namespace diagnostics

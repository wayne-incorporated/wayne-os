// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "missive/resources/resource_manager.h"

#include <cstdint>
#include <utility>

#include <base/memory/scoped_refptr.h>
#include <base/task/sequenced_task_runner.h>
#include <base/task/thread_pool.h>
#include <base/test/task_environment.h>
#include <base/time/time.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "base/functional/bind.h"
#include "base/sequence_checker.h"
#include "missive/util/test_support_callbacks.h"

using ::testing::Eq;

namespace reporting {
namespace {

class ResourceManagerTest : public ::testing::TestWithParam<uint64_t> {
 protected:
  void SetUp() override {
    resource_ = base::MakeRefCounted<ResourceManager>(GetParam());
    // Make sure parameters define reasonably large total resource size.
    ASSERT_GE(resource_->GetTotal(), 1u * 1024LLu * 1024LLu);
  }

  void TearDown() override { EXPECT_THAT(resource_->GetUsed(), Eq(0u)); }

  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};

  scoped_refptr<ResourceManager> resource_;
};

TEST_P(ResourceManagerTest, NestedReservationTest) {
  uint64_t size = resource_->GetTotal();
  while ((size / 2) > 0u) {
    size /= 2;
    EXPECT_TRUE(resource_->Reserve(size));
  }

  for (; size < resource_->GetTotal(); size *= 2) {
    resource_->Discard(size);
  }
}

TEST_P(ResourceManagerTest, SimultaneousReservationTest) {
  uint64_t size = resource_->GetTotal();

  // Schedule reservations.
  test::TestCallbackWaiter reserve_waiter;
  while ((size / 2) > 0u) {
    size /= 2;
    reserve_waiter.Attach();
    base::ThreadPool::PostTask(
        FROM_HERE, {base::TaskPriority::BEST_EFFORT},
        base::BindOnce(
            [](size_t size, scoped_refptr<ResourceManager> resource_manager,
               test::TestCallbackWaiter* waiter) {
              EXPECT_TRUE(resource_manager->Reserve(size));
              waiter->Signal();
            },
            size, resource_, &reserve_waiter));
  }
  reserve_waiter.Wait();

  // Schedule discards.
  test::TestCallbackWaiter discard_waiter;
  for (; size < resource_->GetTotal(); size *= 2) {
    discard_waiter.Attach();
    base::ThreadPool::PostTask(
        FROM_HERE, {base::TaskPriority::BEST_EFFORT},
        base::BindOnce(
            [](size_t size, scoped_refptr<ResourceManager> resource_manager,
               test::TestCallbackWaiter* waiter) {
              resource_manager->Discard(size);
              waiter->Signal();
            },
            size, resource_, &discard_waiter));
  }
  discard_waiter.Wait();
}

TEST_P(ResourceManagerTest, SimultaneousScopedReservationTest) {
  uint64_t size = resource_->GetTotal();
  test::TestCallbackWaiter waiter;
  while ((size / 2) > 0u) {
    size /= 2;
    waiter.Attach();
    base::ThreadPool::PostTask(
        FROM_HERE, {base::TaskPriority::BEST_EFFORT},
        base::BindOnce(
            [](size_t size, scoped_refptr<ResourceManager> resource_manager,
               test::TestCallbackWaiter* waiter) {
              { ScopedReservation(size, resource_manager); }
              waiter->Signal();
            },
            size, resource_, &waiter));
  }
  waiter.Wait();
}

TEST_P(ResourceManagerTest, MoveScopedReservationTest) {
  uint64_t size = resource_->GetTotal();
  ScopedReservation scoped_reservation(size / 2, resource_);
  EXPECT_TRUE(scoped_reservation.reserved());
  {
    ScopedReservation moved_scoped_reservation(std::move(scoped_reservation));
    EXPECT_TRUE(moved_scoped_reservation.reserved());
    EXPECT_FALSE(scoped_reservation.reserved());
  }
  EXPECT_FALSE(scoped_reservation.reserved());
}

TEST_P(ResourceManagerTest, ScopedReservationBasicReduction) {
  uint64_t size = resource_->GetTotal() / 2;
  ScopedReservation scoped_reservation(size, resource_);
  EXPECT_TRUE(scoped_reservation.reserved());
  EXPECT_TRUE(scoped_reservation.Reduce(size / 2));
}

TEST_P(ResourceManagerTest, ScopedReservationReductionWithLargerNewSize) {
  uint64_t size = resource_->GetTotal() / 2;
  ScopedReservation scoped_reservation(size, resource_);
  EXPECT_TRUE(scoped_reservation.reserved());
  EXPECT_FALSE(scoped_reservation.Reduce(size + 1));
}

TEST_P(ResourceManagerTest, ScopedReservationReductionWithNegativeNewSize) {
  uint64_t size = resource_->GetTotal() / 2;
  ScopedReservation scoped_reservation(size, resource_);
  EXPECT_TRUE(scoped_reservation.reserved());
  EXPECT_FALSE(scoped_reservation.Reduce(-(size / 2)));
}

TEST_P(ResourceManagerTest, ScopedReservationRepeatingReductions) {
  uint64_t size = resource_->GetTotal() / 2;
  ScopedReservation scoped_reservation(size, resource_);
  EXPECT_TRUE(scoped_reservation.reserved());

  for (; size >= 2; size /= 2) {
    EXPECT_TRUE(scoped_reservation.Reduce(size / 2));
  }
  EXPECT_TRUE(scoped_reservation.Reduce(size / 2));
  EXPECT_FALSE(scoped_reservation.reserved());
}

TEST_P(ResourceManagerTest, ScopedReservationBasicHandOver) {
  uint64_t size = resource_->GetTotal() / 2;
  ScopedReservation scoped_reservation(size, resource_);
  ASSERT_TRUE(scoped_reservation.reserved());
  {
    ScopedReservation another_reservation(size - 1, resource_);
    ASSERT_TRUE(another_reservation.reserved());
    EXPECT_THAT(resource_->GetUsed(), Eq(resource_->GetTotal() - 1));
    EXPECT_TRUE(scoped_reservation.reserved());
    EXPECT_TRUE(another_reservation.reserved());
    scoped_reservation.HandOver(another_reservation);
    EXPECT_THAT(resource_->GetUsed(), Eq(resource_->GetTotal() - 1));
  }
  // Destruction of |anoter_reservation| does not change the amount used.
  EXPECT_THAT(resource_->GetUsed(), Eq(resource_->GetTotal() - 1));
}

TEST_P(ResourceManagerTest, ScopedReservationRepeatingHandOvers) {
  uint64_t size = resource_->GetTotal() / 2;
  ScopedReservation scoped_reservation(size, resource_);
  EXPECT_TRUE(scoped_reservation.reserved());

  for (; size >= 2; size /= 2) {
    ScopedReservation another_reservation(size / 2, resource_);
    scoped_reservation.HandOver(another_reservation);
  }
  EXPECT_THAT(resource_->GetUsed(), Eq(resource_->GetTotal() - 1));
}

TEST_P(ResourceManagerTest, ScopedReservationRepeatingCopyHandOvers) {
  uint64_t size = resource_->GetTotal() / 2;
  ScopedReservation scoped_reservation(size, resource_);
  EXPECT_TRUE(scoped_reservation.reserved());

  for (; size >= 2; size /= 2) {
    ScopedReservation another_reservation(size / 2, scoped_reservation);
    EXPECT_TRUE(another_reservation.reserved());
    scoped_reservation.HandOver(another_reservation);
  }
  EXPECT_THAT(resource_->GetUsed(), Eq(resource_->GetTotal() - 1));
}

TEST_P(ResourceManagerTest, ScopedReservationFailureToCopyFromEmpty) {
  ScopedReservation scoped_reservation;
  uint64_t size = resource_->GetTotal() / 2;
  ScopedReservation another_reservation(size, scoped_reservation);
  EXPECT_FALSE(scoped_reservation.reserved());
}

TEST_P(ResourceManagerTest, ScopedReservationRepeatingHandOversToEmpty) {
  ScopedReservation scoped_reservation;
  EXPECT_FALSE(scoped_reservation.reserved());

  uint64_t size = resource_->GetTotal();
  for (; size >= 2; size /= 2) {
    ScopedReservation another_reservation(size / 2, resource_);
    scoped_reservation.HandOver(another_reservation);
  }
  EXPECT_THAT(resource_->GetUsed(), Eq(resource_->GetTotal() - 1));
}

TEST_P(ResourceManagerTest, ScopedReservationEmptyHandOver) {
  uint64_t size = resource_->GetTotal() / 2;
  ScopedReservation scoped_reservation(size, resource_);

  ASSERT_TRUE(scoped_reservation.reserved());
  {
    ScopedReservation another_reservation(size - 1, resource_);
    ASSERT_TRUE(another_reservation.reserved());

    EXPECT_THAT(resource_->GetUsed(), Eq(resource_->GetTotal() - 1));
    EXPECT_TRUE(scoped_reservation.reserved());
    EXPECT_TRUE(another_reservation.reserved());

    another_reservation.Reduce(0);
    ASSERT_FALSE(another_reservation.reserved());

    scoped_reservation.HandOver(another_reservation);
    EXPECT_THAT(resource_->GetUsed(), Eq(size));
  }
  // Destruction of |anoter_reservation| does not change the amount used.
  EXPECT_THAT(resource_->GetUsed(), Eq(size));
}

TEST_P(ResourceManagerTest, ReservationOverMaxTest) {
  EXPECT_FALSE(resource_->Reserve(resource_->GetTotal() + 1));
  EXPECT_TRUE(resource_->Reserve(resource_->GetTotal()));
  resource_->Discard(resource_->GetTotal());
}

// Helper class with the following behavior:
// - Once created, immediately posts `Start` action on a dedicated task runner
// - `Start` registers a callback for `size` resource
// - When Callback happens (on the same task runner), the work is done;
//   `done` is called and then teh `Actor` commits suiside.
class Actor {
 public:
  Actor(uint64_t size,
        base::OnceClosure done,
        scoped_refptr<ResourceManager> resource_manager)
      : size_(size),
        done_(std::move(done)),
        resource_manager_(resource_manager) {
    DETACH_FROM_SEQUENCE(sequence_checker_);
    EXPECT_TRUE(done_);
    sequenced_task_runner_->PostTask(
        FROM_HERE, base::BindOnce(&Actor::Start, base::Unretained(this)));
  }

  ~Actor() {
    DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
    EXPECT_FALSE(done_);
  }

  void Start() {
    DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
    // Pretend that the reservation was unavailable, schedule callback when it
    // becomes available.
    resource_manager_->RegisterCallback(
        size_,
        base::BindOnce(&Actor::OnResourceRelease, base::Unretained(this)));
  }

  void Execute() {
    auto done = std::move(done_);
    resource_manager_->Discard(size_);
    delete this;
    // Signal after deletion, to prevent potential test flake.
    std::move(done).Run();
  }

  void OnResourceRelease() {
    DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);  // Same task runner!
    if (!resource_manager_->Reserve(size_)) {
      // Still not available, reschedule callback.
      resource_manager_->RegisterCallback(
          size_,
          base::BindOnce(&Actor::OnResourceRelease, base::Unretained(this)));
      return;
    }
    // Reserved. Pause, then release and delete itself.
    sequenced_task_runner_->PostDelayedTask(
        FROM_HERE, base::BindOnce(&Actor::Execute, base::Unretained(this)),
        base::Seconds(1));
  }

 private:
  const uint64_t size_;
  base::OnceClosure done_;
  scoped_refptr<ResourceManager> resource_manager_;
  const scoped_refptr<base::SequencedTaskRunner> sequenced_task_runner_{
      base::ThreadPool::CreateSequencedTaskRunner(
          {base::TaskPriority::BEST_EFFORT})};
  SEQUENCE_CHECKER(sequence_checker_);
};

TEST_P(ResourceManagerTest, ReservationWithWaits) {
  static constexpr size_t kActorsCount = 64;

  // Occupy whole resource.

  ASSERT_TRUE(resource_->Reserve(resource_->GetTotal()));
  // Create a number of Actors reserving 1/2 of total resource.
  // Only two of them could fit simultaneously, others will wait and retry
  // getting the resource after being called back.
  test::TestCallbackAutoWaiter waiter;
  waiter.Attach(kActorsCount - 1);
  for (size_t i = 0; i < kActorsCount; ++i) {
    new Actor(resource_->GetTotal() / 2,
              base::BindOnce(&test::TestCallbackAutoWaiter::Signal,
                             base::Unretained(&waiter)),
              resource_);
  }

  // Release resource.
  resource_->Discard(resource_->GetTotal());

  // All waiting Actors are called back to get resource, finish work,
  // and then the waiter will be signaled.
  task_environment_.FastForwardUntilNoTasksRemain();
}

TEST_P(ResourceManagerTest, ReservationWithWaitsOnEmptyReservation) {
  // Similar to the previous test, but with no reservation other than
  // the Actors.
  static constexpr size_t kActorsCount = 64;

  // Create a number of Actors reserving 1/2 of total resource.
  // Only two of them could fit simultaneously, others will wait and retry
  // getting the resource after being called back.
  test::TestCallbackAutoWaiter waiter;
  waiter.Attach(kActorsCount - 1);
  for (size_t i = 0; i < kActorsCount; ++i) {
    new Actor(resource_->GetTotal() / 2,
              base::BindOnce(&test::TestCallbackAutoWaiter::Signal,
                             base::Unretained(&waiter)),
              resource_);
  }

  // Waiting Actors are called back to get resource, finish work,
  // and then the waiter will be signaled.
  task_environment_.FastForwardUntilNoTasksRemain();
}

INSTANTIATE_TEST_SUITE_P(VariousResources,
                         ResourceManagerTest,
                         testing::Values(16u * 1024LLu * 1024LLu,
                                         4u * 1024LLu * 1024LLu));
}  // namespace
}  // namespace reporting

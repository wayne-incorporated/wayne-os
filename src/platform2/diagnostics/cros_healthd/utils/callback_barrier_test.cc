// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <utility>

#include <base/functional/callback_helpers.h>
#include <gtest/gtest.h>
#include <mojo/public/cpp/bindings/callback_helpers.h>

#include "diagnostics/cros_healthd/utils/callback_barrier.h"

namespace diagnostics {
namespace {

base::OnceClosure ExpectToBeCalledCallback() {
  return mojo::WrapCallbackWithDropHandler(
      base::BindOnce([]() {}), base::BindOnce([]() {
        EXPECT_TRUE(false) << "The callback was dropped without being called.";
      }));
}

base::OnceClosure ExpectNotToBeCalledCallback() {
  return base::BindOnce([]() { EXPECT_TRUE(false) << "Should not be called"; });
}

TEST(CallbackBarrierTest, Depend) {
  CallbackBarrier barrier{ExpectToBeCalledCallback(),
                          ExpectNotToBeCalledCallback()};
  auto cb = barrier.Depend(base::BindOnce([]() {}));
  std::move(cb).Run();
}

TEST(CallbackBarrierTest, DependencyClosure) {
  CallbackBarrier barrier{ExpectToBeCalledCallback(),
                          ExpectNotToBeCalledCallback()};
  auto cb = barrier.CreateDependencyClosure();
  std::move(cb).Run();
}

TEST(CallbackBarrierTest, DependMultiple) {
  CallbackBarrier barrier{ExpectToBeCalledCallback(),
                          ExpectNotToBeCalledCallback()};
  auto cb1 = barrier.Depend(base::BindOnce([]() {}));
  auto cb2 = barrier.Depend(base::BindOnce([]() {}));
  auto cb3 = barrier.Depend(base::BindOnce([]() {}));
  auto cb4 = barrier.Depend(base::BindOnce([]() {}));
  std::move(cb1).Run();
  std::move(cb2).Run();
  std::move(cb3).Run();
  std::move(cb4).Run();
}

TEST(CallbackBarrierTest, CallBetweenEachDepend) {
  CallbackBarrier barrier{ExpectToBeCalledCallback(),
                          ExpectNotToBeCalledCallback()};
  auto cb1 = barrier.Depend(base::BindOnce([]() {}));
  std::move(cb1).Run();
  auto cb2 = barrier.Depend(base::BindOnce([]() {}));
  std::move(cb2).Run();
  auto cb3 = barrier.Depend(base::BindOnce([]() {}));
  std::move(cb3).Run();
  auto cb4 = barrier.Depend(base::BindOnce([]() {}));
  std::move(cb4).Run();
}

TEST(CallbackBarrierTest, NoDepend) {
  // barrier calls on_success after it is destructed.
  CallbackBarrier barrier{ExpectToBeCalledCallback(),
                          ExpectNotToBeCalledCallback()};
}

TEST(CallbackBarrierTest, DeleteCallbackBarrierBeforeCallbackCalled) {
  base::OnceClosure cb;
  {
    CallbackBarrier barrier{ExpectToBeCalledCallback(),
                            ExpectNotToBeCalledCallback()};
    cb = barrier.Depend(base::BindOnce([]() {}));
  }
  std::move(cb).Run();
}

TEST(CallbackBarrierTest, CallbackNotCalled) {
  CallbackBarrier barrier{ExpectNotToBeCalledCallback(),
                          ExpectToBeCalledCallback()};
  // This is not called so the barrier calls on_error.
  barrier.Depend(base::BindOnce([]() {}));
}

TEST(CallbackBarrierTest, OneOfManyCallbacksNotCalled) {
  CallbackBarrier barrier{ExpectNotToBeCalledCallback(),
                          ExpectToBeCalledCallback()};
  // cb1 is not called so the barrier calls on_error.
  auto cb1 = barrier.Depend(base::BindOnce([]() {}));
  auto cb2 = barrier.Depend(base::BindOnce([]() {}));
  auto cb3 = barrier.Depend(base::BindOnce([]() {}));
  auto cb4 = barrier.Depend(base::BindOnce([]() {}));
  std::move(cb2).Run();
  std::move(cb3).Run();
  std::move(cb4).Run();
}

}  // namespace
}  // namespace diagnostics

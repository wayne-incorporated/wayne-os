// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <utility>

#include <base/run_loop.h>
#include <base/test/bind.h>
#include <base/test/task_environment.h>
#include <gtest/gtest.h>
#include <mojo/core/embedder/embedder.h>
#include <mojo/core/embedder/scoped_ipc_support.h>
#include <mojo/public/cpp/bindings/receiver.h>
#include <mojo/public/cpp/bindings/receiver_set.h>
#include <mojo/public/cpp/bindings/remote.h>

#include "diagnostics/bindings/connectivity/context.h"
#include "diagnostics/bindings/connectivity/local_state.h"
#include "diagnostics/bindings/connectivity/remote_state.h"
#include "diagnostics/mojom/public/cros_healthd.mojom-connectivity.h"

namespace diagnostics {
namespace {

namespace connectivity = ::ash::cros_healthd::connectivity;
namespace mojom = ::ash::cros_healthd::mojom;

class CrosHealthdConnectivityTest : public ::testing::Test {
 protected:
  void SetUp() override {
    ::mojo::core::Init();
    ipc_support_ = std::make_unique<::mojo::core::ScopedIPCSupport>(
        base::SingleThreadTaskRunner::
            GetCurrentDefault() /* io_thread_task_runner */,
        ::mojo::core::ScopedIPCSupport::ShutdownPolicy::
            CLEAN /* blocking shutdown */);

    mojo::PendingReceiver<connectivity::mojom::State> receiver;
    auto remote = receiver.InitWithNewPipeAndPassRemote();
    context_ = connectivity::Context::Create(
        connectivity::LocalState::Create(std::move(receiver)),
        connectivity::RemoteState::Create(std::move(remote)));
  }

  connectivity::Context* context() { return context_.get(); }

 private:
  base::test::SingleThreadTaskEnvironment task_environment_;
  std::unique_ptr<mojo::core::ScopedIPCSupport> ipc_support_;
  std::unique_ptr<connectivity::Context> context_;
};

template <typename ConsumerType>
bool Check(ConsumerType* consumer) {
  base::RunLoop run_loop;
  bool res;
  consumer->Check(base::BindLambdaForTesting([&](bool res_inner) {
    res = res_inner;
    run_loop.Quit();
  }));
  run_loop.Run();
  return res;
}

#define INTERFACE_TEST_BASE(INTERFACE_NAME)                               \
  auto provider = mojom::INTERFACE_NAME##TestProvider::Create(context()); \
  ASSERT_NE(provider, nullptr);                                           \
  auto consumer = mojom::INTERFACE_NAME##TestConsumer::Create(context()); \
  ASSERT_NE(consumer, nullptr);                                           \
  provider->Bind(consumer->Generate())

#define SUCCESSFUL_TEST(INTERFACE_NAME)                 \
  TEST_F(CrosHealthdConnectivityTest, INTERFACE_NAME) { \
    INTERFACE_TEST_BASE(INTERFACE_NAME);                \
    EXPECT_TRUE(Check(consumer.get()));                 \
  }

SUCCESSFUL_TEST(CrosHealthdServiceFactory);

}  // namespace
}  // namespace diagnostics

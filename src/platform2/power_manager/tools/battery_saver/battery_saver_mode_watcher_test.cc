// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/tools/battery_saver/battery_saver_mode_watcher.h"

#include <string>
#include <utility>
#include <vector>

#include <base/run_loop.h>
#include <base/test/bind.h>
#include <base/test/repeating_test_future.h>
#include <base/test/task_environment.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <power_manager/dbus-proxy-mocks.h>
#include <power_manager/proto_bindings/battery_saver.pb.h>

#include "power_manager/tools/battery_saver/proto_util.h"
#include "power_manager/tools/battery_saver/task_util.h"

namespace power_manager {
namespace {

using ::base::test::RepeatingTestFuture;
using ::org::chromium::PowerManagerProxyMock;
using ::testing::_;
using ::testing::ContainsRegex;

class BatterySaverModeWatcherTest : public testing::Test {
  base::test::SingleThreadTaskEnvironment task_environment_;
};

// Implements a fake `PowerManagerProxyInterface`, implementing the calls used
// by `BatterySaverModeWatcher`, such as fetching the current BSM state, and
// broadcasting changes to the BSM state.
class FakePowerManagerProxy
    // We inherit from PowerManagerProxyMock to avoid having to implement the
    // ~100 different DBus methods in PowerManagerProxyInterface.
    //
    // The `StrictMock` wrapper will cause calls to unimplemented functions to
    // fail the test.
    : public testing::StrictMock<PowerManagerProxyMock> {
 public:
  explicit FakePowerManagerProxy(BatterySaverModeState initial_state)
      : state_(std::move(initial_state)) {}

  // Send a signal indicating the BSM state has been updated.
  void UpdateState(BatterySaverModeState new_state) {
    state_ = std::move(new_state);
    if (!signal_callback_.is_null()) {
      PostToCurrentSequence(
          base::BindOnce(signal_callback_, SerializeProto(state_)));
    }
  }

  // `PowerManagerProxyInterface` implementation.

  void RegisterBatterySaverModeStateChangedSignalHandler(
      const base::RepeatingCallback<void(const std::vector<uint8_t>&)>&
          signal_callback,
      dbus::ObjectProxy::OnConnectedCallback on_connected_callback) override {
    // Save the callback, and post a notification that the connection was
    // successful.
    signal_callback_ = signal_callback;
    PostToCurrentSequence(base::BindOnce(std::move(on_connected_callback), "",
                                         "", /*success=*/true));
  }

  void GetBatterySaverModeStateAsync(
      base::OnceCallback<void(const std::vector<uint8_t>&)> success_callback,
      base::OnceCallback<void(brillo::Error*)> error_callback,
      int timeout) override {
    // Return the current state.
    PostToCurrentSequence(
        base::BindOnce(signal_callback_, SerializeProto(state_)));
  }

 private:
  base::RepeatingCallback<void(const std::vector<uint8_t>&)> signal_callback_;
  BatterySaverModeState state_;
};

TEST_F(BatterySaverModeWatcherTest, UpdateState) {
  BatterySaverModeState state;
  state.set_enabled(true);
  FakePowerManagerProxy proxy(/*initial_state=*/state);

  // Start the watcher. Expect to get a callback with the initial state.
  RepeatingTestFuture<absl::StatusOr<BatterySaverModeState>> future;
  BatterySaverModeWatcher watcher(proxy, future.GetCallback());
  {
    absl::StatusOr<BatterySaverModeState> result = future.Take();
    ASSERT_TRUE(result.ok());
    EXPECT_TRUE(result->enabled());
  }

  // Update the state. Expect the watcher to send us another value.
  state.set_enabled(false);
  proxy.UpdateState(state);
  {
    absl::StatusOr<BatterySaverModeState> result = future.Take();
    ASSERT_TRUE(result.ok());
    EXPECT_FALSE(result->enabled());
  }

  // Send the same state unchanged. We still expect a notification.
  proxy.UpdateState(state);
  {
    absl::StatusOr<BatterySaverModeState> result = future.Take();
    ASSERT_TRUE(result.ok());
    EXPECT_FALSE(result->enabled());
  }
}

// Exercise behaviour when registering for the BatterySaverModeStateChanged
// signal fails.
TEST_F(BatterySaverModeWatcherTest, RegistrationFail) {
  PowerManagerProxyMock proxy;

  // When we get a registration call, reply with a failure.
  EXPECT_CALL(proxy, DoRegisterBatterySaverModeStateChangedSignalHandler(_, _))
      .WillOnce(
          [](const base::RepeatingCallback<void(const std::vector<uint8_t>&)>&
                 callback,
             dbus::ObjectProxy::OnConnectedCallback* on_connect) {
            PostToCurrentSequence(base::BindOnce(std::move(*on_connect), "", "",
                                                 /*success=*/false));
          });

  // Attempt to register.
  RepeatingTestFuture<absl::StatusOr<BatterySaverModeState>> future;
  BatterySaverModeWatcher watcher(proxy, future.GetCallback());

  // Expect to receive an error callback.
  absl::StatusOr<BatterySaverModeState> result = future.Take();
  ASSERT_FALSE(result.ok());
  EXPECT_THAT(std::string(result.status().message()),
              ContainsRegex("Failed to subscribe"));
}

// Exercise behaviour when registering for the BatterySaverModeStateChanged
// signal succeeds, but the initial fetch of the state fails.
TEST_F(BatterySaverModeWatcherTest, InitialFetchFail) {
  PowerManagerProxyMock proxy;

  // When we get a registration call, save the callback and reply success.
  base::RepeatingCallback<void(const std::vector<uint8_t>&)> signal_callback;
  EXPECT_CALL(proxy, DoRegisterBatterySaverModeStateChangedSignalHandler(_, _))
      .WillOnce(
          [&](const base::RepeatingCallback<void(const std::vector<uint8_t>&)>&
                  callback,
              dbus::ObjectProxy::OnConnectedCallback* on_connect) {
            signal_callback = callback;
            PostToCurrentSequence(base::BindOnce(std::move(*on_connect), "", "",
                                                 /*success=*/true));
          });

  // However, fail the initial fetch.
  EXPECT_CALL(proxy, GetBatterySaverModeStateAsync(_, _, _))
      .WillOnce([](base::OnceCallback<void(const std::vector<uint8_t>&)>
                       success_callback,
                   base::OnceCallback<void(brillo::Error*)> error_callback,
                   int timeout) {
        brillo::ErrorPtr error = brillo::Error::CreateNoLog(
            FROM_HERE, "domain", "code", "message", /*inner_error=*/nullptr);
        PostToCurrentSequence(base::BindOnce(std::move(error_callback),
                                             base::Owned(std::move(error))));
      });

  // Attempt to register. We don't expect any callbacks.
  RepeatingTestFuture<absl::StatusOr<BatterySaverModeState>> future;
  BatterySaverModeWatcher watcher(proxy, future.GetCallback());

  // However, we do expect that signals will still be processed and result in
  // a callback.
  BatterySaverModeState new_state;
  new_state.set_enabled(true);
  PostToCurrentSequence(
      base::BindOnce(signal_callback, SerializeProto(new_state)));
  {
    absl::StatusOr<BatterySaverModeState> result = future.Take();
    ASSERT_TRUE(result.ok());
    EXPECT_TRUE(result->enabled());
  }
}

}  // namespace
}  // namespace power_manager

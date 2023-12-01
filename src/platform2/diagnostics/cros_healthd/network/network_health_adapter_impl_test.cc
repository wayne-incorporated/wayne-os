// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <optional>
#include <utility>

#include <base/functional/callback.h>
#include <base/run_loop.h>
#include <base/test/bind.h>
#include <base/test/task_environment.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <mojo/public/cpp/bindings/pending_receiver.h>
#include <mojo/public/cpp/bindings/receiver.h>
#include <mojo/public/cpp/bindings/remote.h>

#include "diagnostics/cros_healthd/network/network_health_adapter_impl.h"
#include "diagnostics/mojom/external/network_health.mojom.h"
#include "diagnostics/mojom/external/network_health_types.mojom.h"

namespace diagnostics {
namespace {

namespace network_health_ipc = chromeos::network_health::mojom;

const char kFakeGuid[] = "fake_guid";

class MockNetworkHealthService
    : public network_health_ipc::NetworkHealthService {
 public:
  MockNetworkHealthService() : receiver_{this} {}
  MockNetworkHealthService(const MockNetworkHealthService&) = delete;
  MockNetworkHealthService& operator=(const MockNetworkHealthService&) = delete;

  MOCK_METHOD(void,
              GetNetworkList,
              (NetworkHealthService::GetNetworkListCallback),
              (override));
  MOCK_METHOD(void,
              GetHealthSnapshot,
              (NetworkHealthService::GetHealthSnapshotCallback),
              (override));
  MOCK_METHOD(void,
              AddObserver,
              (mojo::PendingRemote<network_health_ipc::NetworkEventsObserver>),
              (override));

  mojo::PendingRemote<network_health_ipc::NetworkHealthService>
  pending_remote() {
    return receiver_.BindNewPipeAndPassRemote();
  }

 private:
  mojo::Receiver<NetworkHealthService> receiver_;
};

class FakeNetworkHealthService
    : public network_health_ipc::NetworkHealthService {
 public:
  FakeNetworkHealthService() : receiver_{this} {}
  FakeNetworkHealthService(const FakeNetworkHealthService&) = delete;
  FakeNetworkHealthService& operator=(const FakeNetworkHealthService&) = delete;

  // network_health_ipc::NetworkHealthService overrides:
  // unimplemented
  void GetNetworkList(
      network_health_ipc::NetworkHealthService::GetNetworkListCallback)
      override {}
  // unimplemented
  void GetHealthSnapshot(
      network_health_ipc::NetworkHealthService::GetHealthSnapshotCallback)
      override {}
  void AddObserver(
      mojo::PendingRemote<network_health_ipc::NetworkEventsObserver>
          pending_remote) override {
    remote_.Bind(std::move(pending_remote));
  }

  void EmitConnectionStateChangedEvent(const std::string& guid,
                                       network_health_ipc::NetworkState state) {
    remote_->OnConnectionStateChanged(guid, state);
  }

  void EmitSignalStrengthChangedEvent(
      const std::string& guid,
      network_health_ipc::UInt32ValuePtr signal_strength) {
    remote_->OnSignalStrengthChanged(guid, std::move(signal_strength));
  }

  mojo::PendingRemote<network_health_ipc::NetworkHealthService>
  pending_remote() {
    return receiver_.BindNewPipeAndPassRemote();
  }

 private:
  mojo::Receiver<NetworkHealthService> receiver_;
  mojo::Remote<network_health_ipc::NetworkEventsObserver> remote_;
};

class MockNetworkEventsObserver
    : public network_health_ipc::NetworkEventsObserver {
 public:
  MockNetworkEventsObserver() : receiver_{this} {}
  MockNetworkEventsObserver(const MockNetworkEventsObserver&) = delete;
  MockNetworkEventsObserver& operator=(const MockNetworkEventsObserver&) =
      delete;

  MOCK_METHOD(void,
              OnConnectionStateChanged,
              (const std::string&, network_health_ipc::NetworkState),
              (override));
  MOCK_METHOD(void,
              OnSignalStrengthChanged,
              (const std::string&, network_health_ipc::UInt32ValuePtr),
              (override));

  mojo::PendingRemote<network_health_ipc::NetworkEventsObserver>
  pending_remote() {
    return receiver_.BindNewPipeAndPassRemote();
  }

 private:
  mojo::Receiver<network_health_ipc::NetworkEventsObserver> receiver_;
};

class NetworkHealthAdapterImplTest : public testing::Test {
 protected:
  NetworkHealthAdapterImplTest() = default;
  NetworkHealthAdapterImplTest(const NetworkHealthAdapterImplTest&) = delete;
  NetworkHealthAdapterImplTest& operator=(const NetworkHealthAdapterImplTest&) =
      delete;

  void SetUp() override {
    // Create a new |network_health_adapter_| for each test to ensure the
    // adapter is not already listening for network events.
    network_health_adapter_ = std::make_unique<NetworkHealthAdapterImpl>();
  }

  void RunUntilIdle() { task_environment_.RunUntilIdle(); }

  NetworkHealthAdapterImpl* network_health_adapter() {
    return network_health_adapter_.get();
  }

 private:
  base::test::TaskEnvironment task_environment_;
  std::unique_ptr<NetworkHealthAdapterImpl> network_health_adapter_;
};

// Test that the NetworkHealthAdapterImpl can set the NetworkHealthService
// remote and request the NetworkHealthState.
TEST_F(NetworkHealthAdapterImplTest, RequestNetworkHealthState) {
  MockNetworkHealthService service;
  network_health_adapter()->SetServiceRemote(service.pending_remote());

  base::RunLoop run_loop;
  auto canned_response = network_health_ipc::NetworkHealthState::New();
  EXPECT_CALL(service, GetHealthSnapshot(testing::_))
      .WillOnce(testing::Invoke([&](network_health_ipc::NetworkHealthService::
                                        GetHealthSnapshotCallback callback) {
        std::move(callback).Run(canned_response.Clone());
      }));

  network_health_adapter()->GetNetworkHealthState(base::BindLambdaForTesting(
      [&](std::optional<network_health_ipc::NetworkHealthStatePtr> response) {
        ASSERT_TRUE(response.has_value());
        EXPECT_EQ(canned_response, response);
        run_loop.Quit();
      }));

  run_loop.Run();
}

// Test that NetworkHealthAdapterImpl can set the NetworkHealthService remote
// and adds itself as an observer of the NetworkEventsObserver interface.
TEST_F(NetworkHealthAdapterImplTest, AddNetworkEventsObserver) {
  MockNetworkHealthService service;
  network_health_adapter()->SetServiceRemote(service.pending_remote());

  base::RunLoop run_loop;
  EXPECT_CALL(service, AddObserver(testing::_))
      .WillOnce(testing::Invoke(
          [&](mojo::PendingRemote<network_health_ipc::NetworkEventsObserver>
                  pending_remote) { run_loop.Quit(); }));

  // Add a NetworkObserver to the NetworkHealthAdapterImpl instance. The
  // NetworkHealthAdapterImpl instance should start listening for network
  // events.
  MockNetworkEventsObserver observer;
  network_health_adapter()->AddObserver(observer.pending_remote());

  run_loop.Run();
}

// Test that the NetworkHealthAdapter can receive connection state change
// events.
TEST_F(NetworkHealthAdapterImplTest, ReceiveConnectionStateChangeEvent) {
  FakeNetworkHealthService fake_service;
  network_health_adapter()->SetServiceRemote(fake_service.pending_remote());

  base::RunLoop run_loop;
  MockNetworkEventsObserver mock_observer;
  auto network_state = network_health_ipc::NetworkState::kConnected;
  EXPECT_CALL(mock_observer, OnConnectionStateChanged(kFakeGuid, network_state))
      .WillOnce(testing::Invoke(
          [&](const std::string& guid, network_health_ipc::NetworkState state) {
            run_loop.Quit();
          }));

  network_health_adapter()->AddObserver(mock_observer.pending_remote());

  RunUntilIdle();

  fake_service.EmitConnectionStateChangedEvent(kFakeGuid, network_state);

  run_loop.Run();
}

// Test that the NetworkHealthAdapter can receive signal strength change events.
TEST_F(NetworkHealthAdapterImplTest, ReceiveSignalStrengthChangeEvent) {
  FakeNetworkHealthService service;
  network_health_adapter()->SetServiceRemote(service.pending_remote());

  base::RunLoop run_loop;
  MockNetworkEventsObserver observer;
  uint32_t network_signal_strength = 50;
  EXPECT_CALL(observer, OnSignalStrengthChanged(kFakeGuid, testing::_))
      .WillOnce(testing::Invoke(
          [&](const std::string& guid,
              network_health_ipc::UInt32ValuePtr signal_strength) {
            EXPECT_EQ(signal_strength->value, network_signal_strength);
            run_loop.Quit();
          }));

  network_health_adapter()->AddObserver(observer.pending_remote());

  RunUntilIdle();

  service.EmitSignalStrengthChangedEvent(
      kFakeGuid, network_health_ipc::UInt32Value::New(network_signal_strength));

  run_loop.Run();
}

// Test a std::nullopt is returned if no remote is bound;
TEST_F(NetworkHealthAdapterImplTest, NoRemote) {
  base::RunLoop run_loop;
  network_health_adapter()->GetNetworkHealthState(base::BindLambdaForTesting(
      [&](std::optional<network_health_ipc::NetworkHealthStatePtr> response) {
        EXPECT_FALSE(response.has_value());
        run_loop.Quit();
      }));

  run_loop.Run();
}

// Test that the correct status of the bound remote is returned on request.
TEST_F(NetworkHealthAdapterImplTest, RemoteBoundCheck) {
  EXPECT_FALSE(network_health_adapter()->ServiceRemoteBound());

  MockNetworkHealthService service;
  network_health_adapter()->SetServiceRemote(service.pending_remote());
  EXPECT_TRUE(network_health_adapter()->ServiceRemoteBound());
}

}  // namespace
}  // namespace diagnostics

// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/test/task_environment.h>
#include <base/test/test_future.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <mojo/public/cpp/bindings/pending_remote.h>
#include <mojo/public/cpp/bindings/receiver.h>

#include "diagnostics/cros_healthd/network_diagnostics/network_diagnostics_adapter_impl.h"
#include "diagnostics/cros_healthd/network_diagnostics/network_diagnostics_utils.h"

namespace diagnostics {
namespace {

using base::test::TestFuture;
using testing::_;
using testing::Invoke;
using testing::WithArg;

namespace network_diagnostics_ipc = chromeos::network_diagnostics::mojom;

constexpr network_diagnostics_ipc::RoutineVerdict kNoProblem =
    network_diagnostics_ipc::RoutineVerdict::kNoProblem;

class MockNetworkDiagnosticsRoutines final
    : public network_diagnostics_ipc::NetworkDiagnosticsRoutines {
 public:
  MockNetworkDiagnosticsRoutines() : receiver_{this} {}
  MockNetworkDiagnosticsRoutines(const MockNetworkDiagnosticsRoutines&) =
      delete;
  MockNetworkDiagnosticsRoutines& operator=(
      const MockNetworkDiagnosticsRoutines&) = delete;

  MOCK_METHOD(void,
              RunLanConnectivity,
              (network_diagnostics_ipc::NetworkDiagnosticsRoutines::
                   RunLanConnectivityCallback),
              (override));
  MOCK_METHOD(void,
              RunSignalStrength,
              (network_diagnostics_ipc::NetworkDiagnosticsRoutines::
                   RunSignalStrengthCallback),
              (override));
  MOCK_METHOD(void,
              RunGatewayCanBePinged,
              (network_diagnostics_ipc::NetworkDiagnosticsRoutines::
                   RunGatewayCanBePingedCallback),
              (override));
  MOCK_METHOD(void,
              RunHasSecureWiFiConnection,
              (network_diagnostics_ipc::NetworkDiagnosticsRoutines::
                   RunHasSecureWiFiConnectionCallback),
              (override));
  MOCK_METHOD(void,
              RunDnsResolverPresent,
              (network_diagnostics_ipc::NetworkDiagnosticsRoutines::
                   RunDnsResolverPresentCallback),
              (override));
  MOCK_METHOD(void,
              RunDnsLatency,
              (network_diagnostics_ipc::NetworkDiagnosticsRoutines::
                   RunDnsLatencyCallback),
              (override));
  MOCK_METHOD(void,
              RunDnsResolution,
              (network_diagnostics_ipc::NetworkDiagnosticsRoutines::
                   RunDnsResolutionCallback),
              (override));
  MOCK_METHOD(void,
              RunCaptivePortal,
              (network_diagnostics_ipc::NetworkDiagnosticsRoutines::
                   RunCaptivePortalCallback),
              (override));
  MOCK_METHOD(void,
              RunHttpFirewall,
              (network_diagnostics_ipc::NetworkDiagnosticsRoutines::
                   RunHttpFirewallCallback),
              (override));
  MOCK_METHOD(void,
              RunHttpsFirewall,
              (network_diagnostics_ipc::NetworkDiagnosticsRoutines::
                   RunHttpsFirewallCallback),
              (override));
  MOCK_METHOD(void,
              RunHttpsLatency,
              (network_diagnostics_ipc::NetworkDiagnosticsRoutines::
                   RunHttpsLatencyCallback),
              (override));
  MOCK_METHOD(void,
              RunVideoConferencing,
              (const std::optional<std::string>&,
               network_diagnostics_ipc::NetworkDiagnosticsRoutines::
                   RunVideoConferencingCallback),
              (override));
  MOCK_METHOD(
      void,
      RunArcHttp,
      (network_diagnostics_ipc::NetworkDiagnosticsRoutines::RunArcHttpCallback),
      (override));
  MOCK_METHOD(void,
              RunArcDnsResolution,
              (network_diagnostics_ipc::NetworkDiagnosticsRoutines::
                   RunArcDnsResolutionCallback),
              (override));
  MOCK_METHOD(
      void,
      RunArcPing,
      (network_diagnostics_ipc::NetworkDiagnosticsRoutines::RunArcPingCallback),
      (override));
  MOCK_METHOD(
      void,
      GetResult,
      (const network_diagnostics_ipc::RoutineType type,
       network_diagnostics_ipc::NetworkDiagnosticsRoutines::GetResultCallback),
      (override));
  MOCK_METHOD(void,
              GetAllResults,
              (network_diagnostics_ipc::NetworkDiagnosticsRoutines::
                   GetAllResultsCallback),
              (override));

  mojo::PendingRemote<network_diagnostics_ipc::NetworkDiagnosticsRoutines>
  pending_remote() {
    return receiver_.BindNewPipeAndPassRemote();
  }

 private:
  mojo::Receiver<network_diagnostics_ipc::NetworkDiagnosticsRoutines> receiver_;
};

class NetworkDiagnosticsAdapterImplTest : public testing::Test {
 protected:
  NetworkDiagnosticsAdapterImplTest() = default;
  NetworkDiagnosticsAdapterImplTest(const NetworkDiagnosticsAdapterImplTest&) =
      delete;
  NetworkDiagnosticsAdapterImplTest& operator=(
      const NetworkDiagnosticsAdapterImplTest&) = delete;

  NetworkDiagnosticsAdapterImpl* network_diagnostics_adapter() {
    return &network_diagnostics_adapter_;
  }

 private:
  base::test::SingleThreadTaskEnvironment task_environment_;
  NetworkDiagnosticsAdapterImpl network_diagnostics_adapter_;
};

// Test that the LanConnectivity routine can be run.
TEST_F(NetworkDiagnosticsAdapterImplTest, RunLanConnectivityRoutine) {
  MockNetworkDiagnosticsRoutines network_diagnostics_routines;
  network_diagnostics_adapter()->SetNetworkDiagnosticsRoutines(
      network_diagnostics_routines.pending_remote());

  EXPECT_CALL(network_diagnostics_routines, RunLanConnectivity(_))
      .WillOnce(WithArg<0>(
          Invoke([&](network_diagnostics_ipc::NetworkDiagnosticsRoutines::
                         RunLanConnectivityCallback callback) {
            auto result = CreateResult(
                network_diagnostics_ipc::RoutineVerdict::kNoProblem,
                network_diagnostics_ipc::RoutineProblems::
                    NewLanConnectivityProblems({}));
            std::move(callback).Run(std::move(result));
          })));

  TestFuture<network_diagnostics_ipc::RoutineResultPtr> future;
  network_diagnostics_adapter()->RunLanConnectivityRoutine(
      future.GetCallback());

  auto result = future.Take();
  EXPECT_EQ(result->verdict, kNoProblem);
  EXPECT_EQ(result->problems->get_lan_connectivity_problems().size(), 0);
}

// Test that the SignalStrength routine can be run.
TEST_F(NetworkDiagnosticsAdapterImplTest, RunSignalStrengthRoutine) {
  MockNetworkDiagnosticsRoutines network_diagnostics_routines;
  network_diagnostics_adapter()->SetNetworkDiagnosticsRoutines(
      network_diagnostics_routines.pending_remote());

  EXPECT_CALL(network_diagnostics_routines, RunSignalStrength(_))
      .WillOnce(WithArg<0>(
          Invoke([&](network_diagnostics_ipc::NetworkDiagnosticsRoutines::
                         RunSignalStrengthCallback callback) {
            auto result = CreateResult(
                network_diagnostics_ipc::RoutineVerdict::kNoProblem,
                network_diagnostics_ipc::RoutineProblems::
                    NewSignalStrengthProblems({}));
            std::move(callback).Run(std::move(result));
          })));

  TestFuture<network_diagnostics_ipc::RoutineResultPtr> future;
  network_diagnostics_adapter()->RunSignalStrengthRoutine(future.GetCallback());

  auto result = future.Take();
  EXPECT_EQ(result->verdict,
            network_diagnostics_ipc::RoutineVerdict::kNoProblem);
  EXPECT_EQ(result->problems->get_signal_strength_problems().size(), 0);
}

// Test that the GatewayCanBePinged routine can be run.
TEST_F(NetworkDiagnosticsAdapterImplTest, RunGatewayCanBePingedRoutine) {
  MockNetworkDiagnosticsRoutines network_diagnostics_routines;
  network_diagnostics_adapter()->SetNetworkDiagnosticsRoutines(
      network_diagnostics_routines.pending_remote());

  EXPECT_CALL(network_diagnostics_routines, RunGatewayCanBePinged(testing::_))
      .WillOnce(testing::Invoke(
          [&](network_diagnostics_ipc::NetworkDiagnosticsRoutines::
                  RunGatewayCanBePingedCallback callback) {
            auto result = CreateResult(
                network_diagnostics_ipc::RoutineVerdict::kNoProblem,
                network_diagnostics_ipc::RoutineProblems::
                    NewGatewayCanBePingedProblems({}));
            std::move(callback).Run(std::move(result));
          }));

  TestFuture<network_diagnostics_ipc::RoutineResultPtr> future;
  network_diagnostics_adapter()->RunGatewayCanBePingedRoutine(
      future.GetCallback());

  auto result = future.Take();
  EXPECT_EQ(result->verdict,
            network_diagnostics_ipc::RoutineVerdict::kNoProblem);
  EXPECT_EQ(result->problems->get_gateway_can_be_pinged_problems().size(), 0);
}

// Test that the HasSecureWiFiConnection routine can be run.
TEST_F(NetworkDiagnosticsAdapterImplTest, RunHasSecureWiFiConnectionRoutine) {
  MockNetworkDiagnosticsRoutines network_diagnostics_routines;
  network_diagnostics_adapter()->SetNetworkDiagnosticsRoutines(
      network_diagnostics_routines.pending_remote());

  EXPECT_CALL(network_diagnostics_routines,
              RunHasSecureWiFiConnection(testing::_))
      .WillOnce(testing::Invoke(
          [&](network_diagnostics_ipc::NetworkDiagnosticsRoutines::
                  RunHasSecureWiFiConnectionCallback callback) {
            auto result = CreateResult(
                network_diagnostics_ipc::RoutineVerdict::kNoProblem,
                network_diagnostics_ipc::RoutineProblems::
                    NewHasSecureWifiConnectionProblems({}));
            std::move(callback).Run(std::move(result));
          }));

  TestFuture<network_diagnostics_ipc::RoutineResultPtr> future;
  network_diagnostics_adapter()->RunHasSecureWiFiConnectionRoutine(
      future.GetCallback());

  auto result = future.Take();
  EXPECT_EQ(result->verdict,
            network_diagnostics_ipc::RoutineVerdict::kNoProblem);
  EXPECT_EQ(result->problems->get_has_secure_wifi_connection_problems().size(),
            0);
}

// Test that the DnsResolverPresent routine can be run.
TEST_F(NetworkDiagnosticsAdapterImplTest, RunDnsResolverPresentRoutine) {
  MockNetworkDiagnosticsRoutines network_diagnostics_routines;
  network_diagnostics_adapter()->SetNetworkDiagnosticsRoutines(
      network_diagnostics_routines.pending_remote());

  EXPECT_CALL(network_diagnostics_routines, RunDnsResolverPresent(testing::_))
      .WillOnce(testing::Invoke(
          [&](network_diagnostics_ipc::NetworkDiagnosticsRoutines::
                  RunDnsResolverPresentCallback callback) {
            auto result = CreateResult(
                network_diagnostics_ipc::RoutineVerdict::kNoProblem,
                network_diagnostics_ipc::RoutineProblems::
                    NewDnsResolverPresentProblems({}));
            std::move(callback).Run(std::move(result));
          }));

  TestFuture<network_diagnostics_ipc::RoutineResultPtr> future;
  network_diagnostics_adapter()->RunDnsResolverPresentRoutine(
      future.GetCallback());

  auto result = future.Take();
  EXPECT_EQ(result->verdict,
            network_diagnostics_ipc::RoutineVerdict::kNoProblem);
  EXPECT_EQ(result->problems->get_dns_resolver_present_problems().size(), 0);
}

// Test that the DnsLatency routine can be run.
TEST_F(NetworkDiagnosticsAdapterImplTest, RunDnsLatencyRoutine) {
  MockNetworkDiagnosticsRoutines network_diagnostics_routines;
  network_diagnostics_adapter()->SetNetworkDiagnosticsRoutines(
      network_diagnostics_routines.pending_remote());

  EXPECT_CALL(network_diagnostics_routines, RunDnsLatency(testing::_))
      .WillOnce(testing::Invoke(
          [&](network_diagnostics_ipc::NetworkDiagnosticsRoutines::
                  RunDnsLatencyCallback callback) {
            auto result = CreateResult(
                network_diagnostics_ipc::RoutineVerdict::kNoProblem,
                network_diagnostics_ipc::RoutineProblems::NewDnsLatencyProblems(
                    {}));
            std::move(callback).Run(std::move(result));
          }));

  TestFuture<network_diagnostics_ipc::RoutineResultPtr> future;
  network_diagnostics_adapter()->RunDnsLatencyRoutine(future.GetCallback());

  auto result = future.Take();
  EXPECT_EQ(result->verdict,
            network_diagnostics_ipc::RoutineVerdict::kNoProblem);
  EXPECT_EQ(result->problems->get_dns_latency_problems().size(), 0);
}

// Test that the DnsResolution routine can be run.
TEST_F(NetworkDiagnosticsAdapterImplTest, RunDnsResolutionRoutine) {
  MockNetworkDiagnosticsRoutines network_diagnostics_routines;
  network_diagnostics_adapter()->SetNetworkDiagnosticsRoutines(
      network_diagnostics_routines.pending_remote());

  EXPECT_CALL(network_diagnostics_routines, RunDnsResolution(testing::_))
      .WillOnce(testing::Invoke(
          [&](network_diagnostics_ipc::NetworkDiagnosticsRoutines::
                  RunDnsResolutionCallback callback) {
            auto result = CreateResult(
                network_diagnostics_ipc::RoutineVerdict::kNoProblem,
                network_diagnostics_ipc::RoutineProblems::
                    NewDnsResolutionProblems({}));
            std::move(callback).Run(std::move(result));
          }));

  TestFuture<network_diagnostics_ipc::RoutineResultPtr> future;
  network_diagnostics_adapter()->RunDnsResolutionRoutine(future.GetCallback());

  auto result = future.Take();
  EXPECT_EQ(result->verdict,
            network_diagnostics_ipc::RoutineVerdict::kNoProblem);
  EXPECT_EQ(result->problems->get_dns_resolution_problems().size(), 0);
}

// Test that the CaptivePortal routine can be run.
TEST_F(NetworkDiagnosticsAdapterImplTest, RunCaptivePortalRoutine) {
  MockNetworkDiagnosticsRoutines network_diagnostics_routines;
  network_diagnostics_adapter()->SetNetworkDiagnosticsRoutines(
      network_diagnostics_routines.pending_remote());

  EXPECT_CALL(network_diagnostics_routines, RunCaptivePortal(testing::_))
      .WillOnce(testing::Invoke(
          [&](network_diagnostics_ipc::NetworkDiagnosticsRoutines::
                  RunCaptivePortalCallback callback) {
            auto result = CreateResult(
                network_diagnostics_ipc::RoutineVerdict::kNoProblem,
                network_diagnostics_ipc::RoutineProblems::
                    NewCaptivePortalProblems({}));
            std::move(callback).Run(std::move(result));
          }));

  TestFuture<network_diagnostics_ipc::RoutineResultPtr> future;
  network_diagnostics_adapter()->RunCaptivePortalRoutine(future.GetCallback());

  auto result = future.Take();
  EXPECT_EQ(result->verdict,
            network_diagnostics_ipc::RoutineVerdict::kNoProblem);
  EXPECT_EQ(result->problems->get_captive_portal_problems().size(), 0);
}

// Test that the HttpFirewall routine can be run.
TEST_F(NetworkDiagnosticsAdapterImplTest, RunHttpFirewallRoutine) {
  MockNetworkDiagnosticsRoutines network_diagnostics_routines;
  network_diagnostics_adapter()->SetNetworkDiagnosticsRoutines(
      network_diagnostics_routines.pending_remote());

  EXPECT_CALL(network_diagnostics_routines, RunHttpFirewall(testing::_))
      .WillOnce(testing::Invoke(
          [&](network_diagnostics_ipc::NetworkDiagnosticsRoutines::
                  RunHttpFirewallCallback callback) {
            auto result = CreateResult(
                network_diagnostics_ipc::RoutineVerdict::kNoProblem,
                network_diagnostics_ipc::RoutineProblems::
                    NewHttpFirewallProblems({}));
            std::move(callback).Run(std::move(result));
          }));

  TestFuture<network_diagnostics_ipc::RoutineResultPtr> future;
  network_diagnostics_adapter()->RunHttpFirewallRoutine(future.GetCallback());

  auto result = future.Take();
  EXPECT_EQ(result->verdict,
            network_diagnostics_ipc::RoutineVerdict::kNoProblem);
  EXPECT_EQ(result->problems->get_http_firewall_problems().size(), 0);
}

// Test that the HttpsFirewall routine can be run.
TEST_F(NetworkDiagnosticsAdapterImplTest, RunHttpsFirewallRoutine) {
  MockNetworkDiagnosticsRoutines network_diagnostics_routines;
  network_diagnostics_adapter()->SetNetworkDiagnosticsRoutines(
      network_diagnostics_routines.pending_remote());

  EXPECT_CALL(network_diagnostics_routines, RunHttpsFirewall(testing::_))
      .WillOnce(testing::Invoke(
          [&](network_diagnostics_ipc::NetworkDiagnosticsRoutines::
                  RunHttpsFirewallCallback callback) {
            auto result = CreateResult(
                network_diagnostics_ipc::RoutineVerdict::kNoProblem,
                network_diagnostics_ipc::RoutineProblems::
                    NewHttpsFirewallProblems({}));
            std::move(callback).Run(std::move(result));
          }));

  TestFuture<network_diagnostics_ipc::RoutineResultPtr> future;
  network_diagnostics_adapter()->RunHttpsFirewallRoutine(future.GetCallback());

  auto result = future.Take();
  EXPECT_EQ(result->verdict,
            network_diagnostics_ipc::RoutineVerdict::kNoProblem);
  EXPECT_EQ(result->problems->get_https_firewall_problems().size(), 0);
}

// Test that the HttpsLatency routine can be run.
TEST_F(NetworkDiagnosticsAdapterImplTest, RunHttpsLatencyRoutine) {
  MockNetworkDiagnosticsRoutines network_diagnostics_routines;
  network_diagnostics_adapter()->SetNetworkDiagnosticsRoutines(
      network_diagnostics_routines.pending_remote());

  EXPECT_CALL(network_diagnostics_routines, RunHttpsLatency(testing::_))
      .WillOnce(testing::Invoke(
          [&](network_diagnostics_ipc::NetworkDiagnosticsRoutines::
                  RunHttpsLatencyCallback callback) {
            auto result = CreateResult(
                network_diagnostics_ipc::RoutineVerdict::kNoProblem,
                network_diagnostics_ipc::RoutineProblems::
                    NewHttpsLatencyProblems({}));
            std::move(callback).Run(std::move(result));
          }));

  TestFuture<network_diagnostics_ipc::RoutineResultPtr> future;
  network_diagnostics_adapter()->RunHttpsLatencyRoutine(future.GetCallback());

  auto result = future.Take();
  EXPECT_EQ(result->verdict,
            network_diagnostics_ipc::RoutineVerdict::kNoProblem);
  EXPECT_EQ(result->problems->get_https_latency_problems().size(), 0);
}

// Test that the VideoConferencing routine can be run.
TEST_F(NetworkDiagnosticsAdapterImplTest, RunVideoConferencingRoutine) {
  MockNetworkDiagnosticsRoutines network_diagnostics_routines;
  network_diagnostics_adapter()->SetNetworkDiagnosticsRoutines(
      network_diagnostics_routines.pending_remote());

  EXPECT_CALL(network_diagnostics_routines, RunVideoConferencing(_, _))
      .WillOnce(testing::Invoke(
          [&](const std::optional<std::string>& stun_server_hostname,
              network_diagnostics_ipc::NetworkDiagnosticsRoutines::
                  RunVideoConferencingCallback callback) {
            auto result = CreateResult(
                network_diagnostics_ipc::RoutineVerdict::kNoProblem,
                network_diagnostics_ipc::RoutineProblems::
                    NewVideoConferencingProblems({}));
            std::move(callback).Run(std::move(result));
          }));

  TestFuture<network_diagnostics_ipc::RoutineResultPtr> future;
  network_diagnostics_adapter()->RunVideoConferencingRoutine(
      /*stun_server_hostname=*/"http://www.stunserverhostname.com/path?k=v",
      future.GetCallback());

  auto result = future.Take();
  EXPECT_EQ(result->verdict,
            network_diagnostics_ipc::RoutineVerdict::kNoProblem);
  EXPECT_EQ(result->problems->get_video_conferencing_problems().size(), 0);
}

// Test that the ARC HTTP routine can be run.
TEST_F(NetworkDiagnosticsAdapterImplTest, RunArcHttpRoutine) {
  MockNetworkDiagnosticsRoutines network_diagnostics_routines;
  network_diagnostics_adapter()->SetNetworkDiagnosticsRoutines(
      network_diagnostics_routines.pending_remote());

  EXPECT_CALL(network_diagnostics_routines, RunArcHttp(testing::_))
      .WillOnce(testing::Invoke(
          [&](network_diagnostics_ipc::NetworkDiagnosticsRoutines::
                  RunArcHttpCallback callback) {
            auto result = CreateResult(
                network_diagnostics_ipc::RoutineVerdict::kNoProblem,
                network_diagnostics_ipc::RoutineProblems::NewArcHttpProblems(
                    {}));
            std::move(callback).Run(std::move(result));
          }));

  TestFuture<network_diagnostics_ipc::RoutineResultPtr> future;
  network_diagnostics_adapter()->RunArcHttpRoutine(future.GetCallback());

  auto result = future.Take();
  EXPECT_EQ(result->verdict,
            network_diagnostics_ipc::RoutineVerdict::kNoProblem);
  EXPECT_EQ(result->problems->get_arc_http_problems().size(), 0);
}

// Test that the ARC Ping routine can be run.
TEST_F(NetworkDiagnosticsAdapterImplTest, RunArcPingRoutine) {
  MockNetworkDiagnosticsRoutines network_diagnostics_routines;
  network_diagnostics_adapter()->SetNetworkDiagnosticsRoutines(
      network_diagnostics_routines.pending_remote());

  EXPECT_CALL(network_diagnostics_routines, RunArcPing(testing::_))
      .WillOnce(testing::Invoke(
          [&](network_diagnostics_ipc::NetworkDiagnosticsRoutines::
                  RunArcPingCallback callback) {
            auto result = CreateResult(
                network_diagnostics_ipc::RoutineVerdict::kNoProblem,
                network_diagnostics_ipc::RoutineProblems::NewArcPingProblems(
                    {}));
            std::move(callback).Run(std::move(result));
          }));

  TestFuture<network_diagnostics_ipc::RoutineResultPtr> future;
  network_diagnostics_adapter()->RunArcPingRoutine(future.GetCallback());

  auto result = future.Take();
  EXPECT_EQ(result->verdict,
            network_diagnostics_ipc::RoutineVerdict::kNoProblem);
  EXPECT_EQ(result->problems->get_arc_ping_problems().size(), 0);
}

// Test that the ARC Dns Resolution routine can be run.
TEST_F(NetworkDiagnosticsAdapterImplTest, RunArcDnsResolutionRoutine) {
  MockNetworkDiagnosticsRoutines network_diagnostics_routines;
  network_diagnostics_adapter()->SetNetworkDiagnosticsRoutines(
      network_diagnostics_routines.pending_remote());

  EXPECT_CALL(network_diagnostics_routines, RunArcDnsResolution(testing::_))
      .WillOnce(testing::Invoke(
          [&](network_diagnostics_ipc::NetworkDiagnosticsRoutines::
                  RunArcDnsResolutionCallback callback) {
            auto result = CreateResult(
                network_diagnostics_ipc::RoutineVerdict::kNoProblem,
                network_diagnostics_ipc::RoutineProblems::
                    NewArcDnsResolutionProblems({}));
            std::move(callback).Run(std::move(result));
          }));

  TestFuture<network_diagnostics_ipc::RoutineResultPtr> future;
  network_diagnostics_adapter()->RunArcDnsResolutionRoutine(
      future.GetCallback());

  auto result = future.Take();
  EXPECT_EQ(result->verdict,
            network_diagnostics_ipc::RoutineVerdict::kNoProblem);
  EXPECT_EQ(result->problems->get_arc_dns_resolution_problems().size(), 0);
}

// Test that the LanConnectivity routine returns RoutineVerdict::kNotRun if a
// valid NetworkDiagnosticsRoutines remote was never sent.
TEST_F(NetworkDiagnosticsAdapterImplTest,
       RunLanConnectivityRoutineWithNoRemote) {
  TestFuture<network_diagnostics_ipc::RoutineResultPtr> future;
  network_diagnostics_adapter()->RunLanConnectivityRoutine(
      future.GetCallback());

  auto result = future.Take();
  EXPECT_EQ(result->verdict, network_diagnostics_ipc::RoutineVerdict::kNotRun);
  EXPECT_EQ(result->problems->get_lan_connectivity_problems().size(), 0);
}

// Test that the SignalStrength routine returns RoutineVerdict::kNotRun if a
// valid NetworkDiagnosticsRoutines remote was never sent.
TEST_F(NetworkDiagnosticsAdapterImplTest,
       RunSignalStrengthRoutineWithNoRemote) {
  TestFuture<network_diagnostics_ipc::RoutineResultPtr> future;
  network_diagnostics_adapter()->RunSignalStrengthRoutine(future.GetCallback());

  auto result = future.Take();
  EXPECT_EQ(result->verdict, network_diagnostics_ipc::RoutineVerdict::kNotRun);
  EXPECT_EQ(result->problems->get_signal_strength_problems().size(), 0);
}

// Test that the GatewayCanBePinged routine returns RoutineVerdict::kNotRun if a
// valid NetworkDiagnosticsRoutines remote was never sent.
TEST_F(NetworkDiagnosticsAdapterImplTest,
       RunGatewayCanBePingedRoutineWithNoRemote) {
  TestFuture<network_diagnostics_ipc::RoutineResultPtr> future;
  network_diagnostics_adapter()->RunGatewayCanBePingedRoutine(
      future.GetCallback());

  auto result = future.Take();
  EXPECT_EQ(result->verdict, network_diagnostics_ipc::RoutineVerdict::kNotRun);
  EXPECT_EQ(result->problems->get_gateway_can_be_pinged_problems().size(), 0);
}

// Test that the HasSecureWiFiConnection routine returns RoutineVerdict::kNotRun
// if a valid NetworkDiagnosticsRoutines remote was never sent.
TEST_F(NetworkDiagnosticsAdapterImplTest,
       RunHasSecureWiFiConnectionRoutineWithNoRemote) {
  TestFuture<network_diagnostics_ipc::RoutineResultPtr> future;
  network_diagnostics_adapter()->RunHasSecureWiFiConnectionRoutine(
      future.GetCallback());

  auto result = future.Take();
  EXPECT_EQ(result->verdict, network_diagnostics_ipc::RoutineVerdict::kNotRun);
  EXPECT_EQ(result->problems->get_has_secure_wifi_connection_problems().size(),
            0);
}

// Test that the DnsResolverPresent routine returns RoutineVerdict::kNotRun if a
// valid NetworkDiagnosticsRoutines remote was never sent.
TEST_F(NetworkDiagnosticsAdapterImplTest,
       RunDnsResolverPresentRoutineWithNoRemote) {
  TestFuture<network_diagnostics_ipc::RoutineResultPtr> future;
  network_diagnostics_adapter()->RunDnsResolverPresentRoutine(
      future.GetCallback());

  auto result = future.Take();
  EXPECT_EQ(result->verdict, network_diagnostics_ipc::RoutineVerdict::kNotRun);
  EXPECT_EQ(result->problems->get_dns_resolver_present_problems().size(), 0);
}

// Test that the DnsLatency routine returns RoutineVerdict::kNotRun if a valid
// NetworkDiagnosticsRoutines remote was never sent.
TEST_F(NetworkDiagnosticsAdapterImplTest, RunDnsLatencyRoutineWithNoRemote) {
  TestFuture<network_diagnostics_ipc::RoutineResultPtr> future;
  network_diagnostics_adapter()->RunDnsLatencyRoutine(future.GetCallback());

  auto result = future.Take();
  EXPECT_EQ(result->verdict, network_diagnostics_ipc::RoutineVerdict::kNotRun);
  EXPECT_EQ(result->problems->get_dns_latency_problems().size(), 0);
}

// Test that the DnsResolution routine returns RoutineVerdict::kNotRun if a
// valid NetworkDiagnosticsRoutines remote was never sent.
TEST_F(NetworkDiagnosticsAdapterImplTest, RunDnsResolutionRoutineWithNoRemote) {
  TestFuture<network_diagnostics_ipc::RoutineResultPtr> future;
  network_diagnostics_adapter()->RunDnsResolutionRoutine(future.GetCallback());

  auto result = future.Take();
  EXPECT_EQ(result->verdict, network_diagnostics_ipc::RoutineVerdict::kNotRun);
  EXPECT_EQ(result->problems->get_dns_resolution_problems().size(), 0);
}

// Test that the CaptivePortal routine returns RoutineVerdict::kNotRun if a
// valid NetworkDiagnosticsRoutines remote was never sent.
TEST_F(NetworkDiagnosticsAdapterImplTest, RunCaptivePortalRoutineWithNoRemote) {
  TestFuture<network_diagnostics_ipc::RoutineResultPtr> future;
  network_diagnostics_adapter()->RunCaptivePortalRoutine(future.GetCallback());

  auto result = future.Take();
  EXPECT_EQ(result->verdict, network_diagnostics_ipc::RoutineVerdict::kNotRun);
  EXPECT_EQ(result->problems->get_captive_portal_problems().size(), 0);
}

// Test that the HttpFirewall routine returns RoutineVerdict::kNotRun if a valid
// NetworkDiagnosticsRoutines remote was never sent.
TEST_F(NetworkDiagnosticsAdapterImplTest, RunHttpFirewallRoutineWithNoRemote) {
  TestFuture<network_diagnostics_ipc::RoutineResultPtr> future;
  network_diagnostics_adapter()->RunHttpFirewallRoutine(future.GetCallback());

  auto result = future.Take();
  EXPECT_EQ(result->verdict, network_diagnostics_ipc::RoutineVerdict::kNotRun);
  EXPECT_EQ(result->problems->get_http_firewall_problems().size(), 0);
}

// Test that the HttpsFirewall routine returns RoutineVerdict::kNotRun if a
// valid NetworkDiagnosticsRoutines remote was never sent.
TEST_F(NetworkDiagnosticsAdapterImplTest, RunHttpsFirewallRoutineWithNoRemote) {
  TestFuture<network_diagnostics_ipc::RoutineResultPtr> future;
  network_diagnostics_adapter()->RunHttpsFirewallRoutine(future.GetCallback());

  auto result = future.Take();
  EXPECT_EQ(result->verdict, network_diagnostics_ipc::RoutineVerdict::kNotRun);
  EXPECT_EQ(result->problems->get_https_firewall_problems().size(), 0);
}

// Test that the HttpsLatency routine returns RoutineVerdict::kNotRun if a valid
// NetworkDiagnosticsRoutines remote was never sent.
TEST_F(NetworkDiagnosticsAdapterImplTest, RunHttpsLatencyRoutineWithNoRemote) {
  TestFuture<network_diagnostics_ipc::RoutineResultPtr> future;
  network_diagnostics_adapter()->RunHttpsLatencyRoutine(future.GetCallback());

  auto result = future.Take();
  EXPECT_EQ(result->verdict, network_diagnostics_ipc::RoutineVerdict::kNotRun);
  EXPECT_EQ(result->problems->get_https_latency_problems().size(), 0);
}

// Test that the VideoConferencing routine returns RoutineVerdict::kNotRun if a
// valid NetworkDiagnosticsRoutines remote was never sent.
TEST_F(NetworkDiagnosticsAdapterImplTest,
       RunVideoConferencingRoutineWithNoRemote) {
  TestFuture<network_diagnostics_ipc::RoutineResultPtr> future;
  network_diagnostics_adapter()->RunVideoConferencingRoutine(
      /*stun_server_hostname=*/"http://www.stunserverhostname.com/path?k=v",
      future.GetCallback());

  auto result = future.Take();
  EXPECT_EQ(result->verdict, network_diagnostics_ipc::RoutineVerdict::kNotRun);
  EXPECT_EQ(result->problems->get_video_conferencing_problems().size(), 0);
}

// Test that the ArcHttp routine returns RoutineVerdict::kNotRun if a valid
// NetworkDiagnosticsRoutines remote was never sent.
TEST_F(NetworkDiagnosticsAdapterImplTest, RunArcHttpRoutineWithNoRemote) {
  TestFuture<network_diagnostics_ipc::RoutineResultPtr> future;
  network_diagnostics_adapter()->RunArcHttpRoutine(future.GetCallback());

  auto result = future.Take();
  EXPECT_EQ(result->verdict, network_diagnostics_ipc::RoutineVerdict::kNotRun);
  EXPECT_EQ(result->problems->get_arc_http_problems().size(), 0);
}

// Test that the ArcPing routine returns RoutineVerdict::kNotRun if a valid
// NetworkDiagnosticsRoutines remote was never sent.
TEST_F(NetworkDiagnosticsAdapterImplTest, RunArcPingRoutineWithNoRemote) {
  TestFuture<network_diagnostics_ipc::RoutineResultPtr> future;
  network_diagnostics_adapter()->RunArcPingRoutine(future.GetCallback());

  auto result = future.Take();
  EXPECT_EQ(result->verdict, network_diagnostics_ipc::RoutineVerdict::kNotRun);
  EXPECT_EQ(result->problems->get_arc_ping_problems().size(), 0);
}

// Test that the ArcDnsResolution routine returns RoutineVerdict::kNotRun if a
// valid NetworkDiagnosticsRoutines remote was never sent.
TEST_F(NetworkDiagnosticsAdapterImplTest,
       RunArcDnsResolutionRoutineWithNoRemote) {
  TestFuture<network_diagnostics_ipc::RoutineResultPtr> future;
  network_diagnostics_adapter()->RunArcDnsResolutionRoutine(
      future.GetCallback());

  auto result = future.Take();
  EXPECT_EQ(result->verdict, network_diagnostics_ipc::RoutineVerdict::kNotRun);
  EXPECT_EQ(result->problems->get_arc_dns_resolution_problems().size(), 0);
}

// Test that the correct status of the bound remote is returned on request.
TEST_F(NetworkDiagnosticsAdapterImplTest, RemoteBoundCheck) {
  EXPECT_FALSE(network_diagnostics_adapter()->ServiceRemoteBound());

  MockNetworkDiagnosticsRoutines network_diagnostics_routines;
  network_diagnostics_adapter()->SetNetworkDiagnosticsRoutines(
      network_diagnostics_routines.pending_remote());
  EXPECT_TRUE(network_diagnostics_adapter()->ServiceRemoteBound());
}

}  // namespace
}  // namespace diagnostics

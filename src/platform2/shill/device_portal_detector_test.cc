// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/device.h"

#include <memory>
#include <string>
#include <vector>

#include <base/functional/bind.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "metrics/fake_metrics_library.h"

#include "shill/event_dispatcher.h"
#include "shill/metrics.h"
#include "shill/mock_control.h"
#include "shill/mock_device_info.h"
#include "shill/mock_manager.h"
#include "shill/network/network.h"
#include "shill/portal_detector.h"
#include "shill/service_under_test.h"
#include "shill/technology.h"
#include "shill/test_event_dispatcher.h"
#include "shill/testing.h"

using ::testing::_;
using ::testing::ElementsAre;
using ::testing::Mock;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::ReturnRef;
using ::testing::ReturnRefOfCopy;

// This file contains Device unit tests focused on portal detection and
// integration with the Network class. These tests minimize the use of
// mocks, relying instead on a test Network implementation and a test
// Device implementation to provide the test Network.

// The primary advantage to this pattern, other than increased readability,
// is that it is much easier to test the Device state machine from
// UpdatePortalDetector() through completion, including multiple attempts.
// This will be especially helpful for ensuring that UMA metrics are properly
// measured.

namespace shill {

namespace {

constexpr char kDeviceName[] = "testdevice";
constexpr char kDeviceAddress[] = "00:01:02:03:04:05";
constexpr int kDeviceInterfaceIndex = 1;
constexpr char kRedirectUrl[] = "http://www.redirect.com/signin";
// Portal detection is technology agnostic, use 'unknown'.
constexpr Technology kTestTechnology = Technology::kUnknown;

class TestNetwork : public Network {
 public:
  explicit TestNetwork(Metrics* metrics)
      : Network(kDeviceInterfaceIndex,
                kDeviceName,
                kTestTechnology,
                /*fixed_ip_params=*/false,
                /*control_interface=*/nullptr,
                /*dispatcher=*/nullptr,
                metrics) {}
  ~TestNetwork() override = default;
  TestNetwork(const TestNetwork&) = delete;
  TestNetwork& operator=(const TestNetwork&) = delete;

  // Network overrides
  bool IsConnected() const override { return true; }
  void StartConnectionDiagnostics() override {}

  bool StartPortalDetection(bool reset) override {
    portal_detection_delayed_ = false;
    portal_detection_started_ = true;
    portal_detection_running_ = true;
    portal_detection_num_attempts_++;
    return true;
  }

  bool RestartPortalDetection() override {
    portal_detection_delayed_ = true;
    portal_detection_running_ = false;
    return true;
  }

  void StopPortalDetection() override {
    portal_detection_delayed_ = false;
    portal_detection_started_ = false;
    portal_detection_running_ = false;
    portal_detection_num_attempts_ = 0;
  }

  bool IsPortalDetectionInProgress() const override {
    return portal_detection_started_;
  }

  // Check if a portal detection attempt is currently running.
  // IsPortalDetectionInProgress returns a different result from
  // IsPortalDetectionInProgress when an attempt has completed
  // (Network::EventHandler::OnNetworkValidationResult has been called) and
  // portal detection has not been restarted with
  // Network::RestartPortalDetection().
  bool IsPortalDetectionRunning() const { return portal_detection_running_; }

  void SetDNSResult(PortalDetector::Status status) {
    portal_detection_result_ = PortalDetector::Result();
    portal_detection_result_.http_phase = PortalDetector::Phase::kDNS;
    portal_detection_result_.http_status = status;
    portal_detection_result_.https_phase = PortalDetector::Phase::kDNS;
    portal_detection_result_.https_status = status;
  }

  void SetRedirectResult(const std::string& redirect_url) {
    portal_detection_result_ = PortalDetector::Result();
    portal_detection_result_.http_phase = PortalDetector::Phase::kContent;
    portal_detection_result_.http_status = PortalDetector::Status::kRedirect;
    portal_detection_result_.http_status_code = 302;
    portal_detection_result_.redirect_url_string = redirect_url;
    portal_detection_result_.https_phase = PortalDetector::Phase::kContent;
    portal_detection_result_.https_status = PortalDetector::Status::kSuccess;
  }

  void SetHTTPSFailureResult() {
    portal_detection_result_ = PortalDetector::Result();
    portal_detection_result_.http_phase = PortalDetector::Phase::kContent;
    portal_detection_result_.http_status = PortalDetector::Status::kSuccess;
    portal_detection_result_.http_status_code = 204;
    portal_detection_result_.https_phase = PortalDetector::Phase::kContent;
    portal_detection_result_.https_status = PortalDetector::Status::kFailure;
  }

  void SetOnlineResult() {
    portal_detection_result_ = PortalDetector::Result();
    portal_detection_result_.http_phase = PortalDetector::Phase::kContent;
    portal_detection_result_.http_status = PortalDetector::Status::kSuccess;
    portal_detection_result_.http_status_code = 204;
    portal_detection_result_.https_phase = PortalDetector::Phase::kContent;
    portal_detection_result_.https_status = PortalDetector::Status::kSuccess;
  }

  void ContinuePortalDetection() {
    if (portal_detection_delayed_) {
      portal_detection_running_ = true;
      portal_detection_num_attempts_++;
      portal_detection_delayed_ = false;
    }
  }

  void CompletePortalDetection() {
    if (portal_detection_delayed_) {
      ContinuePortalDetection();
    }
    portal_detection_running_ = false;
    // The callback might delete |this| so copy |portal_detection_result_|.
    PortalDetector::Result result = portal_detection_result_;
    result.num_attempts = portal_detection_num_attempts_;
    OnPortalDetectorResult(result);
  }

  const PortalDetector::Result& portal_detection_result() const {
    return portal_detection_result_;
  }
  int portal_detection_num_attempts() { return portal_detection_num_attempts_; }

 private:
  PortalDetector::Result portal_detection_result_;
  bool portal_detection_started_ = false;
  bool portal_detection_running_ = false;
  bool portal_detection_delayed_ = false;
  int portal_detection_num_attempts_ = 0;
  base::WeakPtrFactory<TestNetwork> test_weak_ptr_factory_{this};
};

class TestDevice : public Device {
 public:
  TestDevice(Manager* manager,
             const std::string& link_name,
             const std::string& address,
             int interface_index,
             Technology technology)
      : Device(manager, link_name, address, interface_index, technology) {}
  ~TestDevice() override = default;

  // Device overrides
  void Start(EnabledStateChangedCallback callback) override {
    std::move(callback).Run(Error(Error::kSuccess));
  }

  void Stop(EnabledStateChangedCallback callback) override {
    std::move(callback).Run(Error(Error::kSuccess));
  }

  TestNetwork* test_network() {
    return static_cast<TestNetwork*>(GetPrimaryNetwork());
  }

 private:
  base::WeakPtrFactory<TestDevice> test_weak_ptr_factory_{this};
};

class TestService : public ServiceUnderTest {
 public:
  explicit TestService(Manager* manager) : ServiceUnderTest(manager) {}
  ~TestService() override = default;

 protected:
  // Service
  void OnConnect(Error* /*error*/) override { SetState(kStateConnected); }

  void OnDisconnect(Error* /*error*/, const char* /*reason*/) override {
    SetState(kStateIdle);
  }
};

}  // namespace

class DevicePortalDetectorTest : public testing::Test {
 public:
  DevicePortalDetectorTest()
      : manager_(&control_interface_, &dispatcher_, &metrics_),
        device_info_(&manager_) {
    metrics_.SetLibraryForTesting(&fake_metrics_library_);
    manager_.set_mock_device_info(&device_info_);
    device_ = new TestDevice(&manager_, kDeviceName, kDeviceAddress,
                             kDeviceInterfaceIndex, kTestTechnology);
  }

  ~DevicePortalDetectorTest() override = default;

  void SetUp() override {
    device_->set_network_for_testing(std::make_unique<TestNetwork>(&metrics_));
    device_->GetPrimaryNetwork()->RegisterEventHandler(device_.get());
    // Set up a connected test Service for the Device.
    service_ = new TestService(&manager_);
    service_->SetState(Service::kStateConnected);
    SetServiceCheckPortal(true);
    device_->SelectService(service_);
  }

  void UpdatePortalDetector(bool restart = true) {
    device_->UpdatePortalDetector(restart);
  }

  TestNetwork* GetTestNetwork() { return device_->test_network(); }

  void SetServiceCheckPortal(bool check_portal) {
    service_->SetCheckPortal(
        check_portal ? Service::kCheckPortalTrue : Service::kCheckPortalFalse,
        /*error=*/nullptr);
  }

  std::string GetServiceProbeUrlString() { return service_->probe_url_string_; }

  int NumHistogramCalls(
      const Metrics::HistogramMetric<Metrics::NameByTechnology>& metric) {
    return fake_metrics_library_.NumCalls(Metrics::GetFullMetricName(
        metric.n.name, kTestTechnology, metric.n.location));
  }

  int NumEnumMetricsCalls(
      const Metrics::EnumMetric<Metrics::NameByTechnology>& metric) {
    return fake_metrics_library_.NumCalls(Metrics::GetFullMetricName(
        metric.n.name, kTestTechnology, metric.n.location));
  }

  std::vector<int> MetricsHistogramCalls(
      const Metrics::HistogramMetric<Metrics::NameByTechnology>& metric) {
    return fake_metrics_library_.GetCalls(Metrics::GetFullMetricName(
        metric.n.name, kTestTechnology, metric.n.location));
  }

  std::vector<int> MetricsEnumCalls(
      const Metrics::EnumMetric<Metrics::NameByTechnology>& metric) {
    return fake_metrics_library_.GetCalls(Metrics::GetFullMetricName(
        metric.n.name, kTestTechnology, metric.n.location));
  }

 protected:
  NiceMock<MockControl> control_interface_;
  EventDispatcherForTest dispatcher_;
  Metrics metrics_;
  FakeMetricsLibrary fake_metrics_library_;
  NiceMock<MockManager> manager_;
  NiceMock<MockDeviceInfo> device_info_;
  scoped_refptr<TestDevice> device_;
  scoped_refptr<TestService> service_;
};

TEST_F(DevicePortalDetectorTest, DNSFailure) {
  auto test_network = GetTestNetwork();

  UpdatePortalDetector();
  EXPECT_TRUE(device_->GetPrimaryNetwork()->IsPortalDetectionInProgress());

  test_network->SetDNSResult(PortalDetector::Status::kFailure);
  test_network->CompletePortalDetection();
  EXPECT_EQ(service_->state(), Service::kStateNoConnectivity);

  EXPECT_THAT(MetricsEnumCalls(Metrics::kMetricPortalResult),
              ElementsAre(Metrics::kPortalResultDNSFailure));
  EXPECT_THAT(MetricsEnumCalls(Metrics::kPortalDetectorInitialResult),
              ElementsAre(Metrics::kPortalDetectorResultDNSFailure));
  EXPECT_EQ(NumEnumMetricsCalls(Metrics::kPortalDetectorRetryResult), 0);

  EXPECT_EQ(NumHistogramCalls(Metrics::kPortalDetectorAttemptsToOnline), 0);
  EXPECT_EQ(NumHistogramCalls(Metrics::kPortalDetectorAttemptsToDisconnect), 0);

  // Portal detection should be started again.
  EXPECT_TRUE(test_network->IsPortalDetectionInProgress());
  EXPECT_FALSE(test_network->IsPortalDetectionRunning());
  test_network->ContinuePortalDetection();
  EXPECT_TRUE(test_network->IsPortalDetectionInProgress());
  EXPECT_TRUE(test_network->IsPortalDetectionRunning());
  EXPECT_EQ(test_network->portal_detection_num_attempts(), 2);
}

TEST_F(DevicePortalDetectorTest, DNSTimeout) {
  auto test_network = GetTestNetwork();

  UpdatePortalDetector();
  EXPECT_TRUE(device_->GetPrimaryNetwork()->IsPortalDetectionInProgress());

  test_network->SetDNSResult(PortalDetector::Status::kTimeout);
  test_network->CompletePortalDetection();
  EXPECT_EQ(service_->state(), Service::kStateNoConnectivity);

  EXPECT_THAT(MetricsEnumCalls(Metrics::kMetricPortalResult),
              ElementsAre(Metrics::kPortalResultDNSTimeout));
  EXPECT_THAT(MetricsEnumCalls(Metrics::kPortalDetectorInitialResult),
              ElementsAre(Metrics::kPortalDetectorResultDNSTimeout));
  EXPECT_EQ(NumEnumMetricsCalls(Metrics::kPortalDetectorRetryResult), 0);

  EXPECT_EQ(NumHistogramCalls(Metrics::kPortalDetectorAttemptsToOnline), 0);
  EXPECT_EQ(NumHistogramCalls(Metrics::kPortalDetectorAttemptsToDisconnect), 0);

  // Portal detection should still be active.
  EXPECT_TRUE(test_network->IsPortalDetectionInProgress());
  EXPECT_FALSE(test_network->IsPortalDetectionRunning());
}

TEST_F(DevicePortalDetectorTest, RedirectFound) {
  auto test_network = GetTestNetwork();

  UpdatePortalDetector();
  EXPECT_TRUE(device_->GetPrimaryNetwork()->IsPortalDetectionInProgress());

  test_network->SetRedirectResult(kRedirectUrl);
  test_network->CompletePortalDetection();
  EXPECT_EQ(service_->state(), Service::kStateRedirectFound);
  EXPECT_EQ(GetServiceProbeUrlString(),
            test_network->portal_detection_result().probe_url_string);

  EXPECT_THAT(MetricsEnumCalls(Metrics::kMetricPortalResult),
              ElementsAre(Metrics::kPortalResultContentRedirect));
  EXPECT_THAT(MetricsEnumCalls(Metrics::kPortalDetectorInitialResult),
              ElementsAre(Metrics::kPortalDetectorResultRedirectFound));
  EXPECT_EQ(NumEnumMetricsCalls(Metrics::kPortalDetectorRetryResult), 0);

  EXPECT_EQ(NumHistogramCalls(Metrics::kPortalDetectorAttemptsToOnline), 0);
  EXPECT_THAT(
      MetricsHistogramCalls(Metrics::kPortalDetectorAttemptsToRedirectFound),
      ElementsAre(1));
  EXPECT_EQ(NumHistogramCalls(Metrics::kPortalDetectorAttemptsToDisconnect), 0);

  // Portal detection should still be active.
  EXPECT_TRUE(test_network->IsPortalDetectionInProgress());
  EXPECT_FALSE(test_network->IsPortalDetectionRunning());
}

TEST_F(DevicePortalDetectorTest, RedirectFoundNoUrl) {
  auto test_network = GetTestNetwork();

  UpdatePortalDetector();
  EXPECT_TRUE(device_->GetPrimaryNetwork()->IsPortalDetectionInProgress());

  // Redirect result with an empty redirect URL -> PortalSuspected state.
  test_network->SetRedirectResult("");
  test_network->CompletePortalDetection();
  EXPECT_EQ(service_->state(), Service::kStatePortalSuspected);

  EXPECT_THAT(MetricsEnumCalls(Metrics::kMetricPortalResult),
              ElementsAre(Metrics::kPortalResultContentRedirect));
  EXPECT_THAT(MetricsEnumCalls(Metrics::kPortalDetectorInitialResult),
              ElementsAre(Metrics::kPortalDetectorResultRedirectNoUrl));
  EXPECT_EQ(NumEnumMetricsCalls(Metrics::kPortalDetectorRetryResult), 0);

  EXPECT_EQ(NumHistogramCalls(Metrics::kPortalDetectorAttemptsToOnline), 0);
  EXPECT_EQ(NumHistogramCalls(Metrics::kPortalDetectorAttemptsToDisconnect), 0);
  EXPECT_EQ(NumHistogramCalls(Metrics::kPortalDetectorAttemptsToRedirectFound),
            0);

  // Portal detection should still be active.
  EXPECT_TRUE(test_network->IsPortalDetectionInProgress());
  EXPECT_FALSE(test_network->IsPortalDetectionRunning());
}

TEST_F(DevicePortalDetectorTest, RedirectFoundThenOnline) {
  auto test_network = GetTestNetwork();

  UpdatePortalDetector();
  EXPECT_TRUE(device_->GetPrimaryNetwork()->IsPortalDetectionInProgress());

  test_network->SetRedirectResult(kRedirectUrl);
  test_network->CompletePortalDetection();
  EXPECT_EQ(service_->state(), Service::kStateRedirectFound);

  // Portal detection should be started again.
  test_network->ContinuePortalDetection();
  EXPECT_EQ(test_network->portal_detection_num_attempts(), 2);

  // Completion with an 'online' result should set the Service state to online.
  test_network->SetOnlineResult();
  test_network->CompletePortalDetection();
  EXPECT_EQ(service_->state(), Service::kStateOnline);

  EXPECT_THAT(MetricsEnumCalls(Metrics::kMetricPortalResult),
              ElementsAre(Metrics::kPortalResultContentRedirect,
                          Metrics::kPortalResultSuccess));
  EXPECT_EQ(NumHistogramCalls(Metrics::kPortalDetectorAttemptsToDisconnect), 0);

  // Portal detection should be completed.
  EXPECT_FALSE(test_network->IsPortalDetectionInProgress());
  EXPECT_FALSE(test_network->IsPortalDetectionRunning());
}

TEST_F(DevicePortalDetectorTest, PortalSuspected) {
  auto test_network = GetTestNetwork();

  UpdatePortalDetector();
  EXPECT_TRUE(device_->GetPrimaryNetwork()->IsPortalDetectionInProgress());

  test_network->SetHTTPSFailureResult();
  test_network->CompletePortalDetection();
  EXPECT_EQ(service_->state(), Service::kStatePortalSuspected);

  // NOTE: Since we only report on the HTTP phase, a portal-suspected result
  // reports 'success'. This will be addressed when the metrics are updated.
  EXPECT_THAT(MetricsEnumCalls(Metrics::kMetricPortalResult),
              ElementsAre(Metrics::kPortalResultSuccess));
  EXPECT_THAT(MetricsEnumCalls(Metrics::kPortalDetectorInitialResult),
              ElementsAre(Metrics::kPortalDetectorResultHTTPSFailure));
  EXPECT_EQ(NumEnumMetricsCalls(Metrics::kPortalDetectorRetryResult), 0);

  EXPECT_EQ(NumHistogramCalls(Metrics::kPortalDetectorAttemptsToOnline), 0);
  EXPECT_EQ(NumHistogramCalls(Metrics::kPortalDetectorAttemptsToDisconnect), 0);
  EXPECT_EQ(NumHistogramCalls(Metrics::kPortalDetectorAttemptsToRedirectFound),
            0);

  // Portal detection should still be active.
  EXPECT_TRUE(test_network->IsPortalDetectionInProgress());
  EXPECT_FALSE(test_network->IsPortalDetectionRunning());
}

TEST_F(DevicePortalDetectorTest, PortalSuspectedThenRedirectFound) {
  auto test_network = GetTestNetwork();

  UpdatePortalDetector();
  EXPECT_TRUE(device_->GetPrimaryNetwork()->IsPortalDetectionInProgress());

  // Multiple portal-suspected results.
  test_network->SetHTTPSFailureResult();
  test_network->CompletePortalDetection();
  test_network->CompletePortalDetection();
  EXPECT_EQ(service_->state(), Service::kStatePortalSuspected);
  EXPECT_THAT(MetricsEnumCalls(Metrics::kMetricPortalResult),
              ElementsAre(Metrics::kPortalResultSuccess,
                          Metrics::kPortalResultSuccess));
  EXPECT_THAT(MetricsEnumCalls(Metrics::kPortalDetectorInitialResult),
              ElementsAre(Metrics::kPortalDetectorResultHTTPSFailure));
  EXPECT_THAT(MetricsEnumCalls(Metrics::kPortalDetectorRetryResult),
              ElementsAre(Metrics::kPortalDetectorResultHTTPSFailure));

  // Portal detection should be started again.
  EXPECT_TRUE(test_network->IsPortalDetectionInProgress());
  EXPECT_FALSE(test_network->IsPortalDetectionRunning());
  test_network->ContinuePortalDetection();
  EXPECT_TRUE(test_network->IsPortalDetectionInProgress());
  EXPECT_TRUE(test_network->IsPortalDetectionRunning());
  EXPECT_EQ(test_network->portal_detection_num_attempts(), 3);

  // Completion with a 'redirect-found' result should set the Service state
  // to redirect-found and record the number of attempts..
  test_network->SetRedirectResult(kRedirectUrl);
  test_network->CompletePortalDetection();
  EXPECT_EQ(service_->state(), Service::kStateRedirectFound);

  EXPECT_THAT(
      MetricsEnumCalls(Metrics::kMetricPortalResult),
      ElementsAre(Metrics::kPortalResultSuccess, Metrics::kPortalResultSuccess,
                  Metrics::kPortalResultContentRedirect));
  EXPECT_THAT(MetricsEnumCalls(Metrics::kPortalDetectorInitialResult),
              ElementsAre(Metrics::kPortalDetectorResultHTTPSFailure));
  EXPECT_THAT(MetricsEnumCalls(Metrics::kPortalDetectorRetryResult),
              ElementsAre(Metrics::kPortalDetectorResultHTTPSFailure,
                          Metrics::kPortalDetectorResultRedirectFound));

  EXPECT_EQ(NumHistogramCalls(Metrics::kPortalDetectorAttemptsToOnline), 0);
  EXPECT_EQ(NumHistogramCalls(Metrics::kPortalDetectorAttemptsToDisconnect), 0);
  EXPECT_THAT(
      MetricsHistogramCalls(Metrics::kPortalDetectorAttemptsToRedirectFound),
      ElementsAre(3));

  // Portal detection should be started again.
  test_network->ContinuePortalDetection();
  EXPECT_EQ(test_network->portal_detection_num_attempts(), 4);
}

TEST_F(DevicePortalDetectorTest, PortalSuspectedThenOnline) {
  auto test_network = GetTestNetwork();

  UpdatePortalDetector();
  EXPECT_TRUE(device_->GetPrimaryNetwork()->IsPortalDetectionInProgress());

  test_network->SetHTTPSFailureResult();
  test_network->CompletePortalDetection();
  EXPECT_EQ(service_->state(), Service::kStatePortalSuspected);

  // Portal detection should be started again.
  test_network->ContinuePortalDetection();
  EXPECT_EQ(test_network->portal_detection_num_attempts(), 2);

  // Completion with an 'online' result should set the Service state to online.
  test_network->SetOnlineResult();
  test_network->CompletePortalDetection();
  EXPECT_EQ(service_->state(), Service::kStateOnline);

  // NOTE: Since we only report on the HTTP phase, a portal-suspected result
  // reports 'success'. This will be addressed when the metrics are updated.
  EXPECT_THAT(MetricsEnumCalls(Metrics::kMetricPortalResult),
              ElementsAre(Metrics::kPortalResultSuccess,
                          Metrics::kPortalResultSuccess));
  EXPECT_THAT(MetricsEnumCalls(Metrics::kPortalDetectorInitialResult),
              ElementsAre(Metrics::kPortalDetectorResultHTTPSFailure));
  EXPECT_THAT(MetricsEnumCalls(Metrics::kPortalDetectorRetryResult),
              ElementsAre(Metrics::kPortalDetectorResultOnline));

  EXPECT_THAT(MetricsHistogramCalls(Metrics::kPortalDetectorAttemptsToOnline),
              ElementsAre(2));
  EXPECT_EQ(NumHistogramCalls(Metrics::kPortalDetectorAttemptsToDisconnect), 0);

  // Portal detection should be completed.
  EXPECT_FALSE(test_network->IsPortalDetectionInProgress());
  EXPECT_FALSE(test_network->IsPortalDetectionRunning());
}

TEST_F(DevicePortalDetectorTest, PortalSuspectedThenDisconnect) {
  auto test_network = GetTestNetwork();

  UpdatePortalDetector();
  EXPECT_TRUE(device_->GetPrimaryNetwork()->IsPortalDetectionInProgress());

  // Multiple portal-suspected results
  test_network->SetHTTPSFailureResult();
  test_network->CompletePortalDetection();
  test_network->CompletePortalDetection();
  EXPECT_EQ(service_->state(), Service::kStatePortalSuspected);

  // Portal detection should be started again.
  test_network->ContinuePortalDetection();
  EXPECT_EQ(test_network->portal_detection_num_attempts(), 3);

  // Disconnect should not record an UMA result.
  service_->Disconnect(nullptr, "test");
  test_network->CompletePortalDetection();
  EXPECT_EQ(service_->state(), Service::kStateIdle);

  EXPECT_THAT(
      MetricsEnumCalls(Metrics::kMetricPortalResult),
      ElementsAre(Metrics::kPortalResultSuccess, Metrics::kPortalResultSuccess,
                  Metrics::kPortalResultSuccess));
  EXPECT_THAT(MetricsEnumCalls(Metrics::kPortalDetectorInitialResult),
              ElementsAre(Metrics::kPortalDetectorResultHTTPSFailure));
  EXPECT_THAT(MetricsEnumCalls(Metrics::kPortalDetectorRetryResult),
              ElementsAre(Metrics::kPortalDetectorResultHTTPSFailure));

  EXPECT_EQ(NumHistogramCalls(Metrics::kPortalDetectorAttemptsToOnline), 0);

  // Histogram records the number of failed attempts *before* a disconnect.
  EXPECT_THAT(
      MetricsHistogramCalls(Metrics::kPortalDetectorAttemptsToDisconnect),
      ElementsAre(2));
}

TEST_F(DevicePortalDetectorTest, Online) {
  auto test_network = GetTestNetwork();

  UpdatePortalDetector();
  EXPECT_TRUE(device_->GetPrimaryNetwork()->IsPortalDetectionInProgress());

  test_network->SetOnlineResult();
  test_network->CompletePortalDetection();
  EXPECT_EQ(service_->state(), Service::kStateOnline);

  EXPECT_THAT(MetricsEnumCalls(Metrics::kMetricPortalResult),
              ElementsAre(Metrics::kPortalResultSuccess));
  EXPECT_THAT(MetricsEnumCalls(Metrics::kPortalDetectorInitialResult),
              ElementsAre(Metrics::kPortalDetectorResultOnline));
  EXPECT_EQ(NumEnumMetricsCalls(Metrics::kPortalDetectorRetryResult), 0);

  EXPECT_THAT(MetricsHistogramCalls(Metrics::kPortalDetectorAttemptsToOnline),
              ElementsAre(1));
  EXPECT_EQ(NumHistogramCalls(Metrics::kPortalDetectorAttemptsToDisconnect), 0);

  // Portal detection should be completed.
  EXPECT_FALSE(test_network->IsPortalDetectionInProgress());
  EXPECT_FALSE(test_network->IsPortalDetectionRunning());
}

TEST_F(DevicePortalDetectorTest, RestartPortalDetection) {
  auto test_network = GetTestNetwork();

  UpdatePortalDetector();
  EXPECT_TRUE(device_->GetPrimaryNetwork()->IsPortalDetectionInProgress());

  // Run portal detection 3 times.
  test_network->SetHTTPSFailureResult();
  test_network->CompletePortalDetection();
  test_network->CompletePortalDetection();
  test_network->CompletePortalDetection();
  EXPECT_EQ(service_->state(), Service::kStatePortalSuspected);

  // Portal detection should be started again.
  test_network->ContinuePortalDetection();
  EXPECT_TRUE(test_network->IsPortalDetectionInProgress());

  // UpdatePortalDetector(true) will reset the current portal detector and
  // start a new one.
  device_->UpdatePortalDetector(true);
  EXPECT_TRUE(test_network->IsPortalDetectionInProgress());

  // CompletePortalDetection will run portal detection 1 more time with an
  // 'online' result.
  test_network->SetOnlineResult();
  test_network->CompletePortalDetection();
  EXPECT_EQ(service_->state(), Service::kStateOnline);

  // Old result metric gets called 4 times, with a final result of 'online'.
  // NOTE: Since we only report on the HTTP phase, a portal-suspected result
  // reports 'success'. This will be addressed when the metrics are updated.
  EXPECT_THAT(
      MetricsEnumCalls(Metrics::kMetricPortalResult),
      ElementsAre(Metrics::kPortalResultSuccess, Metrics::kPortalResultSuccess,
                  Metrics::kPortalResultSuccess,
                  Metrics::kPortalResultSuccess));
  // New initial result metric gets called once with an HTTPS failure.
  EXPECT_THAT(MetricsEnumCalls(Metrics::kPortalDetectorInitialResult),
              ElementsAre(Metrics::kPortalDetectorResultHTTPSFailure));
  // New retry result metric gets called three times, ending with 'online'
  EXPECT_THAT(MetricsEnumCalls(Metrics::kPortalDetectorRetryResult),
              ElementsAre(Metrics::kPortalDetectorResultHTTPSFailure,
                          Metrics::kPortalDetectorResultHTTPSFailure,
                          Metrics::kPortalDetectorResultOnline));

  // New attempts-to-online metric gets called once with a value of 3+1 = 4.
  EXPECT_THAT(MetricsHistogramCalls(Metrics::kPortalDetectorAttemptsToOnline),
              ElementsAre(4));

  // Portal detection should be completed.
  EXPECT_FALSE(test_network->IsPortalDetectionInProgress());
  EXPECT_FALSE(test_network->IsPortalDetectionRunning());
}

}  // namespace shill

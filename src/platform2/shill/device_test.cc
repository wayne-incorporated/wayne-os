// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/device.h"

#include <ctype.h>
#include <linux/if.h>  // NOLINT - Needs typedefs from sys/socket.h.
#include <sys/socket.h>

#include <algorithm>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/test/test_future.h>
#include <chromeos/dbus/service_constants.h>
#include <chromeos/patchpanel/dbus/fake_client.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "shill/event_dispatcher.h"
#include "shill/mock_adaptors.h"
#include "shill/mock_control.h"
#include "shill/mock_device.h"
#include "shill/mock_device_info.h"
#include "shill/mock_event_dispatcher.h"
#include "shill/mock_ipconfig.h"
#include "shill/mock_manager.h"
#include "shill/mock_metrics.h"
#include "shill/mock_service.h"
#include "shill/net/mock_rtnl_handler.h"
#include "shill/net/mock_time.h"
#include "shill/net/ndisc.h"
#include "shill/network/mock_network.h"
#include "shill/network/network.h"
#include "shill/portal_detector.h"
#include "shill/routing_table.h"
#include "shill/store/fake_store.h"
#include "shill/technology.h"
#include "shill/test_event_dispatcher.h"
#include "shill/testing.h"
#include "shill/tethering.h"

using ::testing::_;
using ::testing::AnyNumber;
using ::testing::AtLeast;
using ::testing::DoAll;
using ::testing::HasSubstr;
using ::testing::Invoke;
using ::testing::InvokeWithoutArgs;
using ::testing::Mock;
using ::testing::NiceMock;
using ::testing::Ref;
using ::testing::Return;
using ::testing::ReturnRef;
using ::testing::SetArgPointee;
using ::testing::StrEq;
using ::testing::StrictMock;

namespace shill {

namespace {
MATCHER_P(IsWeakPtrTo, address, "") {
  return arg.get() == address;
}
}  // namespace

class TestDevice : public Device {
 public:
  TestDevice(Manager* manager,
             const std::string& link_name,
             const std::string& address,
             int interface_index,
             Technology technology)
      : Device(manager, link_name, address, interface_index, technology),
        start_stop_error_(Error::kSuccess) {
    ON_CALL(*this, ShouldBringNetworkInterfaceDownAfterDisabled())
        .WillByDefault(Invoke(
            this,
            &TestDevice::DeviceShouldBringNetworkInterfaceDownAfterDisabled));
  }

  ~TestDevice() override = default;

  void Start(EnabledStateChangedCallback callback) override {
    std::move(callback).Run(start_stop_error_);
  }

  void Stop(EnabledStateChangedCallback callback) override {
    std::move(callback).Run(start_stop_error_);
  }

  MOCK_METHOD(bool,
              ShouldBringNetworkInterfaceDownAfterDisabled,
              (),
              (const, override));

  bool DeviceShouldBringNetworkInterfaceDownAfterDisabled() const {
    return Device::ShouldBringNetworkInterfaceDownAfterDisabled();
  }

  void device_set_mac_address(const std::string& mac_address) {
    Device::set_mac_address(mac_address);
  }

  Error start_stop_error_;
};

class DeviceTest : public testing::Test {
 public:
  DeviceTest()
      : manager_(control_interface(), dispatcher(), metrics()),
        device_info_(manager()) {
    manager()->set_mock_device_info(&device_info_);
    DHCPProvider::GetInstance()->control_interface_ = control_interface();
    DHCPProvider::GetInstance()->dispatcher_ = dispatcher();

    auto client = std::make_unique<patchpanel::FakeClient>();
    patchpanel_client_ = client.get();
    manager_.patchpanel_client_ = std::move(client);

    device_ =
        new NiceMock<TestDevice>(manager(), kDeviceName, kDeviceAddress,
                                 kDeviceInterfaceIndex, Technology::kUnknown);

    auto network = std::make_unique<NiceMock<MockNetwork>>(
        kDeviceInterfaceIndex, kDeviceName, Technology::kUnknown);
    network_ = network.get();
    device_->set_network_for_testing(std::move(network));
  }
  ~DeviceTest() override = default;

  void SetUp() override {
    device_->rtnl_handler_ = &rtnl_handler_;
    RoutingTable::GetInstance()->Start();
  }

 protected:
  static const char kDeviceName[];
  static const char kDeviceAddress[];
  static const int kDeviceInterfaceIndex;
  static const int kOtherInterfaceIndex;

  void OnIPv4ConfigUpdated() {
    device_->GetPrimaryNetwork()->OnIPv4ConfigUpdated();
  }

  void OnDHCPFailure() {
    device_->GetPrimaryNetwork()->OnDHCPDrop(/*is_voluntary=*/false);
  }

  patchpanel::Client::TrafficCounter CreateCounter(
      const std::valarray<uint64_t>& vals,
      patchpanel::Client::TrafficSource source,
      const std::string& ifname) {
    EXPECT_EQ(4, vals.size());
    patchpanel::Client::TrafficCounter counter;
    counter.rx_bytes = vals[0];
    counter.tx_bytes = vals[1];
    counter.rx_packets = vals[2];
    counter.tx_packets = vals[3];
    counter.source = source;
    counter.ifname = ifname;
    return counter;
  }

  void SelectService(scoped_refptr<MockService> service) {
    if (service) {
      EXPECT_CALL(*service, SetAttachedNetwork(
                                IsWeakPtrTo(device_->GetPrimaryNetwork())));
    }
    device_->SelectService(service);
  }

  DeviceMockAdaptor* GetDeviceMockAdaptor() {
    return static_cast<DeviceMockAdaptor*>(device_->adaptor_.get());
  }

  MockControl* control_interface() { return &control_interface_; }
  EventDispatcher* dispatcher() { return &dispatcher_; }
  MockMetrics* metrics() { return &metrics_; }
  MockManager* manager() { return &manager_; }

  void TriggerConnectionUpdate() {
    EXPECT_CALL(*network_, IsConnected()).WillRepeatedly(Return(true));
    network_->set_ipconfig(
        std::make_unique<MockIPConfig>(control_interface(), kDeviceName));
    device_->OnConnectionUpdated(device_->interface_index());
    device_->OnIPConfigsPropertyUpdated(device_->interface_index());
  }

  NiceMock<MockControl> control_interface_;
  EventDispatcherForTest dispatcher_;
  NiceMock<MockMetrics> metrics_;
  NiceMock<MockManager> manager_;

  scoped_refptr<TestDevice> device_;
  NiceMock<MockDeviceInfo> device_info_;
  StrictMock<MockRTNLHandler> rtnl_handler_;
  patchpanel::FakeClient* patchpanel_client_;
  MockNetwork* network_;  // owned by |device_|
};

const char DeviceTest::kDeviceName[] = "testdevice";
const char DeviceTest::kDeviceAddress[] = "address";
const int DeviceTest::kDeviceInterfaceIndex = 0;
const int DeviceTest::kOtherInterfaceIndex = 255;

TEST_F(DeviceTest, Contains) {
  EXPECT_TRUE(device_->store().Contains(kNameProperty));
  EXPECT_FALSE(device_->store().Contains(""));
}

TEST_F(DeviceTest, GetProperties) {
  brillo::VariantDictionary props;
  Error error;
  device_->store().GetProperties(&props, &error);
  ASSERT_FALSE(props.find(kNameProperty) == props.end());
  EXPECT_TRUE(props[kNameProperty].IsTypeCompatible<std::string>());
  EXPECT_EQ(props[kNameProperty].Get<std::string>(), std::string(kDeviceName));
}

// Note: there are currently no writeable Device properties that
// aren't registered in a subclass.
TEST_F(DeviceTest, SetReadOnlyProperty) {
  Error error;
  // Ensure that an attempt to write a R/O property returns InvalidArgs error.
  device_->mutable_store()->SetAnyProperty(kAddressProperty,
                                           brillo::Any(std::string()), &error);
  EXPECT_EQ(Error::kInvalidArguments, error.type());
}

TEST_F(DeviceTest, ClearReadOnlyProperty) {
  Error error;
  device_->mutable_store()->SetAnyProperty(kAddressProperty,
                                           brillo::Any(std::string()), &error);
  EXPECT_EQ(Error::kInvalidArguments, error.type());
}

TEST_F(DeviceTest, ClearReadOnlyDerivedProperty) {
  Error error;
  device_->mutable_store()->SetAnyProperty(kIPConfigsProperty,
                                           brillo::Any(Strings()), &error);
  EXPECT_EQ(Error::kInvalidArguments, error.type());
}

TEST_F(DeviceTest, Load) {
  device_->enabled_persistent_ = false;

  FakeStore storage;
  const auto id = device_->GetStorageIdentifier();
  storage.SetBool(id, Device::kStoragePowered, true);
  EXPECT_TRUE(device_->Load(&storage));
  EXPECT_TRUE(device_->enabled_persistent());
}

TEST_F(DeviceTest, Save) {
  device_->enabled_persistent_ = true;

  FakeStore storage;
  EXPECT_TRUE(device_->Save(&storage));
  const auto id = device_->GetStorageIdentifier();
  bool powered = false;
  EXPECT_TRUE(storage.GetBool(id, Device::kStoragePowered, &powered));
  EXPECT_TRUE(powered);
}

TEST_F(DeviceTest, SelectedService) {
  EXPECT_EQ(nullptr, device_->selected_service_);
  device_->SetServiceState(Service::kStateAssociating);
  scoped_refptr<MockService> service(new StrictMock<MockService>(manager()));
  SelectService(service);
  EXPECT_EQ(device_->selected_service_, service);

  EXPECT_CALL(*service, SetState(Service::kStateConfiguring));
  device_->SetServiceState(Service::kStateConfiguring);
  EXPECT_CALL(*service, SetFailure(Service::kFailureOutOfRange));
  device_->SetServiceFailure(Service::kFailureOutOfRange);

  // Service should be returned to "Idle" state
  EXPECT_CALL(*service, state()).WillOnce(Return(Service::kStateUnknown));
  EXPECT_CALL(*service, SetState(Service::kStateIdle));
  EXPECT_CALL(*service, SetAttachedNetwork(IsWeakPtrTo(nullptr)));
  SelectService(nullptr);

  // A service in the "Failure" state should not be reset to "Idle"
  SelectService(service);
  EXPECT_CALL(*service, state()).WillOnce(Return(Service::kStateFailure));
  EXPECT_CALL(*service, SetAttachedNetwork(IsWeakPtrTo(nullptr)));
  SelectService(nullptr);
}

TEST_F(DeviceTest, NetworkFailure) {
  scoped_refptr<MockService> service(new StrictMock<MockService>(manager()));
  SelectService(service);
  EXPECT_CALL(*service, DisconnectWithFailure(Service::kFailureDHCP, _,
                                              HasSubstr("OnIPConfigFailure")));
  device_->OnNetworkStopped(device_->interface_index(), /*is_failure=*/true);
}

TEST_F(DeviceTest, ConnectionUpdated) {
  scoped_refptr<MockService> service(new StrictMock<MockService>(manager()));
  SelectService(service);
  EXPECT_CALL(*service, IsConnected(nullptr))
      .WillOnce(Return(false))
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*service, IsPortalDetectionDisabled())
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*service, SetState(Service::kStateConnected));
  EXPECT_CALL(*service, SetState(Service::kStateOnline));
  EXPECT_CALL(*GetDeviceMockAdaptor(),
              EmitRpcIdentifierArrayChanged(
                  kIPConfigsProperty,
                  std::vector<RpcIdentifier>{IPConfigMockAdaptor::kRpcId}));

  TriggerConnectionUpdate();
}

TEST_F(DeviceTest, ConnectionUpdatedAlreadyOnline) {
  // The service is already Online and selected, so it should not transition
  // back to Connected.
  scoped_refptr<MockService> service(new StrictMock<MockService>(manager()));
  SelectService(service);
  EXPECT_CALL(*service, SetState(Service::kStateConnected)).Times(0);
  EXPECT_CALL(*service, IsConnected(nullptr)).WillRepeatedly(Return(true));
  EXPECT_CALL(*service, IsPortalDetectionDisabled())
      .WillRepeatedly(Return(true));

  // Successful portal (non-)detection forces the service Online.
  EXPECT_CALL(*service, SetState(Service::kStateOnline));
  EXPECT_CALL(*GetDeviceMockAdaptor(),
              EmitRpcIdentifierArrayChanged(
                  kIPConfigsProperty,
                  std::vector<RpcIdentifier>{IPConfigMockAdaptor::kRpcId}));

  TriggerConnectionUpdate();
}

TEST_F(DeviceTest, ConnectionUpdatedSuccessNoSelectedService) {
  // Make sure shill doesn't crash if a service is disabled immediately after
  // Network is connected (selected_service_ is nullptr in this case).
  SelectService(nullptr);
  TriggerConnectionUpdate();
}

TEST_F(DeviceTest, NetworkFailureOtherInterface) {
  scoped_refptr<MockService> service(new StrictMock<MockService>(manager()));
  SelectService(service);
  EXPECT_CALL(*service, IsConnected(_)).Times(0);
  EXPECT_CALL(*service, DisconnectWithFailure(_, _, _)).Times(0);
  device_->OnNetworkStopped(kOtherInterfaceIndex, /*is_failure=*/true);
}

TEST_F(DeviceTest, ConnectionUpdatedOtherInterface) {
  scoped_refptr<MockService> service(new StrictMock<MockService>(manager()));
  SelectService(service);
  EXPECT_CALL(*service, IsConnected(_)).Times(0);
  EXPECT_CALL(*service, SetState(_)).Times(0);
  device_->OnConnectionUpdated(kOtherInterfaceIndex);
}

TEST_F(DeviceTest, IPConfigsPropertyUpdatedOtherInterface) {
  scoped_refptr<MockService> service(new StrictMock<MockService>(manager()));
  SelectService(service);
  EXPECT_CALL(*service, IsConnected(_)).Times(0);
  EXPECT_CALL(*GetDeviceMockAdaptor(), EmitRpcIdentifierArrayChanged(_, _))
      .Times(0);
  device_->OnIPConfigsPropertyUpdated(kOtherInterfaceIndex);
}

// Successful cases are tested in the DevicePortalDetectionTest suite.
TEST_F(DeviceTest, OnNetworkValidationResultOtherInterface) {
  scoped_refptr<MockService> service(new StrictMock<MockService>(manager()));
  SelectService(service);
  EXPECT_CALL(*service, IsConnected(_)).Times(0);
  EXPECT_CALL(*service, SetState(_)).Times(0);
  device_->OnNetworkValidationResult(kOtherInterfaceIndex,
                                     PortalDetector::Result{});
}

TEST_F(DeviceTest, SetEnabledNonPersistent) {
  EXPECT_FALSE(device_->enabled_);
  EXPECT_FALSE(device_->enabled_pending_);
  device_->enabled_persistent_ = false;
  Error error;
  SetEnabledSync(device_.get(), true, false, &error);
  EXPECT_FALSE(device_->enabled_persistent_);
  EXPECT_TRUE(device_->enabled_pending_);

  // Enable while already enabled.
  device_->enabled_persistent_ = false;
  device_->enabled_pending_ = true;
  device_->enabled_ = true;
  SetEnabledSync(device_.get(), true, false, &error);
  EXPECT_FALSE(device_->enabled_persistent_);
  EXPECT_TRUE(device_->enabled_pending_);
  EXPECT_TRUE(device_->enabled_);
  EXPECT_TRUE(error.IsSuccess());

  // Enable while enabled but disabling.
  device_->enabled_pending_ = false;
  SetEnabledSync(device_.get(), true, false, &error);
  EXPECT_FALSE(device_->enabled_persistent_);
  EXPECT_FALSE(device_->enabled_pending_);
  EXPECT_TRUE(device_->enabled_);
  EXPECT_TRUE(error.IsSuccess());

  // Disable while already disabled.
  device_->enabled_ = false;
  SetEnabledSync(device_.get(), false, false, &error);
  EXPECT_FALSE(device_->enabled_persistent_);
  EXPECT_FALSE(device_->enabled_pending_);
  EXPECT_FALSE(device_->enabled_);
  EXPECT_TRUE(error.IsSuccess());

  // Disable while already enabling.
  device_->enabled_pending_ = true;
  SetEnabledSync(device_.get(), false, false, &error);
  EXPECT_FALSE(device_->enabled_persistent_);
  EXPECT_TRUE(device_->enabled_pending_);
  EXPECT_FALSE(device_->enabled_);
  EXPECT_TRUE(error.IsSuccess());
}

TEST_F(DeviceTest, SetEnabledPersistent) {
  EXPECT_FALSE(device_->enabled_);
  EXPECT_FALSE(device_->enabled_pending_);
  device_->enabled_persistent_ = false;
  Error error;
  SetEnabledSync(device_.get(), true, true, &error);
  EXPECT_TRUE(device_->enabled_persistent_);
  EXPECT_TRUE(device_->enabled_pending_);

  // Enable while already enabled (but not persisted).
  device_->enabled_persistent_ = false;
  device_->enabled_pending_ = true;
  device_->enabled_ = true;
  SetEnabledSync(device_.get(), true, true, &error);
  EXPECT_TRUE(device_->enabled_persistent_);
  EXPECT_TRUE(device_->enabled_pending_);
  EXPECT_TRUE(device_->enabled_);
  EXPECT_TRUE(error.IsSuccess());

  // Enable while enabled but disabling.
  device_->enabled_pending_ = false;
  SetEnabledSync(device_.get(), true, true, &error);
  EXPECT_TRUE(device_->enabled_persistent_);
  EXPECT_FALSE(device_->enabled_pending_);
  EXPECT_TRUE(device_->enabled_);
  EXPECT_EQ(Error::kOperationFailed, error.type());

  // Disable while already disabled (persisted).
  device_->enabled_ = false;
  SetEnabledSync(device_.get(), false, true, &error);
  EXPECT_FALSE(device_->enabled_persistent_);
  EXPECT_FALSE(device_->enabled_pending_);
  EXPECT_FALSE(device_->enabled_);
  EXPECT_TRUE(error.IsSuccess());

  // Disable while already enabling.
  device_->enabled_pending_ = true;
  SetEnabledSync(device_.get(), false, true, &error);
  EXPECT_FALSE(device_->enabled_persistent_);
  EXPECT_TRUE(device_->enabled_pending_);
  EXPECT_FALSE(device_->enabled_);
  EXPECT_EQ(Error::kOperationFailed, error.type());

  // Disable while already disabled (but not persisted).
  error.Reset();
  device_->enabled_persistent_ = true;
  device_->enabled_pending_ = false;
  device_->enabled_ = false;
  SetEnabledSync(device_.get(), false, true, &error);
  EXPECT_FALSE(device_->enabled_persistent_);
  EXPECT_FALSE(device_->enabled_pending_);
  EXPECT_FALSE(device_->enabled_);
  EXPECT_TRUE(error.IsSuccess());
}

TEST_F(DeviceTest, Start) {
  EXPECT_FALSE(device_->enabled_);
  EXPECT_FALSE(device_->enabled_pending_);
  device_->SetEnabled(true);
  EXPECT_TRUE(device_->enabled_pending_);
  EXPECT_TRUE(device_->enabled_);
}

TEST_F(DeviceTest, StartFailure) {
  EXPECT_FALSE(device_->enabled_);
  EXPECT_FALSE(device_->enabled_pending_);
  device_->start_stop_error_.Populate(Error::kOperationFailed);
  device_->SetEnabled(true);
  EXPECT_FALSE(device_->enabled_pending_);
  EXPECT_FALSE(device_->enabled_);
}

TEST_F(DeviceTest, Stop) {
  device_->enabled_ = true;
  device_->enabled_pending_ = true;
  scoped_refptr<MockService> service(new NiceMock<MockService>(manager()));
  SelectService(service);

  EXPECT_CALL(*service, state())
      .WillRepeatedly(Return(Service::kStateConnected));
  EXPECT_CALL(*GetDeviceMockAdaptor(),
              EmitBoolChanged(kPoweredProperty, false));
  EXPECT_CALL(rtnl_handler_, SetInterfaceFlags(_, 0, IFF_UP));
  EXPECT_CALL(*service, SetAttachedNetwork(IsWeakPtrTo(nullptr)));
  EXPECT_CALL(*network_, Stop());
  device_->SetEnabled(false);

  EXPECT_EQ(nullptr, device_->selected_service_);
}

TEST_F(DeviceTest, StopWithFixedIpParams) {
  device_->GetPrimaryNetwork()->set_fixed_ip_params_for_testing(true);
  device_->enabled_ = true;
  device_->enabled_pending_ = true;
  scoped_refptr<MockService> service(new NiceMock<MockService>(manager()));
  SelectService(service);

  EXPECT_CALL(*service, state())
      .WillRepeatedly(Return(Service::kStateConnected));
  EXPECT_CALL(*GetDeviceMockAdaptor(),
              EmitBoolChanged(kPoweredProperty, false));
  EXPECT_CALL(rtnl_handler_, SetInterfaceFlags(_, _, _)).Times(0);
  EXPECT_CALL(*service, SetAttachedNetwork(IsWeakPtrTo(nullptr)));
  EXPECT_CALL(*network_, Stop());
  device_->SetEnabled(false);

  EXPECT_EQ(nullptr, device_->selected_service_);
}

TEST_F(DeviceTest, StopWithNetworkInterfaceDisabledAfterward) {
  device_->enabled_ = true;
  device_->enabled_pending_ = true;
  scoped_refptr<MockService> service(new NiceMock<MockService>(manager()));
  SelectService(service);

  EXPECT_CALL(*device_, ShouldBringNetworkInterfaceDownAfterDisabled())
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*service, state())
      .WillRepeatedly(Return(Service::kStateConnected));
  EXPECT_CALL(*GetDeviceMockAdaptor(),
              EmitBoolChanged(kPoweredProperty, false));
  EXPECT_CALL(*service, SetAttachedNetwork(IsWeakPtrTo(nullptr)));
  EXPECT_CALL(rtnl_handler_, SetInterfaceFlags(_, 0, IFF_UP));
  EXPECT_CALL(*network_, Stop());
  device_->SetEnabled(false);

  EXPECT_EQ(nullptr, device_->selected_service_);
}

TEST_F(DeviceTest, StartProhibited) {
  DeviceRefPtr device(new TestDevice(manager(), kDeviceName, kDeviceAddress,
                                     kDeviceInterfaceIndex, Technology::kWiFi));
  {
    Error error;
    manager()->SetProhibitedTechnologies("wifi", &error);
    EXPECT_TRUE(error.IsSuccess());
  }

  device->SetEnabled(true);
  EXPECT_FALSE(device->enabled_pending());

  {
    Error error;
    manager()->SetProhibitedTechnologies("", &error);
    EXPECT_TRUE(error.IsSuccess());
  }
  device->SetEnabled(true);
  EXPECT_TRUE(device->enabled_pending());
}

TEST_F(DeviceTest, Reset) {
  base::test::TestFuture<Error> e;
  device_->Reset(GetResultCallback(&e));

  EXPECT_EQ(Error::kNotImplemented, e.Get().type());
}

TEST_F(DeviceTest, ResumeConnected) {
  scoped_refptr<MockService> service0(new NiceMock<MockService>(manager()));
  SelectService(service0);
  EXPECT_CALL(*service0, IsConnected(nullptr)).WillRepeatedly(Return(true));
  EXPECT_CALL(*network_, RenewDHCPLease());
  EXPECT_CALL(*network_, InvalidateIPv6Config());
  device_->OnAfterResume();
}

TEST_F(DeviceTest, ResumeDisconnected) {
  EXPECT_CALL(*network_, RenewDHCPLease()).Times(0);
  EXPECT_CALL(*network_, InvalidateIPv6Config()).Times(0);
  device_->OnAfterResume();
}

TEST_F(DeviceTest, AvailableIPConfigs) {
  EXPECT_EQ(std::vector<RpcIdentifier>(), device_->AvailableIPConfigs(nullptr));
  network_->set_ipconfig(
      std::make_unique<IPConfig>(control_interface(), kDeviceName));
  EXPECT_EQ(std::vector<RpcIdentifier>{IPConfigMockAdaptor::kRpcId},
            device_->AvailableIPConfigs(nullptr));
  network_->set_ip6config(
      std::make_unique<IPConfig>(control_interface(), kDeviceName));

  // We don't really care that the RPC IDs for all IPConfig mock adaptors
  // are the same, or their ordering.  We just need to see that there are two
  // of them when both IPv6 and IPv4 IPConfigs are available.
  EXPECT_EQ(2, device_->AvailableIPConfigs(nullptr).size());

  network_->set_ipconfig(nullptr);
  EXPECT_EQ(std::vector<RpcIdentifier>{IPConfigMockAdaptor::kRpcId},
            device_->AvailableIPConfigs(nullptr));

  network_->set_ip6config(nullptr);
  EXPECT_EQ(std::vector<RpcIdentifier>(), device_->AvailableIPConfigs(nullptr));
}

TEST_F(DeviceTest, SetMacAddress) {
  constexpr char mac_address[] = "abcdefabcdef";
  EXPECT_CALL(*GetDeviceMockAdaptor(),
              EmitStringChanged(kAddressProperty, mac_address));
  EXPECT_NE(mac_address, device_->mac_address());
  device_->device_set_mac_address(mac_address);
  EXPECT_EQ(mac_address, device_->mac_address());
}

TEST_F(DeviceTest, FetchTrafficCounters) {
  auto source0 = patchpanel::Client::TrafficSource::kChrome;
  auto source1 = patchpanel::Client::TrafficSource::kUser;
  std::valarray<uint64_t> counter_arr0{2842, 1243, 240598, 43095};
  std::valarray<uint64_t> counter_arr1{4554666, 43543, 5999, 500000};
  patchpanel::Client::TrafficCounter counter0 =
      CreateCounter(counter_arr0, source0, kDeviceName);
  patchpanel::Client::TrafficCounter counter1 =
      CreateCounter(counter_arr1, source1, kDeviceName);
  std::vector<patchpanel::Client::TrafficCounter> counters{counter0, counter1};
  patchpanel_client_->set_stored_traffic_counters(counters);

  EXPECT_EQ(nullptr, device_->selected_service_);
  scoped_refptr<MockService> service0(new NiceMock<MockService>(manager()));
  EXPECT_TRUE(service0->traffic_counter_snapshot_.empty());
  EXPECT_TRUE(service0->current_traffic_counters_.empty());
  SelectService(service0);
  EXPECT_EQ(service0, device_->selected_service_);
  EXPECT_TRUE(service0->current_traffic_counters_.empty());
  EXPECT_EQ(2, service0->traffic_counter_snapshot_.size());
  for (size_t i = 0; i < Service::kTrafficCounterArraySize; i++) {
    EXPECT_EQ(counter_arr0[i], service0->traffic_counter_snapshot_[source0][i]);
    EXPECT_EQ(counter_arr1[i], service0->traffic_counter_snapshot_[source1][i]);
  }

  std::valarray<uint64_t> counter_diff0{12, 98, 34, 76};
  std::valarray<uint64_t> counter_diff1{324534, 23434, 785676, 256};
  std::valarray<uint64_t> new_total0 = counter_arr0 + counter_diff0;
  std::valarray<uint64_t> new_total1 = counter_arr1 + counter_diff1;
  counter0 = CreateCounter(new_total0, source0, kDeviceName);
  counter1 = CreateCounter(new_total1, source1, kDeviceName);
  counters = {counter0, counter1};
  patchpanel_client_->set_stored_traffic_counters(counters);

  scoped_refptr<MockService> service1(new NiceMock<MockService>(manager()));
  EXPECT_CALL(*service0, SetAttachedNetwork(IsWeakPtrTo(nullptr)));
  SelectService(service1);
  EXPECT_EQ(service1, device_->selected_service_);
  for (size_t i = 0; i < Service::kTrafficCounterArraySize; i++) {
    EXPECT_EQ(counter_diff0[i],
              service0->current_traffic_counters_[source0][i]);
    EXPECT_EQ(counter_diff1[i],
              service0->current_traffic_counters_[source1][i]);

    EXPECT_EQ(new_total0[i], service1->traffic_counter_snapshot_[source0][i]);
    EXPECT_EQ(new_total1[i], service1->traffic_counter_snapshot_[source1][i]);
  }
  EXPECT_TRUE(service1->current_traffic_counters_.empty());
}

class DevicePortalDetectionTest : public DeviceTest {
 public:
  DevicePortalDetectionTest()
      : service_(new StrictMock<MockService>(manager())) {
    ON_CALL(*network_, IsConnected()).WillByDefault(Return(true));
  }
  ~DevicePortalDetectionTest() override = default;

  void SetUp() override {
    DeviceTest::SetUp();
    EXPECT_CALL(*service_, SetProbeUrl(_)).Times(AnyNumber());
    SelectService(service_);
  }

  void TearDown() override {}

 protected:
  static const int kPortalAttempts;

  bool UpdatePortalDetector(bool restart = false) {
    return device_->UpdatePortalDetector(restart);
  }

  void OnNetworkValidationResult(const PortalDetector::Result& result) {
    device_->OnNetworkValidationResult(device_->interface_index(), result);
  }

  scoped_refptr<MockService> service_;
};

const int DevicePortalDetectionTest::kPortalAttempts = 2;

TEST_F(DevicePortalDetectionTest, NoSelectedService) {
  device_->set_selected_service_for_testing(nullptr);
  EXPECT_CALL(*service_, IsPortalDetectionDisabled()).Times(0);
  EXPECT_CALL(*service_, IsConnected(nullptr)).Times(0);
  EXPECT_CALL(*service_, SetState(Service::kStateOnline)).Times(0);
  EXPECT_CALL(*network_, StartPortalDetection(_)).Times(0);

  EXPECT_FALSE(UpdatePortalDetector(true));
  EXPECT_FALSE(UpdatePortalDetector(false));
}

TEST_F(DevicePortalDetectionTest, ServiceNotConnected) {
  EXPECT_CALL(*service_, IsPortalDetectionDisabled()).Times(0);
  EXPECT_CALL(*service_, IsConnected(nullptr)).WillRepeatedly(Return(false));
  EXPECT_CALL(*service_, SetState(Service::kStateOnline)).Times(0);
  EXPECT_CALL(*network_, StartPortalDetection(_)).Times(0);

  EXPECT_FALSE(UpdatePortalDetector(true));
  EXPECT_FALSE(UpdatePortalDetector(false));
}

TEST_F(DevicePortalDetectionTest, PortalDetectionDisabled) {
  EXPECT_CALL(*service_, IsPortalDetectionDisabled())
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*service_, IsConnected(nullptr)).WillRepeatedly(Return(true));
  EXPECT_CALL(*service_, SetState(Service::kStateOnline)).Times(2);
  EXPECT_CALL(*network_, StartPortalDetection(_)).Times(0);

  EXPECT_FALSE(UpdatePortalDetector(true));
  EXPECT_FALSE(UpdatePortalDetector(false));
}

TEST_F(DevicePortalDetectionTest, PortalDetectionInProgress_ForceRestart) {
  EXPECT_CALL(*service_, IsPortalDetectionDisabled())
      .WillRepeatedly(Return(false));
  EXPECT_CALL(*service_, IsConnected(nullptr)).WillRepeatedly(Return(true));
  EXPECT_CALL(*network_, StartPortalDetection(_)).WillOnce(Return(true));

  EXPECT_TRUE(UpdatePortalDetector(true));
}

TEST_F(DevicePortalDetectionTest, PortalDetectionBadUrl) {
  const ManagerProperties props;

  EXPECT_CALL(*service_, IsConnected(nullptr)).WillRepeatedly(Return(true));
  EXPECT_CALL(*service_, IsPortalDetectionDisabled())
      .WillRepeatedly(Return(false));
  EXPECT_CALL(*service_, SetState(Service::kStateOnline));
  EXPECT_CALL(*network_, StartPortalDetection(_)).WillOnce(Return(false));

  EXPECT_FALSE(UpdatePortalDetector());
}

TEST_F(DevicePortalDetectionTest, PortalDetectionStart) {
  EXPECT_CALL(*service_, IsPortalDetectionDisabled())
      .WillRepeatedly(Return(false));
  EXPECT_CALL(*service_, IsConnected(nullptr)).WillRepeatedly(Return(true));
  EXPECT_CALL(*service_, SetState(Service::kStateOnline)).Times(0);
  EXPECT_CALL(*network_, StartPortalDetection(_)).WillOnce(Return(true));

  EXPECT_TRUE(UpdatePortalDetector());
}

TEST_F(DevicePortalDetectionTest, PortalDetectionStartIPv6) {
  EXPECT_CALL(*service_, IsPortalDetectionDisabled())
      .WillRepeatedly(Return(false));
  EXPECT_CALL(*service_, IsConnected(nullptr)).WillRepeatedly(Return(true));
  EXPECT_CALL(*service_, SetState(Service::kStateOnline)).Times(0);
  EXPECT_CALL(*network_, StartPortalDetection(_)).WillOnce(Return(true));

  EXPECT_TRUE(UpdatePortalDetector());
}

TEST_F(DevicePortalDetectionTest, PortalRetryAfterDetectionFailure) {
  const int kFailureStatusCode = 204;
  const auto ip_addr = *IPAddress::CreateFromString("1.2.3.4");
  const std::vector<std::string> dns_list = {"8.8.8.8", "8.8.4.4"};
  PortalDetector::Result result;
  result.http_phase = PortalDetector::Phase::kConnection,
  result.http_status = PortalDetector::Status::kFailure;
  result.http_status_code = kFailureStatusCode;
  result.https_phase = PortalDetector::Phase::kContent;
  result.https_status = PortalDetector::Status::kSuccess;
  result.num_attempts = kPortalAttempts;

  EXPECT_CALL(*service_, IsConnected(nullptr)).WillOnce(Return(true));
  EXPECT_CALL(*service_,
              SetPortalDetectionFailure(kPortalDetectionPhaseConnection,
                                        kPortalDetectionStatusFailure,
                                        kFailureStatusCode));
  EXPECT_CALL(*service_, SetState(Service::kStateNoConnectivity));
  EXPECT_CALL(*metrics(), SendEnumToUMA(_, Technology(Technology::kUnknown), _))
      .Times(AnyNumber());
  EXPECT_CALL(*network_, RestartPortalDetection()).WillOnce(Return(true));
  OnNetworkValidationResult(result);
}

TEST_F(DevicePortalDetectionTest, PortalDetectionSuccess) {
  EXPECT_CALL(*service_, IsConnected(nullptr)).WillOnce(Return(true));
  EXPECT_CALL(*service_, SetPortalDetectionFailure(_, _, _)).Times(0);
  EXPECT_CALL(*service_, SetState(Service::kStateOnline));
  EXPECT_CALL(*metrics(), SendEnumToUMA(_, Technology(Technology::kUnknown), _))
      .Times(AnyNumber());
  PortalDetector::Result result;
  result.http_phase = PortalDetector::Phase::kContent;
  result.http_status = PortalDetector::Status::kSuccess;
  result.https_phase = PortalDetector::Phase::kContent;
  result.https_status = PortalDetector::Status::kSuccess;
  result.num_attempts = kPortalAttempts;
  OnNetworkValidationResult(result);
}

// The first portal detection attempt is inconclusive and the next portal
// detection attempt fails, causing the Service State to be set to 'online'
// since portal detection did not run.
TEST_F(DevicePortalDetectionTest, NextAttemptFails) {
  EXPECT_CALL(*service_, IsConnected(nullptr)).WillRepeatedly(Return(true));
  // If portal detection attempts fail, default to optimistically assuming that
  // the Service is 'online'.
  EXPECT_CALL(*service_, SetState(Service::kStateOnline));
  EXPECT_CALL(*service_, SetPortalDetectionFailure(
                             StrEq(kPortalDetectionPhaseDns),
                             StrEq(kPortalDetectionStatusTimeout), 0));
  // The second portal detection attempt fails immediately, forcing the Device
  // to assume the Service state is 'online'.
  EXPECT_CALL(*network_, RestartPortalDetection()).WillOnce(Return(false));

  // First result indicating no connectivity and triggering a new portal
  // detection attempt.
  PortalDetector::Result result;
  result.http_phase = PortalDetector::Phase::kDNS,
  result.http_status = PortalDetector::Status::kTimeout;
  result.https_phase = PortalDetector::Phase::kDNS;
  result.https_status = PortalDetector::Status::kTimeout;
  OnNetworkValidationResult(result);
}

TEST_F(DevicePortalDetectionTest, ScheduleNextDetectionAttempt) {
  EXPECT_CALL(*service_, IsConnected(nullptr)).WillRepeatedly(Return(true));
  // If portal detection attempts run successfully and do not validate the
  // network, the Service state does not become 'online'.
  EXPECT_CALL(*service_, SetState(Service::kStateNoConnectivity));
  EXPECT_CALL(*service_, SetPortalDetectionFailure(
                             StrEq(kPortalDetectionPhaseDns),
                             StrEq(kPortalDetectionStatusTimeout), 0));
  // The second portal detection attempt succeeds.
  EXPECT_CALL(*network_, RestartPortalDetection()).WillOnce(Return(true));

  // First result indicating no connectivity and triggering a new portal
  // detection attempt.
  PortalDetector::Result result;
  result.http_phase = PortalDetector::Phase::kDNS,
  result.http_status = PortalDetector::Status::kTimeout;
  result.https_phase = PortalDetector::Phase::kDNS;
  result.https_status = PortalDetector::Status::kTimeout;
  OnNetworkValidationResult(result);
}

TEST_F(DevicePortalDetectionTest, CancelledOnSelectService) {
  EXPECT_CALL(*service_, state()).WillOnce(Return(Service::kStateIdle));
  EXPECT_CALL(*service_, SetState(_));
  EXPECT_CALL(*service_, SetAttachedNetwork(IsWeakPtrTo(nullptr)));
  SelectService(nullptr);
}

TEST_F(DevicePortalDetectionTest, PortalDetectionDNSFailure) {
  const int kFailureStatusCode = 204;
  PortalDetector::Result result;
  result.http_phase = PortalDetector::Phase::kDNS,
  result.http_status = PortalDetector::Status::kFailure;
  result.http_status_code = kFailureStatusCode;
  result.https_phase = PortalDetector::Phase::kContent;
  result.https_status = PortalDetector::Status::kFailure;
  result.num_attempts = kPortalAttempts;

  EXPECT_CALL(*service_, IsConnected(nullptr)).WillRepeatedly(Return(true));
  EXPECT_CALL(*service_,
              SetPortalDetectionFailure(kPortalDetectionPhaseDns,
                                        kPortalDetectionStatusFailure,
                                        kFailureStatusCode));
  EXPECT_CALL(*service_, SetState(Service::kStateNoConnectivity));
  EXPECT_CALL(*network_, RestartPortalDetection()).WillOnce(Return(true));

  OnNetworkValidationResult(result);
}

TEST_F(DevicePortalDetectionTest, PortalDetectionDNSTimeout) {
  PortalDetector::Result result;
  result.http_phase = PortalDetector::Phase::kDNS,
  result.http_status = PortalDetector::Status::kTimeout;
  result.http_status_code = 0;
  result.https_phase = PortalDetector::Phase::kContent;
  result.https_status = PortalDetector::Status::kFailure;
  result.num_attempts = kPortalAttempts;

  EXPECT_CALL(*service_, IsConnected(nullptr)).WillRepeatedly(Return(true));
  EXPECT_CALL(*service_,
              SetPortalDetectionFailure(kPortalDetectionPhaseDns,
                                        kPortalDetectionStatusTimeout, 0));
  EXPECT_CALL(*service_, SetState(Service::kStateNoConnectivity));
  EXPECT_CALL(*network_, RestartPortalDetection()).WillOnce(Return(true));

  OnNetworkValidationResult(result);
}

TEST_F(DevicePortalDetectionTest, PortalDetectionRedirect) {
  PortalDetector::Result result;
  result.http_phase = PortalDetector::Phase::kContent,
  result.http_status = PortalDetector::Status::kRedirect;
  result.http_status_code = 302;
  result.https_phase = PortalDetector::Phase::kContent;
  result.https_status = PortalDetector::Status::kSuccess;
  result.redirect_url_string = PortalDetector::kDefaultHttpUrl;
  result.num_attempts = kPortalAttempts;

  EXPECT_CALL(*service_, IsConnected(nullptr)).WillRepeatedly(Return(true));
  EXPECT_CALL(*service_,
              SetPortalDetectionFailure(kPortalDetectionPhaseContent,
                                        kPortalDetectionStatusRedirect, 302));
  EXPECT_CALL(*service_, SetState(Service::kStateRedirectFound));
  EXPECT_CALL(*network_, RestartPortalDetection()).WillOnce(Return(true));

  OnNetworkValidationResult(result);
}

TEST_F(DevicePortalDetectionTest, PortalDetectionRedirectNoUrl) {
  PortalDetector::Result result;
  result.http_phase = PortalDetector::Phase::kContent,
  result.http_status = PortalDetector::Status::kRedirect;
  result.http_status_code = 302;
  result.https_phase = PortalDetector::Phase::kContent;
  result.https_status = PortalDetector::Status::kSuccess;
  result.num_attempts = kPortalAttempts;

  EXPECT_CALL(*service_, IsConnected(nullptr)).WillRepeatedly(Return(true));
  EXPECT_CALL(*service_,
              SetPortalDetectionFailure(kPortalDetectionPhaseContent,
                                        kPortalDetectionStatusRedirect, 302));
  EXPECT_CALL(*service_, SetState(Service::kStatePortalSuspected));
  EXPECT_CALL(*network_, RestartPortalDetection()).WillOnce(Return(true));

  OnNetworkValidationResult(result);
}

TEST_F(DevicePortalDetectionTest, PortalDetectionPortalSuspected) {
  PortalDetector::Result result;
  result.http_phase = PortalDetector::Phase::kContent,
  result.http_status = PortalDetector::Status::kSuccess;
  result.http_status_code = 204;
  result.https_phase = PortalDetector::Phase::kContent;
  result.https_status = PortalDetector::Status::kFailure;
  result.num_attempts = kPortalAttempts;

  EXPECT_CALL(*service_, IsConnected(nullptr)).WillRepeatedly(Return(true));
  EXPECT_CALL(*service_,
              SetPortalDetectionFailure(kPortalDetectionPhaseContent,
                                        kPortalDetectionStatusSuccess, 204));
  EXPECT_CALL(*service_, SetState(Service::kStatePortalSuspected));
  EXPECT_CALL(*network_, RestartPortalDetection()).WillOnce(Return(true));

  OnNetworkValidationResult(result);
}

TEST_F(DevicePortalDetectionTest, PortalDetectionNoConnectivity) {
  PortalDetector::Result result;
  result.http_phase = PortalDetector::Phase::kUnknown,
  result.http_status = PortalDetector::Status::kFailure;
  result.http_status_code = 0;
  result.https_phase = PortalDetector::Phase::kContent;
  result.https_status = PortalDetector::Status::kFailure;
  result.num_attempts = kPortalAttempts;

  EXPECT_CALL(*service_, IsConnected(nullptr)).WillRepeatedly(Return(true));
  EXPECT_CALL(*service_,
              SetPortalDetectionFailure(kPortalDetectionPhaseUnknown,
                                        kPortalDetectionStatusFailure, 0));
  EXPECT_CALL(*service_, SetState(Service::kStateNoConnectivity));
  EXPECT_CALL(*network_, RestartPortalDetection()).WillOnce(Return(true));

  OnNetworkValidationResult(result);
}

}  // namespace shill

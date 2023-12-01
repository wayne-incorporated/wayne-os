// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/wifi/hotspot_device.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/memory/ref_counted.h>
#include <base/test/mock_callback.h>
#include <gmock/gmock.h>

#include "shill/error.h"
#include "shill/mock_control.h"
#include "shill/mock_event_dispatcher.h"
#include "shill/mock_manager.h"
#include "shill/mock_metrics.h"
#include "shill/store/key_value_store.h"
#include "shill/supplicant/mock_supplicant_interface_proxy.h"
#include "shill/supplicant/mock_supplicant_process_proxy.h"
#include "shill/supplicant/wpa_supplicant.h"
#include "shill/test_event_dispatcher.h"
#include "shill/testing.h"
#include "shill/wifi/hotspot_service.h"
#include "shill/wifi/local_device.h"
#include "shill/wifi/wifi_security.h"

using ::testing::_;
using ::testing::ByMove;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Mock;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::SetArgPointee;
using ::testing::StrictMock;
using ::testing::Test;

namespace shill {

namespace {
const char kPrimaryInterfaceName[] = "wlan0";
const char kInterfaceName[] = "ap0";
const char kDeviceAddress[] = "00:01:02:03:04:05";
const char kHotspotSSID[] = "chromeOS-1234";
const char kHotspotPassphrase[] = "test0000";
const int kHotspotFrequency = 2437;
const std::vector<uint8_t> kStationAddress1 = {00, 11, 22, 33, 44, 55};
const std::vector<uint8_t> kStationAddress2 = {00, 11, 22, 33, 44, 66};
const uint32_t kPhyIndex = 5678;
const RpcIdentifier kPrimaryIfacePath = RpcIdentifier("/interface/wlan0");
const RpcIdentifier kIfacePath = RpcIdentifier("/interface/ap0");
const RpcIdentifier kNetworkPath = RpcIdentifier("/network/path");
const RpcIdentifier kStationPath1 = RpcIdentifier("/station/path/1");
const RpcIdentifier kStationPath2 = RpcIdentifier("/station/path/2");
const RpcIdentifier kStationPath3 = RpcIdentifier("/station/path/3");
}  // namespace

class HotspotDeviceTest : public testing::Test {
 public:
  HotspotDeviceTest()
      : manager_(&control_interface_, &dispatcher_, &metrics_),
        device_(new HotspotDevice(&manager_,
                                  kPrimaryInterfaceName,
                                  kInterfaceName,
                                  kDeviceAddress,
                                  kPhyIndex,
                                  cb.Get())),
        supplicant_process_proxy_(new NiceMock<MockSupplicantProcessProxy>()),
        supplicant_interface_proxy_(
            new NiceMock<MockSupplicantInterfaceProxy>()) {
    manager_.supplicant_manager()->set_proxy(supplicant_process_proxy_);
    ON_CALL(*supplicant_process_proxy_, CreateInterface(_, _))
        .WillByDefault(DoAll(SetArgPointee<1>(kIfacePath), Return(true)));
    ON_CALL(control_interface_, CreateSupplicantInterfaceProxy(_, kIfacePath))
        .WillByDefault(Return(ByMove(std::move(supplicant_interface_proxy_))));
  }

  void DispatchPendingEvents() { dispatcher_.DispatchPendingEvents(); }

 protected:
  MockSupplicantInterfaceProxy* GetSupplicantInterfaceProxy() {
    return static_cast<MockSupplicantInterfaceProxy*>(
        device_->supplicant_interface_proxy_.get());
  }

  StrictMock<base::MockRepeatingCallback<void(LocalDevice::DeviceEvent,
                                              const LocalDevice*)>>
      cb;

  NiceMock<MockControl> control_interface_;
  EventDispatcherForTest dispatcher_;
  NiceMock<MockMetrics> metrics_;
  NiceMock<MockManager> manager_;

  scoped_refptr<HotspotDevice> device_;
  MockSupplicantProcessProxy* supplicant_process_proxy_;
  std::unique_ptr<MockSupplicantInterfaceProxy> supplicant_interface_proxy_;
};

TEST_F(HotspotDeviceTest, DeviceCleanStartStopWiFiDisabled) {
  // wpa_supplicant does not control wlan0 if WiFi is disabled.
  EXPECT_CALL(*supplicant_process_proxy_,
              GetInterface(kPrimaryInterfaceName, _))
      .WillOnce(Return(false));
  // Expect to ask wpa_supplicant to control wlan0 first then ap0.
  EXPECT_CALL(*supplicant_process_proxy_, CreateInterface(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(kPrimaryIfacePath), Return(true)))
      .WillOnce(DoAll(SetArgPointee<1>(kIfacePath), Return(true)));
  EXPECT_TRUE(device_->Start());

  // Expect disconnect wpa_supplicant from ap0 and wlan0.
  EXPECT_CALL(*supplicant_process_proxy_, RemoveInterface(kIfacePath))
      .WillOnce(Return(true));
  EXPECT_CALL(*supplicant_process_proxy_, RemoveInterface(kPrimaryIfacePath))
      .WillOnce(Return(true));

  // Expect no DeviceEvent::kInterfaceDisabled sent if the interface is
  // destroyed by caller not Kernel.
  EXPECT_CALL(cb, Run(_, _)).Times(0);
  EXPECT_TRUE(device_->Stop());
  DispatchPendingEvents();
  Mock::VerifyAndClearExpectations(&cb);
}

TEST_F(HotspotDeviceTest, DeviceCleanStartStopWiFiEnabled) {
  // wpa_supplicant already controls wlan0 if WiFi is enabled.
  EXPECT_CALL(*supplicant_process_proxy_,
              GetInterface(kPrimaryInterfaceName, _))
      .WillOnce(DoAll(SetArgPointee<1>(kPrimaryIfacePath), Return(true)));
  // wpa_supplicant only need to control ap0.
  EXPECT_CALL(*supplicant_process_proxy_, CreateInterface(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(kIfacePath), Return(true)));
  EXPECT_TRUE(device_->Start());

  // Expect disconnect wpa_supplicant from ap0 only.
  EXPECT_CALL(*supplicant_process_proxy_, RemoveInterface(kIfacePath))
      .WillOnce(Return(true));

  // Expect no DeviceEvent::kInterfaceDisabled sent if the interface is
  // destroyed by caller not Kernel.
  EXPECT_CALL(cb, Run(_, _)).Times(0);
  EXPECT_TRUE(device_->Stop());
  DispatchPendingEvents();
  Mock::VerifyAndClearExpectations(&cb);
}

TEST_F(HotspotDeviceTest, DeviceExistStart) {
  EXPECT_CALL(*supplicant_process_proxy_,
              GetInterface(kPrimaryInterfaceName, _))
      .WillOnce(DoAll(SetArgPointee<1>(kPrimaryIfacePath), Return(true)));
  EXPECT_CALL(*supplicant_process_proxy_, CreateInterface(_, _))
      .WillOnce(Return(false));
  EXPECT_CALL(*supplicant_process_proxy_, GetInterface(kInterfaceName, _))
      .WillOnce(DoAll(SetArgPointee<1>(kIfacePath), Return(true)));
  EXPECT_TRUE(device_->Start());
}

TEST_F(HotspotDeviceTest, InterfaceDisabledEvent) {
  KeyValueStore props;
  props.Set<std::string>(WPASupplicant::kInterfacePropertyState,
                         WPASupplicant::kInterfaceStateInterfaceDisabled);

  // Expect supplicant_state_ change and kInterfaceDisabled DeviceEvent sent.
  EXPECT_CALL(cb, Run(LocalDevice::DeviceEvent::kInterfaceDisabled, _))
      .Times(1);
  device_->PropertiesChangedTask(props);
  EXPECT_EQ(device_->supplicant_state_,
            WPASupplicant::kInterfaceStateInterfaceDisabled);
  DispatchPendingEvents();
  Mock::VerifyAndClearExpectations(&cb);

  // Expect no supplicant_state_ change and no DeviceEvent sent with same state.
  EXPECT_CALL(cb, Run(_, _)).Times(0);
  device_->PropertiesChangedTask(props);
  EXPECT_EQ(device_->supplicant_state_,
            WPASupplicant::kInterfaceStateInterfaceDisabled);
  DispatchPendingEvents();
  Mock::VerifyAndClearExpectations(&cb);
}

TEST_F(HotspotDeviceTest, ConfigureDeconfigureService) {
  EXPECT_TRUE(device_->Start());

  // Configure service for the first time.
  auto service0 = std::make_unique<HotspotService>(
      device_, kHotspotSSID, kHotspotPassphrase, WiFiSecurity::kWpa2,
      kHotspotFrequency);
  EXPECT_CALL(*GetSupplicantInterfaceProxy(), AddNetwork(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(kNetworkPath), Return(true)));
  EXPECT_CALL(*GetSupplicantInterfaceProxy(), SelectNetwork(Eq(kNetworkPath)))
      .WillOnce(Return(true));
  EXPECT_TRUE(device_->ConfigureService(std::move(service0)));

  // Configure a second service should be a no-op and return false.
  auto service1 = std::make_unique<HotspotService>(
      device_, kHotspotSSID, kHotspotPassphrase, WiFiSecurity::kWpa2,
      kHotspotFrequency);
  EXPECT_CALL(*GetSupplicantInterfaceProxy(), AddNetwork(_, _)).Times(0);
  EXPECT_CALL(*GetSupplicantInterfaceProxy(), SelectNetwork(Eq(kNetworkPath)))
      .Times(0);
  EXPECT_FALSE(device_->ConfigureService(std::move(service1)));

  // Deconfigure service.
  EXPECT_CALL(*GetSupplicantInterfaceProxy(), RemoveNetwork(Eq(kNetworkPath)))
      .WillOnce(Return(true));
  EXPECT_TRUE(device_->DeconfigureService());

  // Deconfigure service for the second time should be a no-op.
  EXPECT_CALL(*GetSupplicantInterfaceProxy(), RemoveNetwork(Eq(kNetworkPath)))
      .Times(0);
  EXPECT_TRUE(device_->DeconfigureService());
}

TEST_F(HotspotDeviceTest, ServiceEvent) {
  auto service = std::make_unique<HotspotService>(
      device_, kHotspotSSID, kHotspotPassphrase, WiFiSecurity::kWpa2,
      kHotspotFrequency);
  EXPECT_TRUE(device_->Start());
  ON_CALL(*GetSupplicantInterfaceProxy(), AddNetwork(_, _))
      .WillByDefault(DoAll(SetArgPointee<1>(kNetworkPath), Return(true)));
  EXPECT_TRUE(device_->ConfigureService(std::move(service)));

  KeyValueStore props;
  props.Set<std::string>(WPASupplicant::kInterfacePropertyState,
                         WPASupplicant::kInterfaceStateCompleted);

  // Expect supplicant_state_ change and kServiceUp DeviceEvent sent on
  // wpa_supplicant state kInterfaceStateCompleted.
  EXPECT_CALL(cb, Run(LocalDevice::DeviceEvent::kServiceUp, _)).Times(1);
  device_->PropertiesChangedTask(props);
  EXPECT_EQ(device_->supplicant_state_,
            WPASupplicant::kInterfaceStateCompleted);
  DispatchPendingEvents();
  Mock::VerifyAndClearExpectations(&cb);

  // Expect supplicant_state_ change and kServiceDown DeviceEvent sent on
  // wpa_supplicant state kInterfaceStateDisconnected.
  props.Set<std::string>(WPASupplicant::kInterfacePropertyState,
                         WPASupplicant::kInterfaceStateDisconnected);
  EXPECT_CALL(cb, Run(LocalDevice::DeviceEvent::kServiceDown, _)).Times(1);
  device_->PropertiesChangedTask(props);
  EXPECT_EQ(device_->supplicant_state_,
            WPASupplicant::kInterfaceStateDisconnected);
  DispatchPendingEvents();
  Mock::VerifyAndClearExpectations(&cb);

  // Expect supplicant_state_ change but no kServiceDown DeviceEvent sent on
  // further wpa_supplicant state change kInterfaceStateInactive.
  props.Set<std::string>(WPASupplicant::kInterfacePropertyState,
                         WPASupplicant::kInterfaceStateInactive);
  EXPECT_CALL(cb, Run(_, _)).Times(0);
  device_->PropertiesChangedTask(props);
  EXPECT_EQ(device_->supplicant_state_, WPASupplicant::kInterfaceStateInactive);
  DispatchPendingEvents();
  Mock::VerifyAndClearExpectations(&cb);
}

TEST_F(HotspotDeviceTest, StationAddedRemoved) {
  // Station connects.
  KeyValueStore props1;
  props1.Set<std::vector<uint8_t>>(WPASupplicant::kStationPropertyAddress,
                                   kStationAddress1);
  props1.Set<uint16_t>(WPASupplicant::kStationPropertyAID, 0);
  EXPECT_CALL(cb, Run(LocalDevice::DeviceEvent::kPeerConnected, _)).Times(1);
  device_->StationAdded(kStationPath1, props1);
  DispatchPendingEvents();
  Mock::VerifyAndClearExpectations(&cb);

  // Same station connect event should not generate device event.
  EXPECT_CALL(cb, Run(LocalDevice::DeviceEvent::kPeerConnected, _)).Times(0);
  device_->StationAdded(kStationPath1, props1);
  DispatchPendingEvents();
  Mock::VerifyAndClearExpectations(&cb);

  // Remove station
  EXPECT_CALL(cb, Run(LocalDevice::DeviceEvent::kPeerDisconnected, _)).Times(1);
  device_->StationRemoved(kStationPath1);
  DispatchPendingEvents();
  Mock::VerifyAndClearExpectations(&cb);

  // Same station remove event should not generate device event.
  EXPECT_CALL(cb, Run(LocalDevice::DeviceEvent::kPeerDisconnected, _)).Times(0);
  device_->StationRemoved(kStationPath1);
  DispatchPendingEvents();
  Mock::VerifyAndClearExpectations(&cb);
}

TEST_F(HotspotDeviceTest, GetStations) {
  std::vector<std::vector<uint8_t>> mac;

  // Station1 connects.
  KeyValueStore props1;
  props1.Set<std::vector<uint8_t>>(WPASupplicant::kStationPropertyAddress,
                                   kStationAddress1);
  props1.Set<uint16_t>(WPASupplicant::kStationPropertyAID, 0);
  mac.push_back(kStationAddress1);
  device_->StationAdded(kStationPath1, props1);
  auto stations = device_->GetStations();
  EXPECT_EQ(stations, mac);

  // Station2 connects.
  KeyValueStore props2;
  props2.Set<std::vector<uint8_t>>(WPASupplicant::kStationPropertyAddress,
                                   kStationAddress2);
  props2.Set<uint16_t>(WPASupplicant::kStationPropertyAID, 1);
  mac.push_back(kStationAddress2);
  device_->StationAdded(kStationPath2, props2);
  stations = device_->GetStations();
  EXPECT_EQ(stations, mac);

  // Remove station1
  mac.erase(mac.begin());
  device_->StationRemoved(kStationPath1);
  stations = device_->GetStations();
  EXPECT_EQ(stations, mac);

  // Remove station2
  mac.erase(mac.begin());
  device_->StationRemoved(kStationPath2);
  stations = device_->GetStations();
  EXPECT_EQ(stations, mac);

  // Station without properties connects.
  KeyValueStore props3;
  device_->StationAdded(kStationPath3, props3);
  stations = device_->GetStations();
  EXPECT_EQ(stations.size(), 1);
}

}  // namespace shill

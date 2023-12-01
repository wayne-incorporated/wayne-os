// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/dbus/client/client.h"

#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <chromeos/dbus/service_constants.h>
#include <dbus/mock_bus.h>
#include <dbus/mock_object_proxy.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <shill/dbus-proxy-mocks.h>

using testing::_;
using testing::AnyNumber;
using testing::DoAll;
using testing::Invoke;
using testing::Return;
using testing::ReturnRef;
using testing::StrEq;

using org::chromium::flimflam::DeviceProxyInterface;
using org::chromium::flimflam::DeviceProxyMock;
using org::chromium::flimflam::ManagerProxyInterface;
using org::chromium::flimflam::ManagerProxyMock;
using org::chromium::flimflam::ServiceProxyInterface;
using org::chromium::flimflam::ServiceProxyMock;

namespace shill {
namespace {

class FakeClient : public Client {
 public:
  explicit FakeClient(scoped_refptr<dbus::Bus> bus)
      : Client(bus),
        manager_mock_(new ManagerProxyMock),
        service_mock_(new ServiceProxyMock) {
    manager_proxy_.reset(manager_mock_);
    default_service_proxy_.reset(service_mock_);
  }
  virtual ~FakeClient() = default;

  void NotifyOwnerChange(const std::string& old_owner,
                         const std::string& new_owner) {
    OnOwnerChange(old_owner, new_owner);
  }

  void NotifyManagerPropertyChange(const std::string& name,
                                   const brillo::Any& value) {
    OnManagerPropertyChange(name, value);
  }

  void NotifyDefaultServicePropertyChange(const std::string& name,
                                          const brillo::Any& value) {
    OnDefaultServicePropertyChange(name, value);
  }

  void NotifyDevicePropertyChange(const std::string& path,
                                  const std::string& name,
                                  const brillo::Any& value) {
    OnDevicePropertyChange(false, path, name, value);
  }

  void NotifyServicePropertyChange(const std::string& device_path,
                                   const std::string& property_name,
                                   const std::string& property_value) {
    OnServicePropertyChange(device_path, property_name, property_value);
  }

  ManagerProxyMock* manager() { return manager_mock_; }
  ServiceProxyMock* default_service() { return service_mock_; }
  dbus::ObjectPath default_service_path() { return service_path_; }

  DeviceProxyMock* PreMakeDevice(const dbus::ObjectPath& device_path) {
    auto* mock = new DeviceProxyMock();
    device_mocks_[device_path.value()] = mock;
    // We need to keep these objects around all the way until the client is
    // destructed.
    static std::vector<std::unique_ptr<dbus::ObjectPath>> paths;
    auto path = std::make_unique<dbus::ObjectPath>(device_path.value());
    paths.emplace_back(std::move(path));
    EXPECT_CALL(*mock, GetObjectPath)
        .WillRepeatedly(ReturnRef(*paths.back().get()));
    return mock;
  }

  ServiceProxyMock* PreMakeService(const dbus::ObjectPath& service_path) {
    auto* mock = new ServiceProxyMock();
    service_mocks_[service_path.value()] = mock;
    // We need to keep these objects around all the way until the client is
    // destructed.
    static std::vector<std::unique_ptr<dbus::ObjectPath>> paths;
    auto path = std::make_unique<dbus::ObjectPath>(service_path.value());
    paths.emplace_back(std::move(path));
    EXPECT_CALL(*mock, GetObjectPath)
        .WillRepeatedly(ReturnRef(*paths.back().get()));
    return mock;
  }

 protected:
  // Erase the default implementations so we can keep the same proxy pointers
  // throughout.
  void NewDefaultServiceProxy(const dbus::ObjectPath& service_path) override {
    service_path_ = service_path;
  }
  void ReleaseDefaultServiceProxy() override {}

  // Pass back the pre-allocated device which is necessary for correctly setting
  // expectations in tests. Unfortunately this isn't going to let us re-add a
  // device with the same path.
  std::unique_ptr<DeviceProxyInterface> NewDeviceProxy(
      const dbus::ObjectPath& device_path) override {
    const auto it = device_mocks_.find(device_path.value());
    if (it == device_mocks_.end())
      return nullptr;

    std::unique_ptr<DeviceProxyMock> mock;
    mock.reset(it->second);
    return mock;
  }

  std::unique_ptr<ServiceProxyInterface> NewServiceProxy(
      const dbus::ObjectPath& service_path) override {
    const auto it = service_mocks_.find(service_path.value());
    // Auto-premake for tests that don't need it.
    ServiceProxyMock* ptr = (it == service_mocks_.end())
                                ? PreMakeService(service_path)
                                : it->second;

    std::unique_ptr<ServiceProxyMock> mock;
    mock.reset(ptr);
    return mock;
  }

  ManagerProxyMock* manager_mock_;
  ServiceProxyMock* service_mock_;
  dbus::ObjectPath service_path_;
  std::map<std::string, DeviceProxyMock*> device_mocks_;
  std::map<std::string, ServiceProxyMock*> service_mocks_;
};

class ClientTest : public testing::Test {
 protected:
  void SetUp() override {
    default_service_changed_ = false;
    default_device_ = {};
    devices_.clear();
    last_device_changed_.clear();
    last_device_cxn_state_ = Client::Device::ConnectionState::kUnknown;

    // It's necessary to mock the base object used for the
    // SetNameOwnerChangedCallback.
    base_mock_ = new dbus::MockObjectProxy(
        bus_mock_.get(), kFlimflamServiceName, dbus::ObjectPath("/"));
    EXPECT_CALL(*bus_mock_,
                GetObjectProxy(kFlimflamServiceName, dbus::ObjectPath("/")))
        .WillRepeatedly(Return(base_mock_.get()));
    EXPECT_CALL(*base_mock_, SetNameOwnerChangedCallback(_));

    client_ = std::make_unique<FakeClient>(bus_mock_);
    client_->RegisterDefaultServiceChangedHandler(base::BindRepeating(
        &ClientTest::DefaultServiceHandler, base::Unretained(this)));
    client_->RegisterDefaultDeviceChangedHandler(base::BindRepeating(
        &ClientTest::DefaultDeviceHandler, base::Unretained(this)));
    client_->RegisterDeviceAddedHandler(base::BindRepeating(
        &ClientTest::DeviceAddedHandler, base::Unretained(this)));
    client_->RegisterDeviceRemovedHandler(base::BindRepeating(
        &ClientTest::DeviceRemovedHandler, base::Unretained(this)));
    client_->RegisterDeviceChangedHandler(base::BindRepeating(
        &ClientTest::DeviceChangedHandler, base::Unretained(this)));

    // These are not blindly added - we expect the Client to issue these calls
    // on the service in order to recover the path.
    EXPECT_CALL(*client_->default_service(), GetObjectPath)
        .WillRepeatedly(
            Invoke([&]() { return client_->default_service_path(); }));
  }

  void TearDown() override { client_.reset(); }

  void DefaultServiceHandler(const std::string& type) {
    default_service_type_ = type;
    default_service_changed_ = true;
  }
  void DeviceAddedHandler(const Client::Device* const device) {
    ASSERT_TRUE(device);
    EXPECT_TRUE(devices_.find(device->ifname) == devices_.end());
    devices_.emplace(device->ifname, *device);
  }
  void DeviceRemovedHandler(const Client::Device* const device) {
    ASSERT_TRUE(device);
    EXPECT_TRUE(devices_.find(device->ifname) != devices_.end());
    devices_.erase(device->ifname);
  }
  void DefaultDeviceHandler(const Client::Device* const device) {
    if (!device) {
      default_device_ = {};
      return;
    }
    default_device_ = *device;
  }
  void DeviceChangedHandler(const Client::Device* const device) {
    ASSERT_TRUE(device);
    last_device_changed_ = device->ifname;
    last_device_cxn_state_ = device->state;
  }

  scoped_refptr<dbus::MockBus> bus_mock_{
      new dbus::MockBus{dbus::Bus::Options{}}};
  scoped_refptr<dbus::MockObjectProxy> base_mock_;
  std::unique_ptr<FakeClient> client_;

  bool default_service_changed_;
  std::string default_service_type_;
  Client::Device default_device_;
  std::map<std::string, Client::Device> devices_;
  std::string last_device_changed_;
  Client::Device::ConnectionState last_device_cxn_state_;
};

ACTION_TEMPLATE(MovePointee,
                HAS_1_TEMPLATE_PARAMS(int, k),
                AND_1_VALUE_PARAMS(pointer)) {
  *pointer = std::move(*(::std::get<k>(args)));
}

TEST_F(ClientTest, DefaultServiceHandlerCalledForValidServicePath) {
  // When the default service changes, the client will start listening for
  // property changes on that proxy.
  dbus::ObjectProxy::OnConnectedCallback callback;
  EXPECT_CALL(*client_->default_service(),
              DoRegisterPropertyChangedSignalHandler(_, _))
      .WillOnce(MovePointee<1>(&callback));
  client_->NotifyManagerPropertyChange(kDefaultServiceProperty,
                                       dbus::ObjectPath("/service/0"));

  brillo::VariantDictionary props;
  props[kTypeProperty] = std::string("eth");
  EXPECT_CALL(*client_->default_service(), GetProperties(_, _, _))
      .WillOnce(DoAll(testing::SetArgPointee<0>(props), Return(true)));

  std::move(callback).Run(kFlimflamServiceName, kMonitorPropertyChanged, true);
  EXPECT_TRUE(default_service_changed_);
  EXPECT_EQ(default_service_type_, "eth");
}

TEST_F(ClientTest, DefaultServiceHandlerCalledForValidNoServicePath) {
  // No registration should occur if there is no service.
  client_->NotifyManagerPropertyChange(kDefaultServiceProperty,
                                       dbus::ObjectPath("/"));
  EXPECT_TRUE(default_service_changed_);
}

TEST_F(ClientTest, DefaultServiceHandlerCalledForInvalidServicePath) {
  // No registration should occur if there is no service.
  client_->NotifyManagerPropertyChange(kDefaultServiceProperty,
                                       dbus::ObjectPath());
  EXPECT_TRUE(default_service_changed_);
}

TEST_F(ClientTest, DefaultDeviceDiscoveredOnNewService) {
  // We want the device to exist first so the client doesn't run through the new
  // device setup process when it detects the change.
  const dbus::ObjectPath device_path("/device/eth0");
  auto* mock_device = client_->PreMakeDevice(device_path);
  dbus::ObjectProxy::OnConnectedCallback device_callback;
  EXPECT_CALL(*mock_device, DoRegisterPropertyChangedSignalHandler(_, _))
      .WillOnce(MovePointee<1>(&device_callback));

  client_->NotifyManagerPropertyChange(
      kDevicesProperty, std::vector<dbus::ObjectPath>({device_path}));

  brillo::VariantDictionary props;
  props[kTypeProperty] = std::string(kTypeEthernet);
  props[kInterfaceProperty] = std::string("eth0");
  EXPECT_CALL(*mock_device, GetProperties(_, _, _))
      .WillOnce(DoAll(testing::SetArgPointee<0>(props), Return(true)));

  // Manually trigger the registration callback since that doesn't happen in the
  // mocks.
  std::move(device_callback)
      .Run(kFlimflamServiceName, kMonitorPropertyChanged, true);

  // This configures the default service properties and fires the initial
  // callback that is normally run after the proxy registers.
  const dbus::ObjectPath service_path("/service/0");
  auto* mock_service = client_->default_service();
  dbus::ObjectProxy::OnConnectedCallback service_callback;
  EXPECT_CALL(*mock_service, DoRegisterPropertyChangedSignalHandler(_, _))
      .WillOnce(MovePointee<1>(&service_callback));

  client_->NotifyManagerPropertyChange(kDefaultServiceProperty, service_path);

  brillo::VariantDictionary service_props;
  service_props[kIsConnectedProperty] = true;
  service_props[kDeviceProperty] = device_path;
  EXPECT_CALL(*mock_service, GetProperties(_, _, _))
      .WillOnce(DoAll(testing::SetArgPointee<0>(service_props), Return(true)));

  EXPECT_EQ(default_device_.ifname, "");

  std::move(service_callback)
      .Run(kFlimflamServiceName, kMonitorPropertyChanged, true);

  EXPECT_EQ(default_device_.ifname, "eth0");
}

TEST_F(ClientTest, DefaultServiceDisconnectedCallsDefaultHandler) {
  // We want the device to exist first so the client doesn't run through the new
  // device setup process when it detects the change.
  const dbus::ObjectPath device_path("/device/eth0");
  auto* mock_device = client_->PreMakeDevice(device_path);
  dbus::ObjectProxy::OnConnectedCallback device_callback;
  EXPECT_CALL(*mock_device, DoRegisterPropertyChangedSignalHandler(_, _))
      .WillOnce(MovePointee<1>(&device_callback));

  client_->NotifyManagerPropertyChange(
      kDevicesProperty, std::vector<dbus::ObjectPath>({device_path}));

  brillo::VariantDictionary props;
  props[kTypeProperty] = std::string(kTypeEthernet);
  props[kInterfaceProperty] = std::string("eth0");
  EXPECT_CALL(*mock_device, GetProperties(_, _, _))
      .WillOnce(DoAll(testing::SetArgPointee<0>(props), Return(true)));

  // Manually trigger the registration callback since that doesn't happen in the
  // mocks.
  std::move(device_callback)
      .Run(kFlimflamServiceName, kMonitorPropertyChanged, true);

  // Set the default device.
  client_->NotifyDefaultServicePropertyChange(kDeviceProperty, device_path);

  // IsConnected property change should not trigger the handler.
  client_->NotifyDefaultServicePropertyChange(kIsConnectedProperty, true);
  client_->NotifyDefaultServicePropertyChange(kIsConnectedProperty, false);
  EXPECT_EQ(default_device_.ifname, "eth0");

  // Service disconnection should trigger the handler.
  client_->NotifyManagerPropertyChange(kDefaultServiceProperty,
                                       dbus::ObjectPath("/"));
  EXPECT_EQ(default_device_.ifname, "");
}

TEST_F(ClientTest, DefaultServiceDeviceChangeCallsDefaultHandler) {
  // Add the devices.
  const dbus::ObjectPath eth0_path("/device/eth0"), wlan0_path("/device/wlan0"),
      eth0_service_path("service/0"), wlan0_service_path("/service/1");
  auto* eth0_device = client_->PreMakeDevice(eth0_path);
  auto* wlan0_device = client_->PreMakeDevice(wlan0_path);
  dbus::ObjectProxy::OnConnectedCallback eth0_callback, wlan0_callback;
  EXPECT_CALL(*eth0_device, DoRegisterPropertyChangedSignalHandler(_, _))
      .WillOnce(MovePointee<1>(&eth0_callback));
  EXPECT_CALL(*wlan0_device, DoRegisterPropertyChangedSignalHandler(_, _))
      .WillOnce(MovePointee<1>(&wlan0_callback));

  client_->NotifyManagerPropertyChange(
      kDevicesProperty, std::vector<dbus::ObjectPath>({eth0_path, wlan0_path}));

  brillo::VariantDictionary eth0_props, wlan0_props;
  eth0_props[kTypeProperty] = std::string(kTypeEthernet);
  eth0_props[kInterfaceProperty] = std::string("eth0");
  eth0_props[kSelectedServiceProperty] = eth0_service_path;
  EXPECT_CALL(*eth0_device, GetProperties(_, _, _))
      .WillOnce(DoAll(testing::SetArgPointee<0>(eth0_props), Return(true)));
  wlan0_props[kTypeProperty] = std::string(kTypeWifi);
  wlan0_props[kInterfaceProperty] = std::string("wlan0");
  wlan0_props[kSelectedServiceProperty] = wlan0_service_path;
  EXPECT_CALL(*wlan0_device, GetProperties(_, _, _))
      .WillOnce(DoAll(testing::SetArgPointee<0>(wlan0_props), Return(true)));

  std::move(eth0_callback)
      .Run(kFlimflamServiceName, kMonitorPropertyChanged, true);
  std::move(wlan0_callback)
      .Run(kFlimflamServiceName, kMonitorPropertyChanged, true);

  // Set up initial state.
  client_->NotifyDefaultServicePropertyChange(kDeviceProperty, eth0_path);
  client_->NotifyDefaultServicePropertyChange(kIsConnectedProperty, true);

  EXPECT_EQ(default_device_.ifname, "eth0");

  // Now trigger the default device change to wifi.
  client_->NotifyDefaultServicePropertyChange(kDeviceProperty, wlan0_path);

  EXPECT_EQ(default_device_.ifname, "wlan0");
}

TEST_F(ClientTest, DefaultServiceChangeAddsDefaultDeviceIfMissing) {
  // Normally, all physical devices are already known so when one becomes the
  // default it will only trigger the default device callback. But VPN devices
  // are (intentionally) not provided by shill and are therefore not tracked.
  // But this client will add VPN devices if they become the device associated
  // with the default service.
  // Note that this also verifies that if for some reason (odd-ball
  // synchronization) when the default device is discover, if it happens be to
  // unknown at the time, it will be added and tracked.
  const dbus::ObjectPath device_path("/device/ppp0");
  auto* mock_device = client_->PreMakeDevice(device_path);
  dbus::ObjectProxy::OnConnectedCallback device_callback;
  EXPECT_CALL(*mock_device, DoRegisterPropertyChangedSignalHandler(_, _))
      .WillOnce(MovePointee<1>(&device_callback));

  brillo::VariantDictionary device_props;
  device_props[kTypeProperty] = std::string(kTypePPP);
  device_props[kInterfaceProperty] = std::string("ppp0");
  EXPECT_CALL(*mock_device, GetProperties(_, _, _))
      .WillOnce(DoAll(testing::SetArgPointee<0>(device_props), Return(true)));

  // Trigger the state change.
  client_->NotifyDefaultServicePropertyChange(kIsConnectedProperty, true);
  client_->NotifyDefaultServicePropertyChange(kDeviceProperty, device_path);

  std::move(device_callback)
      .Run(kFlimflamServiceName, kMonitorPropertyChanged, true);

  EXPECT_EQ(devices_.size(), 1);
  EXPECT_TRUE(devices_.find("ppp0") != devices_.end());

  // This change should have also invoked the default device handler as well.
  EXPECT_EQ(default_device_.ifname, "ppp0");
}

TEST_F(ClientTest, DeviceAddedHandlerCalledOncePerNewDevice) {
  const dbus::ObjectPath device_path("/device/eth0");
  auto* mock_device = client_->PreMakeDevice(device_path);
  dbus::ObjectProxy::OnConnectedCallback callback;
  EXPECT_CALL(*mock_device, DoRegisterPropertyChangedSignalHandler(_, _))
      .WillOnce(MovePointee<1>(&callback));

  client_->NotifyManagerPropertyChange(
      kDevicesProperty, std::vector<dbus::ObjectPath>({device_path}));

  brillo::VariantDictionary props;
  props[kTypeProperty] = std::string(kTypeEthernet);
  props[kInterfaceProperty] = std::string("eth0");
  EXPECT_CALL(*mock_device, GetProperties(_, _, _))
      .WillOnce(DoAll(testing::SetArgPointee<0>(props), Return(true)));

  // Manually trigger the registration callback since that doesn't happen in the
  // mocks.
  std::move(callback).Run(kFlimflamServiceName, kMonitorPropertyChanged, true);
  EXPECT_EQ(devices_.size(), 1);
  EXPECT_TRUE(devices_.find("eth0") != devices_.end());

  // Attempt to add the same device, this should not trigger the creation of a
  // new proxy or property registration and the rest. If this logic fails and
  // the device is readded, the above expectation(s) will be oversaturated and
  // fail.
  devices_.clear();
  client_->NotifyManagerPropertyChange(
      kDevicesProperty, std::vector<dbus::ObjectPath>({device_path}));
  EXPECT_TRUE(devices_.empty());
}

TEST_F(ClientTest, DeviceAddedHandlerNotCalledIfInterfaceMissing) {
  const dbus::ObjectPath device_path("/device/eth0");
  auto* mock_device = client_->PreMakeDevice(device_path);
  dbus::ObjectProxy::OnConnectedCallback callback;
  EXPECT_CALL(*mock_device, DoRegisterPropertyChangedSignalHandler(_, _))
      .WillOnce(MovePointee<1>(&callback));

  client_->NotifyManagerPropertyChange(
      kDevicesProperty, std::vector<dbus::ObjectPath>({device_path}));

  brillo::VariantDictionary props;
  props[kTypeProperty] = std::string(kTypeEthernet);
  EXPECT_CALL(*mock_device, GetProperties(_, _, _))
      .WillOnce(DoAll(testing::SetArgPointee<0>(props), Return(true)));

  // Manually trigger the registration callback since that doesn't happen in the
  // mocks.
  std::move(callback).Run(kFlimflamServiceName, kMonitorPropertyChanged, true);
  EXPECT_TRUE(devices_.empty());
}

TEST_F(ClientTest, DeviceRemovedHandlerCalled) {
  // Add the device.
  const dbus::ObjectPath device_path("/device/eth0");
  auto* mock_device = client_->PreMakeDevice(device_path);
  dbus::ObjectProxy::OnConnectedCallback callback;
  EXPECT_CALL(*mock_device, DoRegisterPropertyChangedSignalHandler(_, _))
      .WillOnce(MovePointee<1>(&callback));

  client_->NotifyManagerPropertyChange(
      kDevicesProperty, std::vector<dbus::ObjectPath>({device_path}));

  brillo::VariantDictionary props;
  props[kTypeProperty] = std::string(kTypeEthernet);
  props[kInterfaceProperty] = std::string("eth0");
  EXPECT_CALL(*mock_device, GetProperties(_, _, _))
      .WillOnce(DoAll(testing::SetArgPointee<0>(props), Return(true)));

  // Manually trigger the registration callback since that doesn't happen in the
  // mocks.
  std::move(callback).Run(kFlimflamServiceName, kMonitorPropertyChanged, true);
  EXPECT_EQ(devices_.size(), 1);
  EXPECT_TRUE(devices_.find("eth0") != devices_.end());

  // Remove the device by updating the device list.
  client_->NotifyManagerPropertyChange(kDevicesProperty,
                                       std::vector<dbus::ObjectPath>({}));
  EXPECT_TRUE(devices_.empty());
}

TEST_F(ClientTest, DeviceHandlersCalledOnIPConfigChange) {
  // Set up 2 devices here to ensure the changes are captured correctly.
  const dbus::ObjectPath eth0_path("/device/eth0"), wlan0_path("/device/wlan0"),
      eth0_service_path("service/0"), wlan0_service_path("/service/1");
  auto* eth0_device = client_->PreMakeDevice(eth0_path);
  auto* wlan0_device = client_->PreMakeDevice(wlan0_path);
  dbus::ObjectProxy::OnConnectedCallback eth0_callback, wlan0_callback;
  EXPECT_CALL(*eth0_device, DoRegisterPropertyChangedSignalHandler(_, _))
      .WillOnce(MovePointee<1>(&eth0_callback));
  EXPECT_CALL(*wlan0_device, DoRegisterPropertyChangedSignalHandler(_, _))
      .WillOnce(MovePointee<1>(&wlan0_callback));

  client_->NotifyManagerPropertyChange(
      kDevicesProperty, std::vector<dbus::ObjectPath>({eth0_path, wlan0_path}));

  brillo::VariantDictionary eth0_props, wlan0_props;
  eth0_props[kTypeProperty] = std::string(kTypeEthernet);
  eth0_props[kInterfaceProperty] = std::string("eth0");
  eth0_props[kSelectedServiceProperty] = eth0_service_path;
  EXPECT_CALL(*eth0_device, GetProperties(_, _, _))
      .WillOnce(DoAll(testing::SetArgPointee<0>(eth0_props), Return(true)));
  wlan0_props[kTypeProperty] = std::string(kTypeWifi);
  wlan0_props[kInterfaceProperty] = std::string("wlan0");
  wlan0_props[kSelectedServiceProperty] = wlan0_service_path;
  EXPECT_CALL(*wlan0_device, GetProperties(_, _, _))
      .WillOnce(DoAll(testing::SetArgPointee<0>(wlan0_props), Return(true)));

  std::move(eth0_callback)
      .Run(kFlimflamServiceName, kMonitorPropertyChanged, true);
  std::move(wlan0_callback)
      .Run(kFlimflamServiceName, kMonitorPropertyChanged, true);

  // Set up initial state.
  client_->NotifyDefaultServicePropertyChange(kDeviceProperty, eth0_path);
  client_->NotifyDefaultServicePropertyChange(kIsConnectedProperty, true);

  // This test doesn't worry about parsing IPConfigs, only that the right
  // handler is called, so it doesn't matter what we send through here.
  last_device_changed_.clear();
  // First check the non-default device.
  client_->NotifyDevicePropertyChange("/device/wlan0", kIPConfigsProperty,
                                      brillo::Any());
  EXPECT_EQ(last_device_changed_, "wlan0");
  // Now the default. We're also going to verify the default device handler is
  // called next, so clear that state first as well.
  default_device_ = {};
  client_->NotifyDevicePropertyChange("/device/eth0", kIPConfigsProperty,
                                      brillo::Any());
  EXPECT_EQ(last_device_changed_, "eth0");
  EXPECT_EQ(default_device_.ifname, "eth0");
}

TEST_F(ClientTest, DeviceSelectedServiceConnectStateObtained) {
  const dbus::ObjectPath device_path("/device/eth0"),
      service_path("/service/1");
  auto* mock_device = client_->PreMakeDevice(device_path);
  auto* mock_service = client_->PreMakeService(service_path);
  dbus::ObjectProxy::OnConnectedCallback device_callback, service_callback;
  EXPECT_CALL(*mock_device, DoRegisterPropertyChangedSignalHandler(_, _))
      .WillOnce(MovePointee<1>(&device_callback));
  EXPECT_CALL(*mock_service, DoRegisterPropertyChangedSignalHandler(_, _))
      .WillOnce(MovePointee<1>(&service_callback));

  client_->NotifyManagerPropertyChange(
      kDevicesProperty, std::vector<dbus::ObjectPath>({device_path}));

  brillo::VariantDictionary device_props;
  device_props[kTypeProperty] = std::string(kTypeEthernet);
  device_props[kInterfaceProperty] = std::string("eth0");
  device_props[kSelectedServiceProperty] = service_path;
  EXPECT_CALL(*mock_device, GetProperties(_, _, _))
      .WillOnce(DoAll(testing::SetArgPointee<0>(device_props), Return(true)));

  brillo::VariantDictionary service_props;
  service_props[kStateProperty] = std::string(kStateOnline);
  EXPECT_CALL(*mock_service, GetProperties(_, _, _))
      .WillRepeatedly(
          DoAll(testing::SetArgPointee<0>(service_props), Return(true)));

  // Manually trigger the registration callback since that doesn't happen in the
  // mocks.
  std::move(device_callback)
      .Run(kFlimflamServiceName, kMonitorPropertyChanged, true);
  std::move(service_callback)
      .Run(kFlimflamServiceName, kMonitorPropertyChanged, true);
  EXPECT_EQ(devices_.size(), 1);
  const auto it = devices_.find("eth0");
  EXPECT_NE(it, devices_.end());
  EXPECT_EQ(it->second.state, Client::Device::ConnectionState::kOnline);
}

TEST_F(ClientTest, DeviceHandlersCalledOnSelectedServiceStateChange) {
  // Set up 2 devices here to ensure the changes are captured correctly.
  const dbus::ObjectPath eth0_path("/device/eth0"), wlan0_path("/device/wlan0"),
      eth0_service_path("/service/0"), wlan0_service_path("/service/1");
  auto* eth0_device = client_->PreMakeDevice(eth0_path);
  auto* wlan0_device = client_->PreMakeDevice(wlan0_path);
  auto* eth0_service = client_->PreMakeService(eth0_service_path);
  auto* wlan0_service = client_->PreMakeService(wlan0_service_path);
  dbus::ObjectProxy::OnConnectedCallback eth0_callback, wlan0_callback,
      eth0_service_callback, wlan0_service_callback;
  EXPECT_CALL(*eth0_device, DoRegisterPropertyChangedSignalHandler(_, _))
      .WillOnce(MovePointee<1>(&eth0_callback));
  EXPECT_CALL(*wlan0_device, DoRegisterPropertyChangedSignalHandler(_, _))
      .WillOnce(MovePointee<1>(&wlan0_callback));
  EXPECT_CALL(*eth0_service, DoRegisterPropertyChangedSignalHandler(_, _))
      .WillOnce(MovePointee<1>(&eth0_service_callback));
  EXPECT_CALL(*wlan0_service, DoRegisterPropertyChangedSignalHandler(_, _))
      .WillOnce(MovePointee<1>(&wlan0_service_callback));

  client_->NotifyManagerPropertyChange(
      kDevicesProperty, std::vector<dbus::ObjectPath>({eth0_path, wlan0_path}));

  brillo::VariantDictionary eth0_props, wlan0_props;
  eth0_props[kTypeProperty] = std::string(kTypeEthernet);
  eth0_props[kInterfaceProperty] = std::string("eth0");
  eth0_props[kSelectedServiceProperty] = eth0_service_path;
  EXPECT_CALL(*eth0_device, GetProperties(_, _, _))
      .WillOnce(DoAll(testing::SetArgPointee<0>(eth0_props), Return(true)));
  wlan0_props[kTypeProperty] = std::string(kTypeWifi);
  wlan0_props[kInterfaceProperty] = std::string("wlan0");
  wlan0_props[kSelectedServiceProperty] = wlan0_service_path;
  EXPECT_CALL(*wlan0_device, GetProperties(_, _, _))
      .WillOnce(DoAll(testing::SetArgPointee<0>(wlan0_props), Return(true)));

  brillo::VariantDictionary service_props;
  service_props[kStateProperty] = std::string(kStateOnline);
  EXPECT_CALL(*eth0_service, GetProperties(_, _, _))
      .WillRepeatedly(
          DoAll(testing::SetArgPointee<0>(service_props), Return(true)));
  EXPECT_CALL(*wlan0_service, GetProperties(_, _, _))
      .WillRepeatedly(
          DoAll(testing::SetArgPointee<0>(service_props), Return(true)));

  std::move(eth0_callback)
      .Run(kFlimflamServiceName, kMonitorPropertyChanged, true);
  std::move(wlan0_callback)
      .Run(kFlimflamServiceName, kMonitorPropertyChanged, true);
  std::move(eth0_service_callback)
      .Run(kFlimflamServiceName, kMonitorPropertyChanged, true);
  std::move(wlan0_service_callback)
      .Run(kFlimflamServiceName, kMonitorPropertyChanged, true);

  // Set up initial state.
  client_->NotifyDefaultServicePropertyChange(kDeviceProperty, eth0_path);
  client_->NotifyDefaultServicePropertyChange(kIsConnectedProperty, true);

  last_device_changed_.clear();
  // First check the non-default device.
  client_->NotifyServicePropertyChange("/device/wlan0", kStateProperty,
                                       kStateFailure);
  EXPECT_EQ(last_device_changed_, "wlan0");
  EXPECT_EQ(last_device_cxn_state_, Client::Device::ConnectionState::kFailure);

  // Now the default. We're also going to verify the default device handler is
  // called next, so clear that state first as well.
  default_device_ = {};
  client_->NotifyServicePropertyChange("/device/eth0", kStateProperty,
                                       kStateReady);
  EXPECT_EQ(last_device_changed_, "eth0");
  EXPECT_EQ(last_device_cxn_state_, Client::Device::ConnectionState::kReady);
  EXPECT_EQ(default_device_.state, Client::Device::ConnectionState::kReady);
  EXPECT_EQ(default_device_.ifname, "eth0");
}

TEST_F(ClientTest, DeviceHandlersCalledOnSelectedServiceChange) {
  const dbus::ObjectPath wlan0_path("/device/wlan0"),
      service0_path("/service/0"), service1_path("/service/1");
  auto* wlan0_device = client_->PreMakeDevice(wlan0_path);
  auto* service0 = client_->PreMakeService(service0_path);
  auto* service1 = client_->PreMakeService(service1_path);
  dbus::ObjectProxy::OnConnectedCallback wlan0_callback, service0_callback,
      service1_callback;
  EXPECT_CALL(*wlan0_device, DoRegisterPropertyChangedSignalHandler(_, _))
      .WillOnce(MovePointee<1>(&wlan0_callback));
  EXPECT_CALL(*service0, DoRegisterPropertyChangedSignalHandler(_, _))
      .WillOnce(MovePointee<1>(&service0_callback));
  EXPECT_CALL(*service1, DoRegisterPropertyChangedSignalHandler(_, _))
      .WillOnce(MovePointee<1>(&service1_callback));

  client_->NotifyManagerPropertyChange(
      kDevicesProperty, std::vector<dbus::ObjectPath>({wlan0_path}));

  brillo::VariantDictionary wlan0_props;
  wlan0_props[kTypeProperty] = std::string(kTypeWifi);
  wlan0_props[kInterfaceProperty] = std::string("wlan0");
  wlan0_props[kSelectedServiceProperty] = service0_path;
  EXPECT_CALL(*wlan0_device, GetProperties(_, _, _))
      .WillOnce(DoAll(testing::SetArgPointee<0>(wlan0_props), Return(true)));

  brillo::VariantDictionary service_props;
  service_props[kStateProperty] = std::string(kStateOnline);
  EXPECT_CALL(*service0, GetProperties(_, _, _))
      .WillRepeatedly(
          DoAll(testing::SetArgPointee<0>(service_props), Return(true)));
  EXPECT_CALL(*service1, GetProperties(_, _, _))
      .WillRepeatedly(
          DoAll(testing::SetArgPointee<0>(service_props), Return(true)));

  std::move(wlan0_callback)
      .Run(kFlimflamServiceName, kMonitorPropertyChanged, true);
  std::move(service0_callback)
      .Run(kFlimflamServiceName, kMonitorPropertyChanged, true);
  // Set up initial state.
  client_->NotifyDefaultServicePropertyChange(kDeviceProperty, wlan0_path);
  client_->NotifyDefaultServicePropertyChange(kIsConnectedProperty, true);

  last_device_changed_.clear();
  client_->NotifyDevicePropertyChange("/device/wlan0", kSelectedServiceProperty,
                                      service1_path);
  std::move(service1_callback)
      .Run(kFlimflamServiceName, kMonitorPropertyChanged, true);

  EXPECT_EQ(last_device_changed_, "wlan0");
}

TEST_F(ClientTest, ManagerPropertyAccessor) {
  brillo::Any bar("bar");
  EXPECT_CALL(*client_->manager(), SetProperty(StrEq("foo"), bar, _, -1));
  EXPECT_CALL(*client_->manager(), SetProperty(StrEq("foo"), bar, _, 10));
  EXPECT_CALL(*client_->manager(),
              SetPropertyAsync(StrEq("foo"), bar, _, _, -1));
  EXPECT_CALL(*client_->manager(),
              SetPropertyAsync(StrEq("foo"), bar, _, _, 10));
  EXPECT_CALL(*client_->manager(), DoRegisterPropertyChangedSignalHandler(_, _))
      .Times(2);

  auto props = client_->ManagerProperties();
  props->Set("foo", "bar", nullptr);
  props->Set("foo", "bar", base::DoNothing(), base::DoNothing());

  props = client_->ManagerProperties(base::Milliseconds(10));
  props->Set("foo", "bar", nullptr);
  props->Set("foo", "bar", base::DoNothing(), base::DoNothing());
}

TEST_F(ClientTest, DefaultServicePropertyAccessor) {
  brillo::Any bar("bar");
  EXPECT_CALL(*client_->default_service(),
              SetProperty(StrEq("foo"), bar, _, -1));
  EXPECT_CALL(*client_->default_service(),
              SetProperty(StrEq("foo"), bar, _, 10));
  EXPECT_CALL(*client_->default_service(),
              SetPropertyAsync(StrEq("foo"), bar, _, _, -1));
  EXPECT_CALL(*client_->default_service(),
              SetPropertyAsync(StrEq("foo"), bar, _, _, 10));
  EXPECT_CALL(*client_->default_service(),
              DoRegisterPropertyChangedSignalHandler(_, _))
      .Times(2);

  auto props = client_->DefaultServicePropertyAccessor();
  props->Set("foo", "bar", nullptr);
  props->Set("foo", "bar", base::DoNothing(),
             base::BindRepeating([](brillo::Error*) {}));

  props = client_->DefaultServicePropertyAccessor(base::Milliseconds(10));
  props->Set("foo", "bar", nullptr);
  props->Set("foo", "bar", base::DoNothing(),
             base::BindRepeating([](brillo::Error*) {}));
}

TEST_F(ClientTest, GetDefaultServiceProperties) {
  brillo::VariantDictionary service_props;

  // No property in the dictionary
  EXPECT_CALL(*client_->default_service(), GetProperties(_, _, _))
      .WillRepeatedly(
          DoAll(testing::SetArgPointee<0>(service_props), Return(true)));

  std::unique_ptr<brillo::VariantDictionary> props1 =
      client_->GetDefaultServiceProperties();
  EXPECT_TRUE(props1 != nullptr);
  EXPECT_EQ(brillo::GetVariantValueOrDefault<bool>(*props1, kMeteredProperty),
            false);

  // Property in the dictionary
  service_props[kMeteredProperty] = true;

  EXPECT_CALL(*client_->default_service(), GetProperties(_, _, _))
      .WillRepeatedly(
          DoAll(testing::SetArgPointee<0>(service_props), Return(true)));

  std::unique_ptr<brillo::VariantDictionary> props2 =
      client_->GetDefaultServiceProperties();
  EXPECT_TRUE(props2 != nullptr);
  EXPECT_EQ(brillo::GetVariantValueOrDefault<bool>(*props2, kMeteredProperty),
            true);
}

TEST_F(ClientTest, DefaultDeviceReturnsCorrectDeviceForVPN) {
  dbus::ObjectPath service0_path("/service/0"), service1_path("/service/1"),
      device0_path("/dev/0"), device1_path("/dev/1");
  brillo::VariantDictionary mgr_props;
  mgr_props[kServicesProperty] =
      std::vector<dbus::ObjectPath>({service0_path, service1_path});
  EXPECT_CALL(*client_->manager(), GetProperties(_, _, _))
      .WillRepeatedly(
          DoAll(testing::SetArgPointee<0>(mgr_props), Return(true)));

  auto* service0 = client_->PreMakeService(service0_path);
  brillo::VariantDictionary service0_props;
  service0_props[kTypeProperty] = std::string(kTypeVPN);
  service0_props[kStateProperty] = std::string(kStateOnline);
  service0_props[kDeviceProperty] = device0_path;
  EXPECT_CALL(*service0, GetProperties(_, _, _))
      .WillRepeatedly(
          DoAll(testing::SetArgPointee<0>(service0_props), Return(true)));

  auto* device0 = client_->PreMakeDevice(device0_path);
  brillo::VariantDictionary device0_props;
  device0_props[kTypeProperty] = std::string(kTypePPP);
  device0_props[kInterfaceProperty] = std::string("ppp0");
  EXPECT_CALL(*device0, GetProperties(_, _, _))
      .WillRepeatedly(
          DoAll(testing::SetArgPointee<0>(device0_props), Return(true)));

  auto dev = client_->DefaultDevice(false /*exclude_vpn*/);
  EXPECT_TRUE(dev);
  EXPECT_EQ(dev->ifname, "ppp0");
  EXPECT_EQ(dev->type, Client::Device::Type::kPPP);
  EXPECT_EQ(dev->state, Client::Device::ConnectionState::kOnline);
}

TEST_F(ClientTest, DefaultDeviceReturnsCorrectDeviceExcludingVPN) {
  dbus::ObjectPath service0_path("/service/0"), service1_path("/service/1"),
      device0_path("/dev/0"), device1_path("/dev/1");
  brillo::VariantDictionary mgr_props;
  mgr_props[kServicesProperty] =
      std::vector<dbus::ObjectPath>({service0_path, service1_path});
  EXPECT_CALL(*client_->manager(), GetProperties(_, _, _))
      .WillRepeatedly(
          DoAll(testing::SetArgPointee<0>(mgr_props), Return(true)));

  auto* service0 = client_->PreMakeService(service0_path);
  brillo::VariantDictionary service0_props;
  service0_props[kTypeProperty] = std::string(kTypeVPN);
  service0_props[kStateProperty] = std::string(kStateOnline);
  service0_props[kDeviceProperty] = device0_path;
  EXPECT_CALL(*service0, GetProperties(_, _, _))
      .WillRepeatedly(
          DoAll(testing::SetArgPointee<0>(service0_props), Return(true)));

  auto* service1 = client_->PreMakeService(service1_path);
  brillo::VariantDictionary service1_props;
  service1_props[kTypeProperty] = std::string(kTypeWifi);
  service1_props[kStateProperty] = std::string(kStateOnline);
  service1_props[kDeviceProperty] = device1_path;
  EXPECT_CALL(*service1, GetProperties(_, _, _))
      .WillRepeatedly(
          DoAll(testing::SetArgPointee<0>(service1_props), Return(true)));

  auto* device1 = client_->PreMakeDevice(device1_path);
  brillo::VariantDictionary device1_props;
  device1_props[kTypeProperty] = std::string(kTypeWifi);
  device1_props[kInterfaceProperty] = std::string("wlan0");
  EXPECT_CALL(*device1, GetProperties(_, _, _))
      .WillRepeatedly(
          DoAll(testing::SetArgPointee<0>(device1_props), Return(true)));

  auto dev = client_->DefaultDevice(true /*exclude_vpn*/);
  EXPECT_TRUE(dev);
  EXPECT_EQ(dev->ifname, "wlan0");
  EXPECT_EQ(dev->type, Client::Device::Type::kWifi);
  EXPECT_EQ(dev->state, Client::Device::ConnectionState::kOnline);
}

}  // namespace
}  // namespace shill

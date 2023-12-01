// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/cellular/modem_info.h"

#include <memory>
#include <utility>

#include <ModemManager/ModemManager.h>
#include <chromeos/dbus/service_constants.h>
#include <gtest/gtest.h>

#include "shill/cellular/mock_dbus_objectmanager_proxy.h"
#include "shill/cellular/modem.h"
#include "shill/manager.h"
#include "shill/mock_control.h"
#include "shill/mock_manager.h"
#include "shill/mock_metrics.h"
#include "shill/test_event_dispatcher.h"

#include <base/check.h>
#include <base/containers/contains.h>

using testing::_;
using testing::Invoke;
using testing::Test;
using testing::WithArg;

namespace shill {

namespace {
const RpcIdentifier kModemPath =
    RpcIdentifier("/org/freedesktop/ModemManager1/Modem/0");
}

class ControlForTest : public MockControl {
 public:
  ControlForTest() : MockControl() {
    mock_proxy_ = std::make_unique<MockDBusObjectManagerProxy>();
    mock_proxy_->IgnoreSetCallbacks();

    weak_mock_proxy_ = mock_proxy_.get();

    ON_CALL(*this, CreateDBusObjectManagerProxy(_, _, _, _))
        .WillByDefault(Invoke(this, &ControlForTest::CreateProxyDelegate));
  }

  std::unique_ptr<DBusObjectManagerProxyInterface> CreateProxyDelegate(
      const RpcIdentifier& path,
      const std::string& service,
      const base::RepeatingClosure& service_appeared_callback,
      const base::RepeatingClosure& service_vanished_callback) {
    service_appeared_callback_ = service_appeared_callback;
    service_vanished_callback_ = service_vanished_callback;
    DCHECK(mock_proxy_);
    return std::move(mock_proxy_);
  }

  void StartService() { service_appeared_callback_.Run(); }

  void StopService() { service_vanished_callback_.Run(); }

  MockDBusObjectManagerProxy* GetMockProxy() { return weak_mock_proxy_; }

 private:
  std::unique_ptr<MockDBusObjectManagerProxy> mock_proxy_;
  MockDBusObjectManagerProxy* weak_mock_proxy_;

  base::RepeatingClosure service_appeared_callback_;
  base::RepeatingClosure service_vanished_callback_;
};

class ModemInfoForTest : public ModemInfo {
 public:
  ModemInfoForTest(ControlInterface* control, Manager* manager)
      : ModemInfo(control, manager) {}

  std::unique_ptr<Modem> CreateModem(
      const RpcIdentifier& path,
      const InterfaceToProperties& properties) override {
    return std::make_unique<Modem>(modemmanager::kModemManager1ServiceName,
                                   path, manager()->device_info());
  }
};

class ModemInfoTest : public Test {
 public:
  ModemInfoTest()
      : manager_(&control_interface_, &dispatcher_, &metrics_),
        modem_info_(&control_interface_, &manager_) {}

 protected:
  void Connect(const ObjectsWithProperties& expected_objects) {
    ManagedObjectsCallback get_managed_objects_callback;
    EXPECT_CALL(*control_interface_.GetMockProxy(), GetManagedObjects(_))
        .WillOnce(WithArg<0>([&get_managed_objects_callback](auto cb) {
          get_managed_objects_callback = std::move(cb);
        }));

    modem_info_.Start();
    modem_info_.Connect();
    std::move(get_managed_objects_callback).Run(expected_objects, Error());
  }

  ObjectsWithProperties GetModemWithProperties() {
    KeyValueStore o_fd_mm1_modem;

    InterfaceToProperties properties;
    properties[MM_DBUS_INTERFACE_MODEM] = o_fd_mm1_modem;

    ObjectsWithProperties objects_with_properties;
    objects_with_properties[kModemPath] = properties;

    return objects_with_properties;
  }

  ControlForTest control_interface_;
  EventDispatcherForTest dispatcher_;
  MockMetrics metrics_;
  MockManager manager_;
  ModemInfoForTest modem_info_;
};

TEST_F(ModemInfoTest, ConnectDisconnect) {
  modem_info_.Start();
  EXPECT_FALSE(modem_info_.service_connected_);

  modem_info_.Connect();
  EXPECT_TRUE(modem_info_.service_connected_);
  EXPECT_EQ(0, modem_info_.modems_.size());

  modem_info_.AddModem(kModemPath, InterfaceToProperties());
  EXPECT_EQ(1, modem_info_.modems_.size());

  modem_info_.Disconnect();
  EXPECT_FALSE(modem_info_.service_connected_);
  EXPECT_EQ(0, modem_info_.modems_.size());
}

TEST_F(ModemInfoTest, AddRemoveModem) {
  modem_info_.Start();
  modem_info_.Connect();
  EXPECT_FALSE(modem_info_.ModemExists(kModemPath));

  // Remove non-existent modem path.
  modem_info_.RemoveModem(kModemPath);
  EXPECT_FALSE(modem_info_.ModemExists(kModemPath));

  modem_info_.AddModem(kModemPath, InterfaceToProperties());
  EXPECT_TRUE(modem_info_.ModemExists(kModemPath));

  // Add an already added modem.
  modem_info_.AddModem(kModemPath, InterfaceToProperties());
  EXPECT_TRUE(modem_info_.ModemExists(kModemPath));

  modem_info_.RemoveModem(kModemPath);
  EXPECT_FALSE(modem_info_.ModemExists(kModemPath));

  // Remove an already removed modem path.
  modem_info_.RemoveModem(kModemPath);
  EXPECT_FALSE(modem_info_.ModemExists(kModemPath));
}

TEST_F(ModemInfoTest, StartStop) {
  modem_info_.Start();
  EXPECT_NE(nullptr, modem_info_.proxy_);

  modem_info_.Stop();
  EXPECT_EQ(nullptr, modem_info_.proxy_);
}

TEST_F(ModemInfoTest, Connect) {
  Connect(GetModemWithProperties());
  EXPECT_EQ(1, modem_info_.modems_.size());
  EXPECT_TRUE(base::Contains(modem_info_.modems_, kModemPath));
}

TEST_F(ModemInfoTest, AddRemoveInterfaces) {
  // Have nothing come back from GetManagedObjects.
  Connect(ObjectsWithProperties());
  EXPECT_EQ(0, modem_info_.modems_.size());

  // Add an object that doesn't have a modem interface.  Nothing should be added
  modem_info_.OnInterfacesAddedSignal(kModemPath, InterfaceToProperties());
  EXPECT_EQ(0, modem_info_.modems_.size());

  // Actually add a modem
  modem_info_.OnInterfacesAddedSignal(kModemPath,
                                      GetModemWithProperties()[kModemPath]);
  EXPECT_EQ(1, modem_info_.modems_.size());

  // Remove an irrelevant interface
  modem_info_.OnInterfacesRemovedSignal(kModemPath, {"not.a.modem.interface"});
  EXPECT_EQ(1, modem_info_.modems_.size());

  // Remove the modem
  modem_info_.OnInterfacesRemovedSignal(kModemPath, {MM_DBUS_INTERFACE_MODEM});
  EXPECT_EQ(0, modem_info_.modems_.size());
}

TEST_F(ModemInfoTest, ModemManagerDown) {
  modem_info_.Start();

  MockDBusObjectManagerProxy* proxy = control_interface_.GetMockProxy();
  ManagedObjectsCallback get_managed_objects_callback;
  EXPECT_CALL(*proxy, GetManagedObjects(_))
      .WillOnce(WithArg<0>([&get_managed_objects_callback](auto cb) {
        get_managed_objects_callback = std::move(cb);
      }));

  control_interface_.StartService();
  std::move(get_managed_objects_callback)
      .Run(ObjectsWithProperties(),
           Error(Error::kInternalError, "Whoops!", FROM_HERE));

  EXPECT_TRUE(modem_info_.service_connected_);
  EXPECT_EQ(0, modem_info_.modems_.size());
}

TEST_F(ModemInfoTest, RestartModemManager) {
  Connect(GetModemWithProperties());
  EXPECT_EQ(1, modem_info_.modems_.size());

  // Simulate ModemManager crashing and coming back/stopping and restarting/etc.
  control_interface_.StopService();
  EXPECT_FALSE(modem_info_.service_connected_);

  MockDBusObjectManagerProxy* proxy = control_interface_.GetMockProxy();
  ManagedObjectsCallback get_managed_objects_callback;
  EXPECT_CALL(*proxy, GetManagedObjects(_))
      .WillOnce(WithArg<0>([&get_managed_objects_callback](auto cb) {
        get_managed_objects_callback = std::move(cb);
      }));

  control_interface_.StartService();
  std::move(get_managed_objects_callback)
      .Run(GetModemWithProperties(), Error());

  EXPECT_TRUE(modem_info_.service_connected_);
  EXPECT_EQ(1, modem_info_.modems_.size());
}

}  // namespace shill

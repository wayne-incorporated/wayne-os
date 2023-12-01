// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "lorgnette/firewall_manager.h"

#include <cstdint>
#include <cstdlib>
#include <memory>
#include <new>
#include <string>
#include <utility>

#include <base/functional/callback.h>
#include <base/memory/scoped_refptr.h>
#include <brillo/errors/error.h>
#include <dbus/mock_object_proxy.h>
#include <dbus/object_proxy.h>
#include <dbus/permission_broker/dbus-constants.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "permission_broker/dbus-proxy-mocks.h"

using testing::_;
using testing::DoAll;
using testing::Invoke;
using testing::Return;
using testing::SetArgPointee;
using testing::WithArg;

namespace lorgnette {

namespace {

// Test interface for FirewallManager to request port access on.
constexpr char kTestInterface[] = "Test Interface";
// Well-known port for Canon scanners.
constexpr uint16_t kCanonBjnpPort = 8612;
// Test ports to request access for.
constexpr uint16_t kFirstUpdPort = 4311;
constexpr uint16_t kSecondUpdPort = 4312;

}  // namespace

class FirewallManagerTest : public testing::Test {
 protected:
  FirewallManagerTest() = default;

  void SetUp() override {
    raw_permission_broker_proxy_mock_ = static_cast<
        testing::StrictMock<org::chromium::PermissionBrokerProxyMock>*>(
        permission_broker_proxy_mock_.get());
  }

  void InitFirewallManager() {
    scoped_refptr<dbus::MockObjectProxy> mock_proxy_ =
        base::MakeRefCounted<dbus::MockObjectProxy>(
            /*bus=*/nullptr, permission_broker::kPermissionBrokerServiceName,
            dbus::ObjectPath(permission_broker::kPermissionBrokerServicePath));
    EXPECT_CALL(*raw_permission_broker_proxy_mock_, GetObjectProxy())
        .Times(2)
        .WillRepeatedly(Return(mock_proxy_.get()));
    // Save the callbacks so they can be run later if a test requires it.
    EXPECT_CALL(*mock_proxy_, DoWaitForServiceToBeAvailable(_))
        .WillOnce(WithArg<0>(Invoke(
            [this](dbus::ObjectProxy::WaitForServiceToBeAvailableCallback*
                       callback) {
              wait_for_service_to_be_available_callback_ = std::move(*callback);
            })));
    EXPECT_CALL(*mock_proxy_, SetNameOwnerChangedCallback(_))
        .WillOnce(WithArg<0>(Invoke(
            [this](
                const dbus::ObjectProxy::NameOwnerChangedCallback& callback) {
              set_name_owner_change_callback_ = callback;
            })));
    firewall_manager_.Init(std::move(permission_broker_proxy_mock_));
  }

  void RunWaitForServiceToBeAvailableCallback(bool service_available) {
    std::move(wait_for_service_to_be_available_callback_)
        .Run(service_available);
  }

  void RunSetNameOwnerChangedCallback(const std::string& old_owner,
                                      const std::string& new_owner) {
    set_name_owner_change_callback_.Run(old_owner, new_owner);
  }

  FirewallManager* firewall_manager() { return &firewall_manager_; }

  org::chromium::PermissionBrokerProxyMock* permission_broker_proxy_mock()
      const {
    return raw_permission_broker_proxy_mock_;
  }

 private:
  // Ownership of `permission_broker_proxy_mock_` is transferred to
  // `firewall_manager_` if `InitFirewallManager()` is called.
  std::unique_ptr<org::chromium::PermissionBrokerProxyInterface>
      permission_broker_proxy_mock_ = std::make_unique<
          testing::StrictMock<org::chromium::PermissionBrokerProxyMock>>();
  // Allows tests to access the PermissionBrokerProxyMock if ownership of
  // `permission_broker_proxy_mock_` has been transferred.
  testing::StrictMock<org::chromium::PermissionBrokerProxyMock>*
      raw_permission_broker_proxy_mock_ = nullptr;
  FirewallManager firewall_manager_{kTestInterface};
  dbus::ObjectProxy::WaitForServiceToBeAvailableCallback
      wait_for_service_to_be_available_callback_;
  dbus::ObjectProxy::NameOwnerChangedCallback set_name_owner_change_callback_;
};

// Test that FirewallManager can request access for all well-known PIXMA scanner
// ports.
TEST_F(FirewallManagerTest, RequestPixmaPortAccess) {
  InitFirewallManager();

  EXPECT_CALL(*permission_broker_proxy_mock(),
              RequestUdpPortAccess(kCanonBjnpPort, kTestInterface, _, _, _,
                                   dbus::ObjectProxy::TIMEOUT_USE_DEFAULT))
      .WillOnce(DoAll(SetArgPointee<3>(true), Return(true)));

  PortToken pixma_token = firewall_manager()->RequestPixmaPortAccess();

  // FirewallManager should request to release the associated port when
  // `pixma_token` is destroyed.
  EXPECT_CALL(*permission_broker_proxy_mock(),
              ReleaseUdpPort(kCanonBjnpPort, kTestInterface, _, _,
                             dbus::ObjectProxy::TIMEOUT_USE_DEFAULT))
      .WillOnce(DoAll(SetArgPointee<2>(true), Return(true)));
}

// Test that FirewallManager can request access for a specific port.
TEST_F(FirewallManagerTest, RequestUdpPortAccess) {
  InitFirewallManager();

  EXPECT_CALL(*permission_broker_proxy_mock(),
              RequestUdpPortAccess(kFirstUpdPort, kTestInterface, _, _, _,
                                   dbus::ObjectProxy::TIMEOUT_USE_DEFAULT))
      .WillOnce(DoAll(SetArgPointee<3>(true), Return(true)));

  PortToken udp_token = firewall_manager()->RequestUdpPortAccess(kFirstUpdPort);

  // FirewallManager should request to release the associated port when
  // `udp_token` is destroyed.
  EXPECT_CALL(*permission_broker_proxy_mock(),
              ReleaseUdpPort(kFirstUpdPort, kTestInterface, _, _,
                             dbus::ObjectProxy::TIMEOUT_USE_DEFAULT))
      .WillOnce(DoAll(SetArgPointee<2>(true), Return(true)));
}

// Test that FirewallManager handles PermissionBroker denying a port access
// request.
TEST_F(FirewallManagerTest, PortAccessRequestDenied) {
  InitFirewallManager();

  EXPECT_CALL(*permission_broker_proxy_mock(),
              RequestUdpPortAccess(kFirstUpdPort, kTestInterface, _, _, _,
                                   dbus::ObjectProxy::TIMEOUT_USE_DEFAULT))
      .WillOnce(DoAll(SetArgPointee<3>(false), Return(true)));

  PortToken udp_token = firewall_manager()->RequestUdpPortAccess(kFirstUpdPort);

  // With PermissionBroker denying the port access request, we should not see
  // FirewallManager sending a request to release the port when `udp_token` is
  // destroyed.
}

// Test that FirewallManager handles PermissionBroker not responding to a port
// access request.
TEST_F(FirewallManagerTest, NoResponseToPortAccessRequest) {
  InitFirewallManager();

  EXPECT_CALL(*permission_broker_proxy_mock(),
              RequestUdpPortAccess(kFirstUpdPort, kTestInterface, _, _, _,
                                   dbus::ObjectProxy::TIMEOUT_USE_DEFAULT))
      .WillOnce(DoAll(WithArg<4>(Invoke([](brillo::ErrorPtr* error) {
                        *error = brillo::Error::Create(
                            base::Location(), "Domain", "Code", "Message");
                      })),
                      Return(false)));

  PortToken udp_token = firewall_manager()->RequestUdpPortAccess(kFirstUpdPort);

  // With PermissionBroker not responding to the port access request, we should
  // not see FirewallManager sending a request to release the port when
  // `udp_token` is destroyed.
}

// Test that FirewallManager handles PermissionBroker denying a port release
// request.
TEST_F(FirewallManagerTest, PortReleaseRequestDenied) {
  InitFirewallManager();

  EXPECT_CALL(*permission_broker_proxy_mock(),
              RequestUdpPortAccess(kFirstUpdPort, kTestInterface, _, _, _,
                                   dbus::ObjectProxy::TIMEOUT_USE_DEFAULT))
      .WillOnce(DoAll(SetArgPointee<3>(true), Return(true)));

  PortToken udp_token = firewall_manager()->RequestUdpPortAccess(kFirstUpdPort);

  // FirewallManager should request to release the associated port when
  // `udp_token` is destroyed.
  EXPECT_CALL(*permission_broker_proxy_mock(),
              ReleaseUdpPort(kFirstUpdPort, kTestInterface, _, _,
                             dbus::ObjectProxy::TIMEOUT_USE_DEFAULT))
      .WillOnce(DoAll(SetArgPointee<2>(false), Return(true)));
}

// Test that FirewallManager handles PermissionBroker not responding to a port
// release request.
TEST_F(FirewallManagerTest, NoResponseToPortReleaseRequest) {
  InitFirewallManager();

  EXPECT_CALL(*permission_broker_proxy_mock(),
              RequestUdpPortAccess(kFirstUpdPort, kTestInterface, _, _, _,
                                   dbus::ObjectProxy::TIMEOUT_USE_DEFAULT))
      .WillOnce(DoAll(SetArgPointee<3>(true), Return(true)));

  PortToken udp_token = firewall_manager()->RequestUdpPortAccess(kFirstUpdPort);

  // FirewallManager should request to release the associated port when
  // `udp_token` is destroyed.
  EXPECT_CALL(*permission_broker_proxy_mock(),
              ReleaseUdpPort(kFirstUpdPort, kTestInterface, _, _,
                             dbus::ObjectProxy::TIMEOUT_USE_DEFAULT))
      .WillOnce(DoAll(WithArg<3>(Invoke([](brillo::ErrorPtr* error) {
                        *error = brillo::Error::Create(
                            base::Location(), "Domain", "Code", "Message");
                      })),
                      Return(false)));
}

// Test that ports can be requested before FirewallManager is initialized.
TEST_F(FirewallManagerTest, RequestPortsBeforeInitialization) {
  PortToken first_token =
      firewall_manager()->RequestUdpPortAccess(kFirstUpdPort);
  PortToken second_token =
      firewall_manager()->RequestUdpPortAccess(kSecondUpdPort);

  InitFirewallManager();

  // FirewallManager should have queued the requested ports, and upon connecting
  // to PermissionBroker FirewallManager should immediately request access for
  // the ports.
  EXPECT_CALL(*permission_broker_proxy_mock(),
              RequestUdpPortAccess(kFirstUpdPort, kTestInterface, _, _, _,
                                   dbus::ObjectProxy::TIMEOUT_USE_DEFAULT))
      .WillOnce(DoAll(SetArgPointee<3>(true), Return(true)));
  EXPECT_CALL(*permission_broker_proxy_mock(),
              RequestUdpPortAccess(kSecondUpdPort, kTestInterface, _, _, _,
                                   dbus::ObjectProxy::TIMEOUT_USE_DEFAULT))
      .WillOnce(DoAll(SetArgPointee<3>(true), Return(true)));

  RunWaitForServiceToBeAvailableCallback(/*service_available=*/true);

  // FirewallManager should request to release the associated ports when the
  // tokens are destroyed.
  EXPECT_CALL(*permission_broker_proxy_mock(),
              ReleaseUdpPort(kFirstUpdPort, kTestInterface, _, _,
                             dbus::ObjectProxy::TIMEOUT_USE_DEFAULT))
      .WillOnce(DoAll(SetArgPointee<2>(true), Return(true)));
  EXPECT_CALL(*permission_broker_proxy_mock(),
              ReleaseUdpPort(kSecondUpdPort, kTestInterface, _, _,
                             dbus::ObjectProxy::TIMEOUT_USE_DEFAULT))
      .WillOnce(DoAll(SetArgPointee<2>(true), Return(true)));
}

// Test that a service name change by PermissionBroker results in re-requesting
// port access.
TEST_F(FirewallManagerTest, ReRequestPortsAfterServiceNameChange) {
  InitFirewallManager();

  EXPECT_CALL(*permission_broker_proxy_mock(),
              RequestUdpPortAccess(kFirstUpdPort, kTestInterface, _, _, _,
                                   dbus::ObjectProxy::TIMEOUT_USE_DEFAULT))
      .Times(2)
      .WillRepeatedly(DoAll(SetArgPointee<3>(true), Return(true)));
  EXPECT_CALL(*permission_broker_proxy_mock(),
              RequestUdpPortAccess(kSecondUpdPort, kTestInterface, _, _, _,
                                   dbus::ObjectProxy::TIMEOUT_USE_DEFAULT))
      .Times(2)
      .WillRepeatedly(DoAll(SetArgPointee<3>(true), Return(true)));

  PortToken first_token =
      firewall_manager()->RequestUdpPortAccess(kFirstUpdPort);
  PortToken second_token =
      firewall_manager()->RequestUdpPortAccess(kSecondUpdPort);

  RunSetNameOwnerChangedCallback("Old owner", "New owner");

  // FirewallManager should request to release the associated ports when the
  // tokens are destroyed.
  EXPECT_CALL(*permission_broker_proxy_mock(),
              ReleaseUdpPort(kFirstUpdPort, kTestInterface, _, _,
                             dbus::ObjectProxy::TIMEOUT_USE_DEFAULT))
      .WillOnce(DoAll(SetArgPointee<2>(true), Return(true)));
  EXPECT_CALL(*permission_broker_proxy_mock(),
              ReleaseUdpPort(kSecondUpdPort, kTestInterface, _, _,
                             dbus::ObjectProxy::TIMEOUT_USE_DEFAULT))
      .WillOnce(DoAll(SetArgPointee<2>(true), Return(true)));
}

// Test that FirewallManager does not send any requests to PermissionBroker if
// FirewallManager is never initialized.
TEST_F(FirewallManagerTest, NeverInitialized) {
  PortToken udp_token = firewall_manager()->RequestUdpPortAccess(kFirstUpdPort);
}

// Test that FirewallManager does not send a port access request if
// PermissionBroker is not available.
TEST_F(FirewallManagerTest, PermissionBrokerUnavailable) {
  PortToken udp_token = firewall_manager()->RequestUdpPortAccess(kFirstUpdPort);

  InitFirewallManager();

  RunWaitForServiceToBeAvailableCallback(/*service_available=*/false);

  // FirewallManager should request to release the associated port when
  // `udp_token` is destroyed.
  EXPECT_CALL(*permission_broker_proxy_mock(),
              ReleaseUdpPort(kFirstUpdPort, kTestInterface, _, _,
                             dbus::ObjectProxy::TIMEOUT_USE_DEFAULT))
      .WillOnce(DoAll(SetArgPointee<2>(true), Return(true)));
}

// Test that FirewallManager does not re-request port access if a service name
// change by PermissionBroker results in no new owner.
TEST_F(FirewallManagerTest, ServiceNameChangeNoNewOwner) {
  InitFirewallManager();

  EXPECT_CALL(*permission_broker_proxy_mock(),
              RequestUdpPortAccess(kFirstUpdPort, kTestInterface, _, _, _,
                                   dbus::ObjectProxy::TIMEOUT_USE_DEFAULT))
      .WillOnce(DoAll(SetArgPointee<3>(true), Return(true)));

  PortToken udp_token = firewall_manager()->RequestUdpPortAccess(kFirstUpdPort);

  RunSetNameOwnerChangedCallback("Old owner", /*new_owner=*/"");

  // FirewallManager should request to release the associated port when
  // `udp_token` is destroyed.
  EXPECT_CALL(*permission_broker_proxy_mock(),
              ReleaseUdpPort(kFirstUpdPort, kTestInterface, _, _,
                             dbus::ObjectProxy::TIMEOUT_USE_DEFAULT))
      .WillOnce(DoAll(SetArgPointee<2>(true), Return(true)));
}

// Test that a PortToken can be constructed via the move constructor and
// ownership of the port is transferred.
TEST_F(FirewallManagerTest, PortTokenMoveConstructor) {
  InitFirewallManager();

  EXPECT_CALL(*permission_broker_proxy_mock(),
              RequestUdpPortAccess(kFirstUpdPort, kTestInterface, _, _, _,
                                   dbus::ObjectProxy::TIMEOUT_USE_DEFAULT))
      .WillOnce(DoAll(SetArgPointee<3>(true), Return(true)));

  std::unique_ptr<PortToken> moved_token;
  {
    // Normally, we would expect a port release request when `first_token` goes
    // out of scope. However, since ownership of the port is transferred to
    // `moved_token` with the move constructor, we do not expect the port
    // release request until `moved_token` goes out of scope.
    PortToken first_token =
        firewall_manager()->RequestUdpPortAccess(kFirstUpdPort);
    moved_token = std::make_unique<PortToken>(std::move(first_token));
  }

  // FirewallManager should request to release the associated port when
  // `moved_token` is destroyed.
  EXPECT_CALL(*permission_broker_proxy_mock(),
              ReleaseUdpPort(kFirstUpdPort, kTestInterface, _, _,
                             dbus::ObjectProxy::TIMEOUT_USE_DEFAULT))
      .WillOnce(DoAll(SetArgPointee<2>(true), Return(true)));
}

}  // namespace lorgnette

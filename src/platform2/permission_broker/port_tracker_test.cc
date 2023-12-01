// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "permission_broker/port_tracker.h"

#include <string>

#include <chromeos/patchpanel/dbus/client.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

using ::testing::_;
using ::testing::Return;
using ::testing::SetArgPointee;

namespace permission_broker {

class MockPortTracker : public PortTracker {
 public:
  MockPortTracker() : PortTracker(nullptr) {}
  MockPortTracker(const MockPortTracker&) = delete;
  MockPortTracker& operator=(const MockPortTracker&) = delete;

  ~MockPortTracker() override = default;

  MOCK_METHOD(bool,
              ModifyPortRule,
              (patchpanel::Client::FirewallRequestOperation, const PortRule&),
              (override));

  MOCK_METHOD(int, AddLifelineFd, (int), (override));
  MOCK_METHOD(bool, DeleteLifelineFd, (int), (override));
};

class PortTrackerTest : public testing::Test {
 public:
  PortTrackerTest() = default;
  PortTrackerTest(const PortTrackerTest&) = delete;
  PortTrackerTest& operator=(const PortTrackerTest&) = delete;

  ~PortTrackerTest() override = default;

 protected:
  MockPortTracker port_tracker_;

  uint16_t tcp_port = 8080;
  uint16_t udp_port = 5353;
  uint16_t reserved_port = 443;

  std::string interface = "interface";

  std::string arc_addr = "100.115.92.2";
  std::string crosvm_addr = "100.115.92.6";
  std::string pluginvm_addr = "100.115.93.10";
  std::string non_guest_addr = "192.168.1.128";
  std::string ipv4_any = "0.0.0.0";

  int dbus_fd = 3;     // First fd not std{in|out|err}. Doesn't get used at all.
  int tracked_fd = 4;  // Next "available" fd. Used only as a placeholder.
};

TEST_F(PortTrackerTest, AllowTcpPortAccess_Success) {
  EXPECT_CALL(port_tracker_, ModifyPortRule(_, _)).WillRepeatedly(Return(true));
  EXPECT_CALL(port_tracker_, AddLifelineFd(dbus_fd)).WillOnce(Return(0));
  ASSERT_TRUE(port_tracker_.AllowTcpPortAccess(tcp_port, interface, dbus_fd));
  ASSERT_TRUE(port_tracker_.HasActiveRules());
}

TEST_F(PortTrackerTest, AllowUdpPortAccess_Success) {
  EXPECT_CALL(port_tracker_, ModifyPortRule(_, _)).WillRepeatedly(Return(true));
  EXPECT_CALL(port_tracker_, AddLifelineFd(dbus_fd)).WillOnce(Return(0));
  ASSERT_TRUE(port_tracker_.AllowUdpPortAccess(udp_port, interface, dbus_fd));
  ASSERT_TRUE(port_tracker_.HasActiveRules());
}

TEST_F(PortTrackerTest, AllowTcpPortAccess_Twice) {
  EXPECT_CALL(port_tracker_, ModifyPortRule(_, _)).WillRepeatedly(Return(true));
  EXPECT_CALL(port_tracker_, AddLifelineFd(dbus_fd)).WillOnce(Return(0));
  ASSERT_TRUE(port_tracker_.AllowTcpPortAccess(tcp_port, interface, dbus_fd));
  ASSERT_FALSE(port_tracker_.AllowTcpPortAccess(tcp_port, interface, dbus_fd));
  ASSERT_TRUE(port_tracker_.HasActiveRules());
}

TEST_F(PortTrackerTest, AllowUdpPortAccess_Twice) {
  EXPECT_CALL(port_tracker_, ModifyPortRule(_, _)).WillRepeatedly(Return(true));
  EXPECT_CALL(port_tracker_, AddLifelineFd(dbus_fd)).WillOnce(Return(0));
  ASSERT_TRUE(port_tracker_.AllowUdpPortAccess(udp_port, interface, dbus_fd));
  ASSERT_FALSE(port_tracker_.AllowUdpPortAccess(udp_port, interface, dbus_fd));
  ASSERT_TRUE(port_tracker_.HasActiveRules());
}

TEST_F(PortTrackerTest, AllowTcpPortAccess_FirewallFailure) {
  // Make DBus call to patchpanel fail.
  EXPECT_CALL(port_tracker_, ModifyPortRule(_, _))
      .WillRepeatedly(Return(false));
  EXPECT_CALL(port_tracker_, AddLifelineFd(dbus_fd))
      .WillOnce(Return(tracked_fd));
  EXPECT_CALL(port_tracker_, DeleteLifelineFd(tracked_fd))
      .WillOnce(Return(true));
  ASSERT_FALSE(port_tracker_.AllowTcpPortAccess(tcp_port, interface, dbus_fd));
  ASSERT_FALSE(port_tracker_.HasActiveRules());
}

TEST_F(PortTrackerTest, AllowUdpPortAccess_FirewallFailure) {
  // Make DBus call to patchpanel fail.
  EXPECT_CALL(port_tracker_, ModifyPortRule(_, _))
      .WillRepeatedly(Return(false));
  EXPECT_CALL(port_tracker_, AddLifelineFd(dbus_fd))
      .WillOnce(Return(tracked_fd));
  EXPECT_CALL(port_tracker_, DeleteLifelineFd(tracked_fd))
      .WillOnce(Return(true));
  ASSERT_FALSE(port_tracker_.AllowUdpPortAccess(udp_port, interface, dbus_fd));
  ASSERT_FALSE(port_tracker_.HasActiveRules());
}

TEST_F(PortTrackerTest, AllowTcpPortAccess_EpollFailure) {
  EXPECT_CALL(port_tracker_, ModifyPortRule(_, _)).WillRepeatedly(Return(true));
  // Make epoll(7) fail.
  EXPECT_CALL(port_tracker_, AddLifelineFd(dbus_fd)).WillOnce(Return(-1));
  ASSERT_FALSE(port_tracker_.AllowTcpPortAccess(tcp_port, interface, dbus_fd));
  ASSERT_FALSE(port_tracker_.HasActiveRules());
}

TEST_F(PortTrackerTest, AllowUdpPortAccess_EpollFailure) {
  EXPECT_CALL(port_tracker_, ModifyPortRule(_, _)).WillRepeatedly(Return(true));
  // Make epoll(7) fail.
  EXPECT_CALL(port_tracker_, AddLifelineFd(dbus_fd)).WillOnce(Return(-1));
  ASSERT_FALSE(port_tracker_.AllowUdpPortAccess(udp_port, interface, dbus_fd));
}

TEST_F(PortTrackerTest, RevokeTcpPortAccess_Success) {
  EXPECT_CALL(port_tracker_, ModifyPortRule(_, _)).WillRepeatedly(Return(true));
  EXPECT_CALL(port_tracker_, AddLifelineFd(dbus_fd))
      .WillOnce(Return(tracked_fd));
  ASSERT_TRUE(port_tracker_.AllowTcpPortAccess(tcp_port, interface, dbus_fd));

  EXPECT_CALL(port_tracker_, DeleteLifelineFd(tracked_fd))
      .WillOnce(Return(true));
  ASSERT_TRUE(port_tracker_.RevokeTcpPortAccess(tcp_port, interface));
  ASSERT_FALSE(port_tracker_.HasActiveRules());
}

TEST_F(PortTrackerTest, RevokeUdpPortAccess_Success) {
  EXPECT_CALL(port_tracker_, ModifyPortRule(_, _)).WillRepeatedly(Return(true));
  EXPECT_CALL(port_tracker_, AddLifelineFd(dbus_fd))
      .WillOnce(Return(tracked_fd));
  ASSERT_TRUE(port_tracker_.AllowUdpPortAccess(udp_port, interface, dbus_fd));

  EXPECT_CALL(port_tracker_, DeleteLifelineFd(tracked_fd))
      .WillOnce(Return(true));
  ASSERT_TRUE(port_tracker_.RevokeUdpPortAccess(udp_port, interface));
  ASSERT_FALSE(port_tracker_.HasActiveRules());
}

TEST_F(PortTrackerTest, RevokeTcpPortAccess_FirewallFailure) {
  // Make revoke iptables rules DBus call fail.
  EXPECT_CALL(port_tracker_, ModifyPortRule(_, _))
      .WillOnce(Return(true))
      .WillOnce(Return(false));

  EXPECT_CALL(port_tracker_, AddLifelineFd(dbus_fd))
      .WillOnce(Return(tracked_fd));
  ASSERT_TRUE(port_tracker_.AllowTcpPortAccess(tcp_port, interface, dbus_fd));

  EXPECT_CALL(port_tracker_, DeleteLifelineFd(tracked_fd))
      .WillOnce(Return(true));
  ASSERT_FALSE(port_tracker_.RevokeTcpPortAccess(tcp_port, interface));
  ASSERT_FALSE(port_tracker_.HasActiveRules());
}

TEST_F(PortTrackerTest, RevokeUdpPortAccess_DbusFailure) {
  // Make revoke iptables rules DBus call fail.
  EXPECT_CALL(port_tracker_, ModifyPortRule(_, _))
      .WillOnce(Return(true))
      .WillOnce(Return(false));

  EXPECT_CALL(port_tracker_, AddLifelineFd(dbus_fd))
      .WillOnce(Return(tracked_fd));
  ASSERT_TRUE(port_tracker_.AllowUdpPortAccess(udp_port, interface, dbus_fd));

  EXPECT_CALL(port_tracker_, DeleteLifelineFd(tracked_fd))
      .WillOnce(Return(true));
  ASSERT_FALSE(port_tracker_.RevokeUdpPortAccess(udp_port, interface));
  ASSERT_FALSE(port_tracker_.HasActiveRules());
}

TEST_F(PortTrackerTest, RevokeTcpPortAccess_EpollFailure) {
  EXPECT_CALL(port_tracker_, ModifyPortRule(_, _)).WillRepeatedly(Return(true));

  EXPECT_CALL(port_tracker_, AddLifelineFd(dbus_fd))
      .WillOnce(Return(tracked_fd));
  ASSERT_TRUE(port_tracker_.AllowTcpPortAccess(tcp_port, interface, dbus_fd));

  // Make epoll(7) fail.
  EXPECT_CALL(port_tracker_, DeleteLifelineFd(tracked_fd))
      .WillOnce(Return(false));
  ASSERT_FALSE(port_tracker_.RevokeTcpPortAccess(tcp_port, interface));
  ASSERT_FALSE(port_tracker_.HasActiveRules());
}

TEST_F(PortTrackerTest, RevokeUdpPortAccess_EpollFailure) {
  EXPECT_CALL(port_tracker_, ModifyPortRule(_, _)).WillRepeatedly(Return(true));

  EXPECT_CALL(port_tracker_, AddLifelineFd(dbus_fd))
      .WillOnce(Return(tracked_fd));
  ASSERT_TRUE(port_tracker_.AllowUdpPortAccess(udp_port, interface, dbus_fd));

  // Make epoll(7) fail.
  EXPECT_CALL(port_tracker_, DeleteLifelineFd(tracked_fd))
      .WillOnce(Return(false));
  ASSERT_FALSE(port_tracker_.RevokeUdpPortAccess(udp_port, interface));
  ASSERT_FALSE(port_tracker_.HasActiveRules());
}

TEST_F(PortTrackerTest, LockDownLoopbackTcpPort_Success) {
  EXPECT_CALL(port_tracker_, ModifyPortRule(_, _)).WillRepeatedly(Return(true));
  EXPECT_CALL(port_tracker_, AddLifelineFd(dbus_fd)).WillOnce(Return(0));
  ASSERT_TRUE(port_tracker_.LockDownLoopbackTcpPort(tcp_port, dbus_fd));
  ASSERT_TRUE(port_tracker_.HasActiveRules());
}

TEST_F(PortTrackerTest, LockDownLoopbackTcpPort_Twice) {
  EXPECT_CALL(port_tracker_, ModifyPortRule(_, _)).WillRepeatedly(Return(true));
  EXPECT_CALL(port_tracker_, AddLifelineFd(dbus_fd)).WillOnce(Return(0));
  ASSERT_TRUE(port_tracker_.LockDownLoopbackTcpPort(tcp_port, dbus_fd));
  ASSERT_FALSE(port_tracker_.LockDownLoopbackTcpPort(tcp_port, dbus_fd));
  ASSERT_TRUE(port_tracker_.HasActiveRules());
}

TEST_F(PortTrackerTest, LockDownLoopbackTcpPort_FirewallFailure) {
  // Make DBus call to patchpanel fail.
  EXPECT_CALL(port_tracker_, ModifyPortRule(_, _))
      .WillRepeatedly(Return(false));
  EXPECT_CALL(port_tracker_, AddLifelineFd(dbus_fd))
      .WillOnce(Return(tracked_fd));
  EXPECT_CALL(port_tracker_, DeleteLifelineFd(tracked_fd))
      .WillOnce(Return(true));
  ASSERT_FALSE(port_tracker_.LockDownLoopbackTcpPort(tcp_port, dbus_fd));
  ASSERT_FALSE(port_tracker_.HasActiveRules());
}

TEST_F(PortTrackerTest, LockDownLoopbackTcpPort_EpollFailure) {
  EXPECT_CALL(port_tracker_, ModifyPortRule(_, _)).WillRepeatedly(Return(true));
  // Make epoll(7) fail.
  EXPECT_CALL(port_tracker_, AddLifelineFd(dbus_fd)).WillOnce(Return(-1));
  ASSERT_FALSE(port_tracker_.LockDownLoopbackTcpPort(tcp_port, dbus_fd));
  ASSERT_FALSE(port_tracker_.HasActiveRules());
}

TEST_F(PortTrackerTest, ReleaseLoopbackTcpPort_Success) {
  EXPECT_CALL(port_tracker_, ModifyPortRule(_, _)).WillRepeatedly(Return(true));
  EXPECT_CALL(port_tracker_, AddLifelineFd(dbus_fd))
      .WillOnce(Return(tracked_fd));
  ASSERT_TRUE(port_tracker_.LockDownLoopbackTcpPort(tcp_port, dbus_fd));

  EXPECT_CALL(port_tracker_, DeleteLifelineFd(tracked_fd))
      .WillOnce(Return(true));
  ASSERT_TRUE(port_tracker_.ReleaseLoopbackTcpPort(tcp_port));
  ASSERT_FALSE(port_tracker_.HasActiveRules());
}

TEST_F(PortTrackerTest, ReleaseLoopbackTcpPort_FirewallFailure) {
  // Make revoke iptables rules DBus call fail.
  EXPECT_CALL(port_tracker_, ModifyPortRule(_, _))
      .WillOnce(Return(true))
      .WillOnce(Return(false));
  EXPECT_CALL(port_tracker_, AddLifelineFd(dbus_fd))
      .WillOnce(Return(tracked_fd));
  ASSERT_TRUE(port_tracker_.LockDownLoopbackTcpPort(tcp_port, dbus_fd));

  EXPECT_CALL(port_tracker_, DeleteLifelineFd(tracked_fd))
      .WillOnce(Return(true));
  ASSERT_FALSE(port_tracker_.ReleaseLoopbackTcpPort(tcp_port));
  ASSERT_FALSE(port_tracker_.HasActiveRules());
}

TEST_F(PortTrackerTest, ReleaseLoopbackTcpPort_EpollFailure) {
  EXPECT_CALL(port_tracker_, ModifyPortRule(_, _)).WillRepeatedly(Return(true));
  EXPECT_CALL(port_tracker_, AddLifelineFd(dbus_fd))
      .WillOnce(Return(tracked_fd));
  ASSERT_TRUE(port_tracker_.LockDownLoopbackTcpPort(tcp_port, dbus_fd));

  // Make epoll(7) fail.
  EXPECT_CALL(port_tracker_, DeleteLifelineFd(tracked_fd))
      .WillOnce(Return(false));
  ASSERT_FALSE(port_tracker_.ReleaseLoopbackTcpPort(tcp_port));
  ASSERT_FALSE(port_tracker_.HasActiveRules());
}

TEST_F(PortTrackerTest, StartPortForwarding_BaseSuccessCase) {
  EXPECT_CALL(port_tracker_, ModifyPortRule(_, _)).WillRepeatedly(Return(true));
  EXPECT_CALL(port_tracker_, AddLifelineFd(dbus_fd)).WillOnce(Return(5));
  ASSERT_TRUE(port_tracker_.StartTcpPortForwarding(
      tcp_port, "eth0", crosvm_addr, tcp_port, dbus_fd));

  EXPECT_CALL(port_tracker_, AddLifelineFd(dbus_fd)).WillOnce(Return(6));
  ASSERT_TRUE(port_tracker_.StartUdpPortForwarding(
      udp_port, "eth0", crosvm_addr, udp_port, dbus_fd));

  EXPECT_CALL(port_tracker_, AddLifelineFd(dbus_fd)).WillOnce(Return(7));
  ASSERT_TRUE(port_tracker_.StartTcpPortForwarding(
      tcp_port, "wlan0", pluginvm_addr, tcp_port, dbus_fd));

  EXPECT_CALL(port_tracker_, AddLifelineFd(dbus_fd)).WillOnce(Return(8));
  ASSERT_TRUE(port_tracker_.StartUdpPortForwarding(
      udp_port, "wlan0", pluginvm_addr, udp_port, dbus_fd));

  ASSERT_TRUE(port_tracker_.HasActiveRules());
}

TEST_F(PortTrackerTest, StartPortForwarding_LifelineFdFailure) {
  EXPECT_CALL(port_tracker_, ModifyPortRule(_, _)).WillRepeatedly(Return(true));
  EXPECT_CALL(port_tracker_, AddLifelineFd(dbus_fd)).WillOnce(Return(-1));
  ASSERT_FALSE(port_tracker_.StartTcpPortForwarding(
      tcp_port, "eth0", crosvm_addr, tcp_port, dbus_fd));

  EXPECT_CALL(port_tracker_, AddLifelineFd(dbus_fd)).WillOnce(Return(-1));
  ASSERT_FALSE(port_tracker_.StartUdpPortForwarding(
      tcp_port, "eth0", crosvm_addr, tcp_port, dbus_fd));

  ASSERT_FALSE(port_tracker_.HasActiveRules());
}

TEST_F(PortTrackerTest, StartPortForwarding_IptablesFailure) {
  EXPECT_CALL(port_tracker_, ModifyPortRule(_, _))
      .WillRepeatedly(Return(false));

  EXPECT_CALL(port_tracker_, AddLifelineFd(dbus_fd)).WillOnce(Return(5));
  EXPECT_CALL(port_tracker_, DeleteLifelineFd(5)).WillOnce(Return(true));
  ASSERT_FALSE(port_tracker_.StartTcpPortForwarding(
      tcp_port, "eth0", crosvm_addr, tcp_port, dbus_fd));

  EXPECT_CALL(port_tracker_, AddLifelineFd(dbus_fd)).WillOnce(Return(6));
  EXPECT_CALL(port_tracker_, DeleteLifelineFd(6)).WillOnce(Return(true));
  ASSERT_FALSE(port_tracker_.StartUdpPortForwarding(
      tcp_port, "eth0", crosvm_addr, tcp_port, dbus_fd));

  ASSERT_FALSE(port_tracker_.HasActiveRules());
}

TEST_F(PortTrackerTest, StartPortForwarding_InputPortValidation) {
  EXPECT_CALL(port_tracker_, ModifyPortRule(_, _)).WillRepeatedly(Return(true));

  ASSERT_FALSE(port_tracker_.StartTcpPortForwarding(
      reserved_port, "eth0", crosvm_addr, tcp_port, dbus_fd));
  ASSERT_FALSE(port_tracker_.StartUdpPortForwarding(
      reserved_port, "eth0", crosvm_addr, tcp_port, dbus_fd));
  ASSERT_FALSE(port_tracker_.HasActiveRules());

  EXPECT_CALL(port_tracker_, AddLifelineFd(dbus_fd)).WillOnce(Return(5));
  ASSERT_TRUE(port_tracker_.StartTcpPortForwarding(
      tcp_port, "eth0", crosvm_addr, reserved_port, dbus_fd));
  EXPECT_CALL(port_tracker_, AddLifelineFd(dbus_fd)).WillOnce(Return(6));
  ASSERT_TRUE(port_tracker_.StartUdpPortForwarding(
      tcp_port, "eth0", crosvm_addr, reserved_port, dbus_fd));
  ASSERT_TRUE(port_tracker_.HasActiveRules());
}

TEST_F(PortTrackerTest, StartPortForwarding_InputInterfaceValidation) {
  EXPECT_CALL(port_tracker_, ModifyPortRule(_, _)).WillRepeatedly(Return(true));

  ASSERT_FALSE(port_tracker_.StartTcpPortForwarding(tcp_port, "", crosvm_addr,
                                                    tcp_port, dbus_fd));
  ASSERT_FALSE(port_tracker_.StartUdpPortForwarding(tcp_port, "", crosvm_addr,
                                                    tcp_port, dbus_fd));

  ASSERT_FALSE(port_tracker_.StartTcpPortForwarding(tcp_port, "lo", crosvm_addr,
                                                    tcp_port, dbus_fd));
  ASSERT_FALSE(port_tracker_.StartUdpPortForwarding(tcp_port, "lo", crosvm_addr,
                                                    tcp_port, dbus_fd));

  ASSERT_FALSE(port_tracker_.StartTcpPortForwarding(
      tcp_port, "iface0", crosvm_addr, tcp_port, dbus_fd));
  ASSERT_FALSE(port_tracker_.StartUdpPortForwarding(
      tcp_port, "iface0", crosvm_addr, tcp_port, dbus_fd));

  ASSERT_FALSE(port_tracker_.StartTcpPortForwarding(
      tcp_port, "ETH0", crosvm_addr, tcp_port, dbus_fd));
  ASSERT_FALSE(port_tracker_.StartUdpPortForwarding(
      tcp_port, "WLAN0", crosvm_addr, tcp_port, dbus_fd));

  ASSERT_TRUE(port_tracker_.StartTcpPortForwarding(
      tcp_port, "eth0", crosvm_addr, tcp_port, dbus_fd));
  ASSERT_TRUE(port_tracker_.StartTcpPortForwarding(
      tcp_port, "eth1", crosvm_addr, tcp_port, dbus_fd));
  ASSERT_TRUE(port_tracker_.StartTcpPortForwarding(
      tcp_port, "usb0", crosvm_addr, tcp_port, dbus_fd));
  ASSERT_TRUE(port_tracker_.StartTcpPortForwarding(
      tcp_port, "wlan0", crosvm_addr, tcp_port, dbus_fd));
  ASSERT_TRUE(port_tracker_.StartTcpPortForwarding(
      tcp_port, "mlan0", crosvm_addr, tcp_port, dbus_fd));

  ASSERT_TRUE(port_tracker_.HasActiveRules());
}

TEST_F(PortTrackerTest, StartPortForwarding_TargetIpAddressValidation) {
  EXPECT_CALL(port_tracker_, ModifyPortRule(_, _)).WillRepeatedly(Return(true));

  ASSERT_FALSE(port_tracker_.StartTcpPortForwarding(
      tcp_port, "eth0", "not_an_ip", tcp_port, dbus_fd));
  ASSERT_FALSE(port_tracker_.StartTcpPortForwarding(tcp_port, "eth0", ipv4_any,
                                                    tcp_port, dbus_fd));
  ASSERT_FALSE(port_tracker_.StartTcpPortForwarding(
      tcp_port, "eth0", non_guest_addr, tcp_port, dbus_fd));
  ASSERT_FALSE(port_tracker_.StartUdpPortForwarding(
      tcp_port, "eth0", "2001:db8::1", tcp_port, dbus_fd));
  ASSERT_FALSE(port_tracker_.StartUdpPortForwarding(tcp_port, "eth0", ipv4_any,
                                                    tcp_port, dbus_fd));
  ASSERT_FALSE(port_tracker_.StartUdpPortForwarding(
      tcp_port, "eth0", non_guest_addr, tcp_port, dbus_fd));

  ASSERT_FALSE(port_tracker_.HasActiveRules());
}

TEST_F(PortTrackerTest, StopPortForwarding) {
  EXPECT_CALL(port_tracker_, ModifyPortRule(_, _)).WillRepeatedly(Return(true));
  // Cannot stop before starting.
  ASSERT_FALSE(port_tracker_.StopTcpPortForwarding(tcp_port, "eth0"));
  ASSERT_FALSE(port_tracker_.StopUdpPortForwarding(tcp_port, "eth0"));

  EXPECT_CALL(port_tracker_, AddLifelineFd(dbus_fd)).WillOnce(Return(5));
  ASSERT_TRUE(port_tracker_.StartTcpPortForwarding(
      tcp_port, "eth0", crosvm_addr, tcp_port, dbus_fd));
  EXPECT_CALL(port_tracker_, AddLifelineFd(dbus_fd)).WillOnce(Return(6));
  ASSERT_TRUE(port_tracker_.StartUdpPortForwarding(
      tcp_port, "eth0", crosvm_addr, tcp_port, dbus_fd));

  EXPECT_CALL(port_tracker_, DeleteLifelineFd(5)).WillOnce(Return(true));
  ASSERT_TRUE(port_tracker_.StopTcpPortForwarding(tcp_port, "eth0"));
  EXPECT_CALL(port_tracker_, DeleteLifelineFd(6)).WillOnce(Return(true));
  ASSERT_TRUE(port_tracker_.StopUdpPortForwarding(tcp_port, "eth0"));

  // Cannot stop twice.
  ASSERT_FALSE(port_tracker_.StopTcpPortForwarding(tcp_port, "eth0"));
  ASSERT_FALSE(port_tracker_.StopUdpPortForwarding(tcp_port, "eth0"));

  ASSERT_FALSE(port_tracker_.HasActiveRules());
}

TEST_F(PortTrackerTest, StartPortForwarding_PreventOverwrite) {
  EXPECT_CALL(port_tracker_, ModifyPortRule(_, _)).WillRepeatedly(Return(true));
  EXPECT_CALL(port_tracker_, AddLifelineFd(dbus_fd)).WillOnce(Return(5));
  ASSERT_TRUE(port_tracker_.StartTcpPortForwarding(
      tcp_port, "eth0", crosvm_addr, tcp_port, dbus_fd));
  EXPECT_CALL(port_tracker_, AddLifelineFd(dbus_fd)).WillOnce(Return(6));
  ASSERT_TRUE(port_tracker_.StartUdpPortForwarding(
      tcp_port, "eth0", crosvm_addr, tcp_port, dbus_fd));

  // Cannot overwrite a (protocol, port, interface) entry.
  ASSERT_FALSE(port_tracker_.StartTcpPortForwarding(tcp_port, "eth0", arc_addr,
                                                    443, dbus_fd));
  ASSERT_FALSE(port_tracker_.StartUdpPortForwarding(tcp_port, "eth0", arc_addr,
                                                    443, dbus_fd));

  EXPECT_CALL(port_tracker_, DeleteLifelineFd(5)).WillOnce(Return(true));
  ASSERT_TRUE(port_tracker_.StopTcpPortForwarding(tcp_port, "eth0"));
  EXPECT_CALL(port_tracker_, DeleteLifelineFd(6)).WillOnce(Return(true));
  ASSERT_TRUE(port_tracker_.StopUdpPortForwarding(tcp_port, "eth0"));

  ASSERT_FALSE(port_tracker_.HasActiveRules());

  // Previous entry was deleted.
  EXPECT_CALL(port_tracker_, AddLifelineFd(dbus_fd)).WillOnce(Return(5));
  ASSERT_TRUE(port_tracker_.StartTcpPortForwarding(tcp_port, "eth0", arc_addr,
                                                   443, dbus_fd));
  EXPECT_CALL(port_tracker_, AddLifelineFd(dbus_fd)).WillOnce(Return(6));
  ASSERT_TRUE(port_tracker_.StartUdpPortForwarding(tcp_port, "eth0", arc_addr,
                                                   443, dbus_fd));

  ASSERT_TRUE(port_tracker_.HasActiveRules());

  ASSERT_FALSE(port_tracker_.StartTcpPortForwarding(
      tcp_port, "eth0", crosvm_addr, tcp_port, dbus_fd));
  ASSERT_FALSE(port_tracker_.StartUdpPortForwarding(
      tcp_port, "eth0", crosvm_addr, tcp_port, dbus_fd));
}

TEST_F(PortTrackerTest, StartPortForwarding_PreventForwardingOpenPort) {
  EXPECT_CALL(port_tracker_, ModifyPortRule(_, _)).WillRepeatedly(Return(true));

  // Open TCP port, that port cannot be forwarded for the same interface.
  EXPECT_CALL(port_tracker_, AddLifelineFd(dbus_fd)).WillOnce(Return(5));
  ASSERT_TRUE(port_tracker_.AllowTcpPortAccess(tcp_port, "eth0", dbus_fd));
  ASSERT_FALSE(port_tracker_.StartTcpPortForwarding(
      tcp_port, "eth0", crosvm_addr, tcp_port, dbus_fd));

  // Forward UDP port, that port cannot be opened for the same interface.
  EXPECT_CALL(port_tracker_, AddLifelineFd(dbus_fd)).WillOnce(Return(6));
  ASSERT_TRUE(port_tracker_.StartUdpPortForwarding(
      udp_port, "eth0", crosvm_addr, tcp_port, dbus_fd));
  ASSERT_FALSE(port_tracker_.AllowUdpPortAccess(udp_port, "eth0", dbus_fd));

  // Close TCP port, that port can now be forwarded.
  EXPECT_CALL(port_tracker_, DeleteLifelineFd(5)).WillOnce(Return(true));
  ASSERT_TRUE(port_tracker_.RevokeTcpPortAccess(tcp_port, "eth0"));
  EXPECT_CALL(port_tracker_, AddLifelineFd(dbus_fd)).WillOnce(Return(7));
  ASSERT_TRUE(port_tracker_.StartTcpPortForwarding(
      tcp_port, "eth0", crosvm_addr, tcp_port, dbus_fd));

  // Stop forwarding UDP port, that port can now be opened.
  EXPECT_CALL(port_tracker_, DeleteLifelineFd(6)).WillOnce(Return(true));
  ASSERT_TRUE(port_tracker_.StopUdpPortForwarding(udp_port, "eth0"));
  EXPECT_CALL(port_tracker_, AddLifelineFd(dbus_fd)).WillOnce(Return(8));
  ASSERT_TRUE(port_tracker_.AllowUdpPortAccess(udp_port, "eth0", dbus_fd));
}
}  // namespace permission_broker

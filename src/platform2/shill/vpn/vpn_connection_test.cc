// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/vpn/vpn_connection.h"

#include <memory>
#include <string>
#include <utility>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "shill/ipconfig.h"
#include "shill/service.h"
#include "shill/test_event_dispatcher.h"
#include "shill/vpn/vpn_connection_under_test.h"

namespace shill {
namespace {

constexpr char kTestIfName[] = "vpn0";
constexpr int kTestIfIndex = 123;
constexpr char kTestIPAddress[] = "192.168.1.2";

// We only compare |address| in this test for simplicity.
MATCHER_P(IPPropertiesEq, rhs, "") {
  return arg->address == rhs.address;
}

class MockCallbacks {
 public:
  MOCK_METHOD(void,
              OnConnected,
              (const std::string& link_name,
               int interface_index,
               std::unique_ptr<IPConfig::Properties> ipv4_properties,
               std::unique_ptr<IPConfig::Properties> ipv6_properties));
  MOCK_METHOD(void, OnFailure, (Service::ConnectFailure));
  MOCK_METHOD(void, OnStopped, ());
};

class VPNConnectionTest : public testing::Test {
 public:
  VPNConnectionTest() {
    auto callbacks = std::make_unique<VPNConnection::Callbacks>(
        base::BindRepeating(&MockCallbacks::OnConnected,
                            base::Unretained(&callbacks_)),
        base::BindOnce(&MockCallbacks::OnFailure,
                       base::Unretained(&callbacks_)),
        base::BindOnce(&MockCallbacks::OnStopped,
                       base::Unretained(&callbacks_)));
    vpn_connection_ = std::make_unique<VPNConnectionUnderTest>(
        std::move(callbacks), &dispatcher_);
    test_ipv4_properties_.address = kTestIPAddress;
  }

 protected:
  IPConfig::Properties test_ipv4_properties_;
  IPConfig::Properties test_ipv6_properties_;
  EventDispatcherForTest dispatcher_;
  MockCallbacks callbacks_;
  std::unique_ptr<VPNConnectionUnderTest> vpn_connection_;
};

TEST_F(VPNConnectionTest, ConnectDisconnect) {
  vpn_connection_->Connect();
  EXPECT_CALL(*vpn_connection_, OnConnect());
  EXPECT_EQ(vpn_connection_->state(), VPNConnection::State::kConnecting);
  dispatcher_.task_environment().RunUntilIdle();
  EXPECT_EQ(vpn_connection_->state(), VPNConnection::State::kConnecting);

  vpn_connection_->TriggerConnected(
      kTestIfName, kTestIfIndex,
      std::make_unique<IPConfig::Properties>(test_ipv4_properties_),
      std::make_unique<IPConfig::Properties>(test_ipv6_properties_));
  EXPECT_CALL(callbacks_, OnConnected(kTestIfName, kTestIfIndex,
                                      IPPropertiesEq(test_ipv4_properties_),
                                      IPPropertiesEq(test_ipv6_properties_)));
  EXPECT_EQ(vpn_connection_->state(), VPNConnection::State::kConnected);
  dispatcher_.task_environment().RunUntilIdle();
  EXPECT_EQ(vpn_connection_->state(), VPNConnection::State::kConnected);

  vpn_connection_->Disconnect();
  EXPECT_CALL(*vpn_connection_, OnDisconnect());
  EXPECT_EQ(vpn_connection_->state(), VPNConnection::State::kDisconnecting);
  dispatcher_.task_environment().RunUntilIdle();
  EXPECT_EQ(vpn_connection_->state(), VPNConnection::State::kDisconnecting);

  vpn_connection_->TriggerStopped();
  EXPECT_CALL(callbacks_, OnStopped());
  EXPECT_EQ(vpn_connection_->state(), VPNConnection::State::kStopped);
  dispatcher_.task_environment().RunUntilIdle();
  EXPECT_EQ(vpn_connection_->state(), VPNConnection::State::kStopped);
}

TEST_F(VPNConnectionTest, ConnectingFailure) {
  vpn_connection_->Connect();
  dispatcher_.task_environment().RunUntilIdle();

  vpn_connection_->TriggerFailure(Service::kFailureInternal, "");
  EXPECT_EQ(vpn_connection_->state(), VPNConnection::State::kDisconnecting);
  EXPECT_CALL(*vpn_connection_, OnDisconnect());
  EXPECT_CALL(callbacks_, OnFailure(Service::kFailureInternal));
  dispatcher_.task_environment().RunUntilIdle();
  EXPECT_EQ(vpn_connection_->state(), VPNConnection::State::kDisconnecting);
}

TEST_F(VPNConnectionTest, ConnectedFailure) {
  vpn_connection_->Connect();
  dispatcher_.task_environment().RunUntilIdle();

  vpn_connection_->TriggerConnected(
      kTestIfName, kTestIfIndex,
      std::make_unique<IPConfig::Properties>(test_ipv4_properties_),
      std::make_unique<IPConfig::Properties>(test_ipv6_properties_));
  dispatcher_.task_environment().RunUntilIdle();

  vpn_connection_->TriggerFailure(Service::kFailureInternal, "");
  EXPECT_EQ(vpn_connection_->state(), VPNConnection::State::kDisconnecting);
  EXPECT_CALL(*vpn_connection_, OnDisconnect());
  EXPECT_CALL(callbacks_, OnFailure(Service::kFailureInternal));
  dispatcher_.task_environment().RunUntilIdle();
  EXPECT_EQ(vpn_connection_->state(), VPNConnection::State::kDisconnecting);
}

}  // namespace
}  // namespace shill

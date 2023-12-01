// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "dns-proxy/controller.h"

#include <memory>
#include <string>
#include <utility>

#include <chromeos/patchpanel/mock_message_dispatcher.h>
#include <google/protobuf/message_lite.h>
#include <gtest/gtest.h>

#include "dns-proxy/ipc.pb.h"
#include "dns-proxy/mock_resolv_conf.h"

using testing::Test;

namespace dns_proxy {

using testing::_;
using testing::ElementsAre;
using testing::IsEmpty;

class ControllerTest : public Test {
 public:
  void SetUp() override {
    auto resolv_conf = std::make_unique<MockResolvConf>();
    resolv_conf_ptr_ = resolv_conf.get();
    controller_ = std::make_unique<Controller>(std::move(resolv_conf));
  }

 protected:
  MockResolvConf* resolv_conf_ptr_;
  std::unique_ptr<Controller> controller_;
};

TEST_F(ControllerTest, SetProxyAddrs) {
  ProxyAddrMessage msg;
  msg.set_type(ProxyAddrMessage::SET_ADDRS);
  msg.add_addrs("100.115.92.100");
  msg.add_addrs("::1");
  EXPECT_CALL(*resolv_conf_ptr_,
              SetDNSProxyAddresses(ElementsAre("100.115.92.100", "::1")));
  controller_->OnProxyAddrMessage(msg);
}

TEST_F(ControllerTest, ClearProxyAddrs) {
  ProxyAddrMessage msg;
  msg.set_type(ProxyAddrMessage::CLEAR_ADDRS);
  EXPECT_CALL(*resolv_conf_ptr_, SetDNSProxyAddresses(IsEmpty()));
  controller_->OnProxyAddrMessage(msg);
}

}  // namespace dns_proxy

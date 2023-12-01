// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/upstart/upstart.h"

#include <utility>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "shill/mock_control.h"
#include "shill/upstart/mock_upstart_proxy.h"
#include "shill/upstart/upstart_proxy_interface.h"

#include <base/check.h>

using testing::_;
using testing::Test;

namespace shill {

namespace {

class FakeControl : public MockControl {
 public:
  FakeControl()
      : upstart_proxy_raw_(new MockUpstartProxy),
        upstart_proxy_(upstart_proxy_raw_) {}

  std::unique_ptr<UpstartProxyInterface> CreateUpstartProxy() override {
    CHECK(upstart_proxy_);
    return std::move(upstart_proxy_);
  }

  // Can not guarantee that the returned object is alive.
  MockUpstartProxy* upstart_proxy() const { return upstart_proxy_raw_; }

 private:
  MockUpstartProxy* const upstart_proxy_raw_;
  std::unique_ptr<MockUpstartProxy> upstart_proxy_;
};

}  // namespace

class UpstartTest : public Test {
 public:
  UpstartTest()
      : upstart_(&control_), upstart_proxy_(control_.upstart_proxy()) {}

 protected:
  FakeControl control_;
  Upstart upstart_;
  MockUpstartProxy* const upstart_proxy_;
};

TEST_F(UpstartTest, NotifyDisconnected) {
  EXPECT_CALL(*upstart_proxy_, EmitEvent("shill-disconnected", _, false));
  upstart_.NotifyDisconnected();
}

TEST_F(UpstartTest, NotifyConnected) {
  EXPECT_CALL(*upstart_proxy_, EmitEvent("shill-connected", _, false));
  upstart_.NotifyConnected();
}

}  // namespace shill

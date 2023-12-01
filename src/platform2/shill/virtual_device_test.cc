// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/virtual_device.h"

#include <sys/socket.h>
#include <linux/if.h>  // NOLINT - Needs typedefs from sys/socket.h.
#include <utility>

#include <base/task/single_thread_task_executor.h>
#include <base/test/test_future.h>
#include <gtest/gtest.h>

#include "shill/event_dispatcher.h"
#include "shill/mock_control.h"
#include "shill/mock_manager.h"
#include "shill/mock_metrics.h"
#include "shill/mock_service.h"
#include "shill/net/mock_rtnl_handler.h"
#include "shill/store/fake_store.h"
#include "shill/technology.h"
#include "shill/testing.h"

using testing::_;
using testing::StrictMock;

namespace shill {

namespace {
const char kTestDeviceName[] = "tun0";
const int kTestInterfaceIndex = 5;

MATCHER_P(IsWeakPtrTo, address, "") {
  return arg.get() == address;
}
}  // namespace

class VirtualDeviceTest : public testing::Test {
 public:
  VirtualDeviceTest()
      : manager_(&control_, &dispatcher_, &metrics_),
        device_(new VirtualDevice(&manager_,
                                  kTestDeviceName,
                                  kTestInterfaceIndex,
                                  Technology::kVPN)) {}

  ~VirtualDeviceTest() override = default;

  void SetUp() override { device_->rtnl_handler_ = &rtnl_handler_; }

 protected:
  base::SingleThreadTaskExecutor task_executor_{base::MessagePumpType::IO};

  MockControl control_;
  EventDispatcher dispatcher_;
  MockMetrics metrics_;
  MockManager manager_;
  StrictMock<MockRTNLHandler> rtnl_handler_;

  VirtualDeviceRefPtr device_;

 private:
};

TEST_F(VirtualDeviceTest, technology) {
  EXPECT_EQ(Technology::kVPN, device_->technology());
  EXPECT_NE(Technology::kEthernet, device_->technology());
}

TEST_F(VirtualDeviceTest, Load) {
  FakeStore storage;
  EXPECT_TRUE(device_->Load(&storage));
}

TEST_F(VirtualDeviceTest, Save) {
  FakeStore storage;
  EXPECT_TRUE(device_->Save(&storage));
  EXPECT_TRUE(storage.GetGroups().empty());
}

TEST_F(VirtualDeviceTest, Start) {
  EXPECT_CALL(rtnl_handler_, SetInterfaceFlags(_, IFF_UP, IFF_UP));

  base::test::TestFuture<Error> error;
  device_->Start(GetResultCallback(&error));
  EXPECT_TRUE(error.Get().IsSuccess());
}

TEST_F(VirtualDeviceTest, Stop) {
  base::test::TestFuture<Error> error;
  device_->Stop(GetResultCallback(&error));
  EXPECT_TRUE(error.Get().IsSuccess());
}

TEST_F(VirtualDeviceTest, ResetConnection) {
  EXPECT_EQ(nullptr, device_->selected_service_);
  device_->SetServiceState(Service::kStateAssociating);
  scoped_refptr<MockService> service(new StrictMock<MockService>(&manager_));
  EXPECT_CALL(*service,
              SetAttachedNetwork(IsWeakPtrTo(device_->GetPrimaryNetwork())));
  device_->SelectService(service);
  EXPECT_EQ(device_->selected_service_, service);

  // ResetConnection() should drop the connection and the selected service,
  // but should not change the service state.
  EXPECT_CALL(*service, SetState(_)).Times(0);
  EXPECT_CALL(*service, SetAttachedNetwork(IsWeakPtrTo(nullptr)));
  device_->ResetConnection();
  EXPECT_EQ(nullptr, device_->selected_service_);
}

}  // namespace shill

// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/concierge/vm_wl_interface.h"

#include <memory>
#include <utility>

#include <dbus/message.h>
#include <dbus/mock_bus.h>
#include <dbus/mock_object_proxy.h>
#include <dbus/object_path.h>
#include <dbus/scoped_dbus_error.h>
#include <dbus/vm_wl/dbus-constants.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <vm_applications/apps.pb.h>

namespace vm_tools::concierge {

namespace {

using testing::_;

dbus::Bus::Options GetDbusOptions() {
  dbus::Bus::Options opts;
  opts.bus_type = dbus::Bus::SYSTEM;
  return opts;
}

class VmWlInterfaceTest : public testing::Test {
 public:
  VmWlInterfaceTest()
      : mock_bus_(new dbus::MockBus(GetDbusOptions())),
        mock_proxy_(
            new dbus::MockObjectProxy(mock_bus_.get(),
                                      wl::kVmWlServiceName,
                                      dbus::ObjectPath(wl::kVmWlServicePath))) {
    EXPECT_CALL(*mock_bus_.get(),
                GetObjectProxy(wl::kVmWlServiceName,
                               dbus::ObjectPath(wl::kVmWlServicePath)))
        .WillRepeatedly(testing::Return(mock_proxy_.get()));
  }

 protected:
  scoped_refptr<dbus::MockBus> mock_bus_;
  scoped_refptr<dbus::MockObjectProxy> mock_proxy_;
};

}  // namespace

TEST_F(VmWlInterfaceTest, FailureReturnsNullptr) {
  EXPECT_CALL(*mock_proxy_.get(), CallMethodAndBlockWithErrorDetails(_, _, _))
      .WillOnce(
          testing::Invoke([](dbus::MethodCall* method_call, int timeout_ms,
                             dbus::ScopedDBusError* error) {
            EXPECT_EQ(method_call->GetMember(),
                      wl::kVmWlServiveListenOnSocketMethod);
            error->get()->name = DBUS_ERROR_FAILED;
            error->get()->message = "test error";
            return nullptr;
          }));

  VmId id("test_owner_id", "test_vm_name");
  VmWlInterface::Result socket = VmWlInterface::CreateWaylandServer(
      mock_bus_.get(), id, apps::VmType::UNKNOWN);
  EXPECT_FALSE(socket.has_value());
}

TEST_F(VmWlInterfaceTest, SuccessfulCreateAndDestroy) {
  EXPECT_CALL(*mock_proxy_.get(), CallMethodAndBlockWithErrorDetails(_, _, _))
      .WillOnce(
          testing::Invoke([](dbus::MethodCall* method_call, int timeout_ms,
                             dbus::ScopedDBusError* error) {
            EXPECT_EQ(method_call->GetMember(),
                      wl::kVmWlServiveListenOnSocketMethod);
            return dbus::Response::CreateEmpty();
          }));

  VmId id("test_owner_id", "test_vm_name");

  VmWlInterface::Result socket = VmWlInterface::CreateWaylandServer(
      mock_bus_.get(), id, apps::VmType::UNKNOWN);
  EXPECT_TRUE(socket.has_value());

  EXPECT_CALL(*mock_proxy_.get(), DoCallMethodWithErrorCallback(_, _, _, _))
      .WillOnce(testing::Invoke(
          [](dbus::MethodCall* method_call, int timeout_ms,
             base::OnceCallback<void(dbus::Response*)>* success_callback,
             base::OnceCallback<void(dbus::ErrorResponse*)>* err_callback) {
            EXPECT_EQ(method_call->GetMember(),
                      wl::kVmWlServiceCloseSocketMethod);
            std::move(*success_callback).Run(nullptr);
          }));
  socket.value().reset();
}

}  // namespace vm_tools::concierge

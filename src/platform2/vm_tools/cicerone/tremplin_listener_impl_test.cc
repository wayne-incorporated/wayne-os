// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <chromeos/dbus/service_constants.h>
#include <grpcpp/grpcpp.h>
#include <grpcpp/impl/call.h>
#include <gtest/gtest.h>

#include "vm_tools/cicerone/dbus_message_testing_helper.h"
#include "vm_tools/cicerone/service.h"
#include "vm_tools/cicerone/service_testing_helper.h"
#include "vm_tools/cicerone/tremplin_listener_impl.h"

namespace vm_tools {
namespace cicerone {

namespace {

using ::testing::AllOf;
using ::testing::Invoke;

// Reads a signal and checks that it looks right.
void ProtoSignalHelper(dbus::Signal* signal,
                       google::protobuf::MessageLite* protobuf) {
  dbus::MessageReader reader(signal);
  EXPECT_TRUE(reader.PopArrayOfBytesAsProto(protobuf));
  EXPECT_FALSE(reader.HasMoreData());
}

TEST(TremplinListenerImplTest, UpdateStartLxdStatusShouldEmitDbusMessage) {
  ServiceTestingHelper test_framework(ServiceTestingHelper::NORMAL_MOCKS);
  test_framework.SetUpDefaultVmAndContainer();
  test_framework.ExpectNoDBusMessages();

  vm_tools::tremplin::StartLxdProgress request;
  vm_tools::tremplin::EmptyMessage response;

  request.set_status(vm_tools::tremplin::StartLxdProgress::STARTING);

  StartLxdProgressSignal dbus_result;
  EXPECT_CALL(test_framework.get_mock_exported_object(),
              SendSignal(AllOf(HasInterfaceName(kVmCiceroneInterface),
                               HasMethodName(kStartLxdProgressSignal))))
      .WillOnce(Invoke([&dbus_result](dbus::Signal* signal) {
        ProtoSignalHelper(signal, &dbus_result);
      }));

  grpc::ServerContext ctx;
  grpc::Status status = test_framework.get_service()
                            .GetTremplinListenerImpl()
                            ->UpdateStartLxdStatus(&ctx, &request, &response);
  ASSERT_TRUE(status.ok()) << status.error_message();

  EXPECT_EQ(dbus_result.vm_name(), ServiceTestingHelper::kDefaultVmName);
  EXPECT_EQ(dbus_result.owner_id(), ServiceTestingHelper::kDefaultOwnerId);
  EXPECT_EQ(dbus_result.status(), StartLxdProgressSignal::STARTING);
  EXPECT_EQ(dbus_result.failure_reason(), "");
}

}  // namespace

}  // namespace cicerone
}  // namespace vm_tools

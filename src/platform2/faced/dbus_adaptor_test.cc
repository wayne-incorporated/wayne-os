// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "faced/dbus_adaptor.h"

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#include <memory>
#include <utility>

#include <base/files/scoped_file.h>
#include <base/functional/bind.h>
#include <base/posix/eintr_wrapper.h>
#include <base/run_loop.h>
#include <base/test/bind.h>
#include <base/test/task_environment.h>
#include <brillo/dbus/mock_dbus_method_response.h>
#include <dbus/bus.h>
#include <dbus/mock_bus.h>
#include <dbus/mock_exported_object.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "faced/face_auth_service.h"

namespace faced {

namespace {

using ::brillo::dbus_utils::MockDBusMethodResponse;
using ::testing::_;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::StrictMock;
using ReceiveOnIpcThreadCallback =
    FaceAuthServiceInterface::ReceiveOnIpcThreadCallback;

class MockFaceAuthService : public FaceAuthServiceInterface {
 public:
  MOCK_METHOD(void,
              ReceiveMojoInvitation,
              (base::ScopedFD fd,
               ReceiveOnIpcThreadCallback callback,
               scoped_refptr<base::TaskRunner> callback_runner),
              (override));
};

base::ScopedFD CreateFakeFd() {
  // Create a pair of connected sockets.
  int fds[2];
  CHECK_EQ(0,
           HANDLE_EINTR(socketpair(AF_UNIX, SOCK_STREAM, /*protocol=*/0, fds)));

  // Close one side of the pair, and return the other.
  close(fds[1]);
  return base::ScopedFD(fds[0]);
}

}  // namespace

TEST(DBusAdaptorTest, BootstrapMojoConnection) {
  StrictMock<MockFaceAuthService> mock_service;
  ON_CALL(mock_service, ReceiveMojoInvitation(_, _, _))
      .WillByDefault(
          Invoke([&](base::ScopedFD fd, ReceiveOnIpcThreadCallback callback,
                     scoped_refptr<base::TaskRunner> callback_runner) {
            callback_runner->PostTask(
                FROM_HERE, base::BindOnce(std::move(callback), true));
          }));
  EXPECT_CALL(mock_service, ReceiveMojoInvitation).Times(1);

  // Expect call to OnBootstrapMojoConnectionResponse
  auto response = std::make_unique<MockDBusMethodResponse<>>();
  bool called = false;
  response->set_return_callback(
      base::BindLambdaForTesting([&called]() { called = true; }));

  scoped_refptr<dbus::Bus> bus =
      base::MakeRefCounted<dbus::Bus>(dbus::Bus::Options{});
  auto dbus_adaptor = std::make_unique<DBusAdaptor>(bus, mock_service);

  base::RunLoop loop;
  dbus_adaptor->BootstrapMojoConnection(std::move(response), CreateFakeFd());

  loop.RunUntilIdle();
  EXPECT_TRUE(called);
}

TEST(DBusAdaptorTest, BootstrapMojoConnectionFailure) {
  StrictMock<MockFaceAuthService> mock_service;
  ON_CALL(mock_service, ReceiveMojoInvitation(_, _, _))
      .WillByDefault(
          Invoke([&](base::ScopedFD fd, ReceiveOnIpcThreadCallback callback,
                     scoped_refptr<base::TaskRunner> callback_runner) {
            callback_runner->PostTask(
                FROM_HERE, base::BindOnce(std::move(callback), false));
          }));
  EXPECT_CALL(mock_service, ReceiveMojoInvitation).Times(1);

  base::RunLoop loop;

  // Expect error to propagate to DBusMethodResponse::ReplyWithError
  auto response = std::make_unique<MockDBusMethodResponse<>>();
  ON_CALL(*response, ReplyWithError(_))
      .WillByDefault(Invoke(
          [&](const brillo::Error* error) { loop.QuitClosure().Run(); }));
  EXPECT_CALL(*response, ReplyWithError(_)).Times(1);

  scoped_refptr<dbus::Bus> bus =
      base::MakeRefCounted<dbus::Bus>(dbus::Bus::Options{});
  auto dbus_adaptor = std::make_unique<DBusAdaptor>(bus, mock_service);

  dbus_adaptor->BootstrapMojoConnection(std::move(response), CreateFakeFd());

  loop.Run();
}

}  // namespace faced

// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/check.h>
#include <base/files/scoped_file.h>
#include <base/logging.h>
#include <base/test/task_environment.h>
#include <brillo/errors/error.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <mojo/public/cpp/bindings/remote.h>

#include "diagnostics/wilco_dtc_supportd/dbus_service.h"
#include "diagnostics/wilco_dtc_supportd/grpc_client_manager.h"
#include "diagnostics/wilco_dtc_supportd/mojo_grpc_adapter.h"
#include "diagnostics/wilco_dtc_supportd/mojo_service_factory.h"
#include "diagnostics/wilco_dtc_supportd/utils/mojo_test_utils.h"

using testing::StrictMock;
using testing::Truly;

namespace diagnostics {
namespace wilco {
namespace {

class MockCallback {
 public:
  void BindMojoServiceFactory(MojoServiceFactory::MojoReceiver* receiver,
                              base::ScopedFD mojo_pipe_fd) {
    DCHECK(receiver);
    DCHECK(mojo_pipe_fd.is_valid());

    BindMojoServiceFactoryImpl(mojo_pipe_fd);

    receiver->Bind(mojo_service_factory_remote_.BindNewPipeAndPassReceiver());
  }

  MOCK_METHOD(void,
              BindMojoServiceFactoryImpl,
              (const base::ScopedFD& mojo_pipe_fd));

  MOCK_METHOD(void, ShutDown, ());

 private:
  mojo::Remote<
      chromeos::wilco_dtc_supportd::mojom::WilcoDtcSupportdServiceFactory>
      mojo_service_factory_remote_;
};

// Tests for the DBusService class.
class DBusServiceTest : public testing::Test {
 protected:
  base::test::TaskEnvironment task_environment_;

  StrictMock<MockCallback> mock_callback_;
  GrpcClientManager grpc_client_manager_;
  MojoGrpcAdapter mojo_grpc_adapter_{&grpc_client_manager_};
  MojoServiceFactory mojo_service_factory_{
      &mojo_grpc_adapter_,
      base::BindRepeating(&MockCallback::ShutDown,
                          base::Unretained(&mock_callback_)),
      base::BindOnce(&MockCallback::BindMojoServiceFactory,
                     base::Unretained(&mock_callback_))};
  DBusService dbus_service_{&mojo_service_factory_};
};

// Test that BootstrapMojoConnection() successfully calls into the
// MojoServiceFactory when called with an valid file descriptor.
TEST_F(DBusServiceTest, BootstrapMojoConnectionBasic) {
  const FakeMojoFdGenerator fake_mojo_fd_generator;

  const auto fd_is_duplicate =
      [&fake_mojo_fd_generator](const base::ScopedFD& fd) {
        return fake_mojo_fd_generator.IsDuplicateFd(fd.get());
      };

  EXPECT_CALL(mock_callback_,
              BindMojoServiceFactoryImpl(Truly(fd_is_duplicate)));

  brillo::ErrorPtr error;
  EXPECT_TRUE(dbus_service_.BootstrapMojoConnection(
      &error, fake_mojo_fd_generator.MakeFd()));
  EXPECT_FALSE(error);
}

// Test that BootstrapMojoConnection() fails before even attempting to bind in
// the MojoServiceFactory in case an empty file descriptor is supplied.
TEST_F(DBusServiceTest, BootstrapMojoConnectionEmptyFd) {
  brillo::ErrorPtr error;
  EXPECT_FALSE(dbus_service_.BootstrapMojoConnection(
      &error, base::ScopedFD() /* mojo_pipe_fd */));
  EXPECT_TRUE(error);
}

}  // namespace
}  // namespace wilco
}  // namespace diagnostics

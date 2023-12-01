// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "mojo_service_manager/daemon/daemon_test_helper.h"

#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <cstdlib>
#include <string>
#include <utility>

#include <base/check_op.h>
#include <base/files/file_util.h>
#include <base/posix/eintr_wrapper.h>
#include <base/test/bind.h>
#include <base/test/test_timeouts.h>
#include <base/threading/platform_thread.h>
#include <base/timer/elapsed_timer.h>
#include <chromeos/constants/mojo_service_manager.h>
#include <mojo/core/embedder/embedder.h>
#include <mojo/public/cpp/bindings/remote.h>
#include <mojo/public/cpp/platform/platform_channel.h>
#include <mojo/public/cpp/system/invitation.h>

#include "mojo_service_manager/lib/connect.h"
#include "mojo_service_manager/lib/mojom/service_manager.mojom.h"
#include "mojo_service_manager/testing/mojo_test_environment.h"

namespace {

namespace mojo_service_manager = chromeos::mojo_service_manager;
namespace mojom = mojo_service_manager::mojom;

}  // namespace

int main(int argc, char** argv) {
  base::CommandLine::Init(argc, argv);
  TestTimeouts::Initialize();
  mojo::core::Init();
  mojo_service_manager::MojoTaskEnvironment env;

  base::FilePath socket_path =
      base::CommandLine::ForCurrentProcess()->GetSwitchValuePath(
          mojo_service_manager::kSocketPathSwitch);
  mojo::Remote<mojom::ServiceManager> mojo_service_manager{
      mojo_service_manager::ConnectToMojoServiceManagerForTesting(socket_path)};
  CHECK(mojo_service_manager.is_connected());

  mojo_service_manager::DaemonTestHelperResult result =
      mojo_service_manager::DaemonTestHelperResult::kConnectSuccessfully;
  mojo_service_manager.set_disconnect_with_reason_handler(
      base::BindLambdaForTesting([&](uint32_t error,
                                     const std::string& message) {
        CHECK_EQ(error,
                 static_cast<uint32_t>(mojom::ErrorCode::kUnexpectedOsError));
        result =
            mojo_service_manager::DaemonTestHelperResult::kResetWithOsError;
      }));

  // Make sure the state is updated.
  mojo_service_manager.FlushForTesting();
  return static_cast<int>(result);
}

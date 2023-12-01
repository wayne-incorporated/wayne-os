// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ocr/daemon.h"

#include <memory>
#include <string>
#include <sysexits.h>
#include <utility>

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/logging.h>
#include <base/task/single_thread_task_runner.h>
#include <base/unguessable_token.h>
#include <dbus/object_path.h>
#include <chromeos/dbus/service_constants.h>
#include <mojo/public/cpp/platform/platform_channel_endpoint.h>
#include <mojo/public/cpp/system/invitation.h>
#include <mojo/core/embedder/embedder.h>

#include "ocr/ocr_service_impl.h"

namespace ocr {

OcrDaemon::OcrDaemon() : brillo::DBusServiceDaemon(kOcrServiceName) {
  ocr_service_impl_ = std::make_unique<OcrServiceImpl>();
  ocr_service_impl_->SetOnDisconnectCallback(base::BindRepeating(
      &OcrDaemon::OnDisconnect, weak_ptr_factory_.GetWeakPtr()));
}

OcrDaemon::~OcrDaemon() = default;

int OcrDaemon::OnInit() {
  int return_code = brillo::DBusServiceDaemon::OnInit();
  if (return_code != EX_OK)
    return return_code;

  // Initialize Mojo IPC.
  mojo::core::Init();
  ipc_support_ = std::make_unique<mojo::core::ScopedIPCSupport>(
      base::SingleThreadTaskRunner::
          GetCurrentDefault() /* io_thread_task_runner */,
      mojo::core::ScopedIPCSupport::ShutdownPolicy::
          CLEAN /* blocking shutdown */);

  return EX_OK;
}

void OcrDaemon::RegisterDBusObjectsAsync(
    brillo::dbus_utils::AsyncEventSequencer* sequencer) {
  DCHECK(!dbus_object_);
  dbus_object_ = std::make_unique<brillo::dbus_utils::DBusObject>(
      nullptr /* object_manager */, bus_, dbus::ObjectPath(kOcrServicePath));
  brillo::dbus_utils::DBusInterface* dbus_interface =
      dbus_object_->AddOrGetInterface(kOcrServiceInterface);
  DCHECK(dbus_interface);
  dbus_interface->AddSimpleMethodHandler(kBootstrapMojoConnectionMethod,
                                         base::Unretained(this),
                                         &OcrDaemon::BootstrapMojoConnection);
  dbus_object_->RegisterAsync(sequencer->GetHandler(
      "Failed to register D-Bus object" /* descriptive_message */,
      true /* failure_is_fatal */));
}

std::string OcrDaemon::BootstrapMojoConnection(const base::ScopedFD& mojo_fd,
                                               bool should_accept_invitation) {
  VLOG(1) << "Received BootstrapMojoConnection D-Bus request";

  if (!mojo_fd.is_valid()) {
    constexpr char kInvalidFileDescriptorError[] =
        "ScopedFD extracted from D-Bus call was invalid (i.e. empty)";
    LOG(ERROR) << kInvalidFileDescriptorError;
    return kInvalidFileDescriptorError;
  }

  // We need a file descriptor that stays alive after the current method
  // finishes, but libbrillo's D-Bus wrappers currently don't support passing
  // base::ScopedFD by value.
  base::ScopedFD mojo_fd_copy(HANDLE_EINTR(dup(mojo_fd.get())));
  if (!mojo_fd_copy.is_valid()) {
    constexpr char kFailedDuplicationError[] =
        "Failed to duplicate the Mojo file descriptor";
    PLOG(ERROR) << kFailedDuplicationError;
    return kFailedDuplicationError;
  }

  if (!base::SetCloseOnExec(mojo_fd_copy.get())) {
    constexpr char kFailedSettingFdCloexec[] =
        "Failed to set FD_CLOEXEC on Mojo file descriptor";
    PLOG(ERROR) << kFailedSettingFdCloexec;
    return kFailedSettingFdCloexec;
  }

  std::string token;
  mojo::ScopedMessagePipeHandle mojo_message_pipe;
  if (should_accept_invitation) {
    if (mojo_service_bind_attempted_) {
      // This should not normally be triggered, since the other endpoint - the
      // browser process - should bootstrap the Mojo connection only once, and
      // when that process is killed the Mojo shutdown notification should have
      // been received earlier. But handle this case to be on the safe side.
      // After we restart, the browser process is expected to invoke the
      // bootstrapping again.
      LOG(ERROR) << "Shutting down due to repeated Mojo bootstrap requests";
      ocr_service_impl_.reset();
      Quit();
      return "";
    }

    // Connect to Mojo in the requesting process.
    mojo::IncomingInvitation invitation =
        mojo::IncomingInvitation::Accept(mojo::PlatformChannelEndpoint(
            mojo::PlatformHandle(std::move(mojo_fd_copy))));
    mojo_message_pipe =
        invitation.ExtractMessagePipe(kBootstrapMojoConnectionChannelToken);
    mojo_service_bind_attempted_ = true;
  } else {
    // Create a unique token which will allow the requesting process to connect
    // to us via Mojo.
    mojo::OutgoingInvitation invitation;
    token = base::UnguessableToken::Create().ToString();
    mojo_message_pipe = invitation.AttachMessagePipe(token);
    mojo::OutgoingInvitation::Send(
        std::move(invitation), base::kNullProcessHandle,
        mojo::PlatformChannelEndpoint(
            mojo::PlatformHandle(std::move(mojo_fd_copy))));
  }
  ocr_service_impl_->AddReceiver(
      mojo::PendingReceiver<
          chromeos::ocr::mojom::OpticalCharacterRecognitionService>(
          std::move(mojo_message_pipe)),
      should_accept_invitation);
  VLOG(1) << "Successfully bootstrapped Mojo connection";
  return token;
}

void OcrDaemon::OnDisconnect(bool should_quit) {
  if (should_quit) {
    LOG(ERROR) << "OcrDaemon lost Mojo connection to the browser; quitting.";
    ocr_service_impl_.reset();
    Quit();
  }
}

}  // namespace ocr

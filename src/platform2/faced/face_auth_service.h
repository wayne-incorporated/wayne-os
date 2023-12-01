// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FACED_FACE_AUTH_SERVICE_H_
#define FACED_FACE_AUTH_SERVICE_H_

#include <memory>
#include <string>

#include <absl/status/statusor.h>
#include <base/files/file_util.h>
#include <base/memory/weak_ptr.h>
#include <base/task/single_thread_task_runner.h>
#include <base/threading/thread.h>
#include <mojo/core/embedder/scoped_ipc_support.h>
#include <mojo/public/cpp/system/invitation.h>

#include "faced/face_auth_service_impl.h"
#include "faced/face_service.h"

namespace faced {

// Interface to aid in testing the FaceAuthService
class FaceAuthServiceInterface {
 public:
  virtual ~FaceAuthServiceInterface() = default;

  using ReceiveOnIpcThreadCallback = base::OnceCallback<void(bool /*success*/)>;

  using CriticalErrorCallback = base::OnceCallback<void(std::string /*error*/)>;

  // Handle an incoming Mojo invitation.
  //
  // `fd` is the file descriptor handle to the Mojo pipe.
  // `callback` is called when the mojo invitation is bound to the service
  // implementation, and will be called on the given `callback_runner`.
  virtual void ReceiveMojoInvitation(
      base::ScopedFD fd,
      ReceiveOnIpcThreadCallback callback,
      scoped_refptr<base::TaskRunner> callback_runner) = 0;
};

// Entrypoint to the Mojo IPC for face auth service implementation
class FaceAuthService : public FaceAuthServiceInterface {
 public:
  static absl::StatusOr<std::unique_ptr<FaceAuthService>> Create();
  ~FaceAuthService() override = default;

  // Disallow copy and move.
  FaceAuthService(const FaceAuthService&) = delete;
  FaceAuthService& operator=(const FaceAuthService&) = delete;

  void ReceiveMojoInvitation(
      base::ScopedFD fd,
      ReceiveOnIpcThreadCallback callback,
      scoped_refptr<base::TaskRunner> callback_runner) override;

 private:
  FaceAuthService();
  void SetupMojoPipeOnThread(mojo::IncomingInvitation invitation,
                             ReceiveOnIpcThreadCallback callback,
                             scoped_refptr<base::TaskRunner> callback_runner);

  // Responds to Mojo broker disconnection
  void OnDisconnect();

  CriticalErrorCallback error_callback_;
  scoped_refptr<base::TaskRunner> error_task_runner_;

  // Handle for mojo IPC shutdown gracefully.
  std::unique_ptr<mojo::core::ScopedIPCSupport> ipc_support_;

  // Separate thread for doing IPC via Mojo because Mojo is asynchronous
  // by default.
  base::Thread ipc_thread_;

  scoped_refptr<base::SingleThreadTaskRunner> mojo_task_runner_;

  std::unique_ptr<FaceServiceManagerInterface> face_service_manager_;
  std::unique_ptr<FaceAuthServiceImpl> service_;
};

}  // namespace faced

#endif  // FACED_FACE_AUTH_SERVICE_H_

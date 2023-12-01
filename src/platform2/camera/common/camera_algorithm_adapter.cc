/*
 * Copyright 2017 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "common/camera_algorithm_adapter.h"

#include <dlfcn.h>

#include <memory>
#include <string>
#include <utility>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/notreached.h>
#include <mojo/core/embedder/embedder.h>
#include <mojo/core/embedder/scoped_ipc_support.h>
#include <mojo/public/cpp/bindings/pending_receiver.h>
#include <mojo/public/cpp/system/invitation.h>

#include "cros-camera/camera_algorithm.h"
#include "cros-camera/common.h"

namespace cros {

namespace {

const char* GetAlgorithmLibraryName(const std::string& pipe_name) {
  // TODO(kamesan): Arrange the library names in some format like
  // libcam_algo_<pipe_name>.so
  if (pipe_name == "vendor_cpu") {
    return "libcam_algo.so";
  }
  if (pipe_name == "vendor_gpu") {
    return "libcam_algo_vendor_gpu.so";
  }
  if (pipe_name == "google_gpu") {
    return "libcros_camera.so";
  }
  if (pipe_name == "test") {
    return "libcam_algo_test.so";
  }
  NOTREACHED() << "Unknown message pipe name: " << pipe_name;
  return "";
}

}  // namespace

CameraAlgorithmAdapter::CameraAlgorithmAdapter()
    : algo_impl_(CameraAlgorithmOpsImpl::GetInstance()),
      is_algo_impl_bound_(false),
      algo_dll_handle_(nullptr),
      ipc_thread_("IPC thread") {}

CameraAlgorithmAdapter::~CameraAlgorithmAdapter() = default;

void CameraAlgorithmAdapter::Run(std::string pipe_name,
                                 base::ScopedFD channel) {
  auto future = cros::Future<void>::Create(&relay_);
  ipc_lost_cb_ = cros::GetFutureCallback(future);
  ipc_thread_.StartWithOptions(
      base::Thread::Options(base::MessagePumpType::IO, 0));
  ipc_thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&CameraAlgorithmAdapter::InitializeOnIpcThread,
                     base::Unretained(this), pipe_name, std::move(channel)));
  future->Wait(-1);
  exit(EXIT_SUCCESS);
}

void CameraAlgorithmAdapter::InitializeOnIpcThread(std::string pipe_name,
                                                   base::ScopedFD channel) {
  DCHECK(ipc_thread_.task_runner()->BelongsToCurrentThread());
  VLOGF(1) << "Setting up message pipe, name: " << pipe_name;
  mojo::core::Init();
  ipc_support_ = std::make_unique<mojo::core::ScopedIPCSupport>(
      ipc_thread_.task_runner(),
      mojo::core::ScopedIPCSupport::ShutdownPolicy::FAST);
  mojo::IncomingInvitation invitation = mojo::IncomingInvitation::Accept(
      mojo::PlatformChannelEndpoint(mojo::PlatformHandle(std::move(channel))));
  mojo::PendingReceiver<mojom::CameraAlgorithmOps> pending_receiver(
      invitation.ExtractMessagePipe(pipe_name));

  const char* algo_lib_name = GetAlgorithmLibraryName(pipe_name);
  algo_dll_handle_ = dlopen(algo_lib_name, RTLD_NOW);
  if (!algo_dll_handle_) {
    LOGF(ERROR) << "Failed to dlopen: " << dlerror();
    DestroyOnIpcThread();
    return;
  }
  camera_algorithm_ops_t* cam_algo = static_cast<camera_algorithm_ops_t*>(
      dlsym(algo_dll_handle_, CAMERA_ALGORITHM_MODULE_INFO_SYM_AS_STR));
  if (!cam_algo) {
    LOGF(ERROR) << "Camera algorithm is invalid";
    DestroyOnIpcThread();
    return;
  }

  base::OnceClosure ipc_lost_handler = base::BindOnce(
      &CameraAlgorithmAdapter::DestroyOnIpcThread, base::Unretained(this));
  if (!algo_impl_->Bind(std::move(pending_receiver), cam_algo,
                        ipc_thread_.task_runner(),
                        std::move(ipc_lost_handler))) {
    LOGF(ERROR) << "Failed to bind algorithm implementation";
    DestroyOnIpcThread();
    return;
  }
  is_algo_impl_bound_ = true;
}

void CameraAlgorithmAdapter::DestroyOnIpcThread() {
  DCHECK(ipc_thread_.task_runner()->BelongsToCurrentThread());

  if (is_algo_impl_bound_) {
    algo_impl_->Deinitialize();
    algo_impl_->Unbind();
  }

  ipc_support_ = nullptr;
  if (algo_dll_handle_) {
    dlclose(algo_dll_handle_);
  }
  std::move(ipc_lost_cb_).Run();
}

}  // namespace cros

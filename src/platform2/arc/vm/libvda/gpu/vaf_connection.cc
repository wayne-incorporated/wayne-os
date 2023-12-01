// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/vm/libvda/gpu/vaf_connection.h"

#include <fcntl.h>

#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <base/memory/ref_counted.h>
#include <base/posix/eintr_wrapper.h>
#include <base/synchronization/lock.h>
#include <base/synchronization/waitable_event.h>
#include <base/task/single_thread_task_runner.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/bus.h>
#include <dbus/message.h>
#include <dbus/object_path.h>
#include <dbus/object_proxy.h>
#include <mojo/core/embedder/embedder.h>
#include <mojo/public/cpp/system/invitation.h>
#include <mojo/public/cpp/system/platform_handle.h>
#include <sys/eventfd.h>

#include "arc/vm/libvda/gpu/mojom/video_decode_accelerator.mojom.h"
#include "arc/vm/libvda/gpu/mojom/video_decoder.mojom.h"
#include "arc/vm/libvda/gpu/mojom/video_encode_accelerator.mojom.h"

namespace arc {

namespace {

// Minimum required version of VideoAcceleratorFactory interface.
// Set to 6 which is when CreateDecodeAccelerator was introduced.
constexpr uint32_t kRequiredVideoAcceleratorFactoryMojoVersion = 6;

static base::Lock connection_lock;
static VafConnection* connection = nullptr;

}  // namespace

void RunTaskOnThread(scoped_refptr<base::SingleThreadTaskRunner> task_runner,
                     base::OnceClosure task) {
  if (task_runner->BelongsToCurrentThread()) {
    LOG(WARNING) << "RunTaskOnThread called on target thread.";
    std::move(task).Run();
    return;
  }

  base::WaitableEvent task_complete_event(
      base::WaitableEvent::ResetPolicy::MANUAL,
      base::WaitableEvent::InitialState::NOT_SIGNALED);
  task_runner->PostTask(
      FROM_HERE,
      base::BindOnce(
          [](base::OnceClosure task, base::WaitableEvent* task_complete_event) {
            std::move(task).Run();
            task_complete_event->Signal();
          },
          std::move(task), &task_complete_event));
  task_complete_event.Wait();
}

VafConnection::VafConnection() : ipc_thread_("VafConnectionIpcThread") {
  DETACH_FROM_THREAD(ipc_thread_checker_);

  mojo::core::Init();
  CHECK(ipc_thread_.StartWithOptions(
      base::Thread::Options(base::MessagePumpType::IO, 0)));
  ipc_support_ = std::make_unique<mojo::core::ScopedIPCSupport>(
      ipc_thread_.task_runner(),
      mojo::core::ScopedIPCSupport::ShutdownPolicy::FAST);
}

VafConnection::~VafConnection() {
  RunTaskOnThread(ipc_thread_.task_runner(),
                  base::BindOnce(&VafConnection::CleanupOnIpcThread,
                                 base::Unretained(this)));
  ipc_support_ = nullptr;
}

void VafConnection::CleanupOnIpcThread() {
  DCHECK_CALLED_ON_VALID_THREAD(ipc_thread_checker_);
  if (remote_factory_.is_bound())
    remote_factory_.reset();
}

bool VafConnection::Initialize() {
  bool init_success = false;
  RunTaskOnThread(ipc_thread_.task_runner(),
                  base::BindOnce(&VafConnection::InitializeOnIpcThread,
                                 base::Unretained(this), &init_success));
  return init_success;
}

void VafConnection::InitializeOnIpcThread(bool* init_success) {
  // Since ipc_thread_checker_ binds to whichever thread it's created on, check
  // that we're on the correct thread first using BelongsToCurrentThread.
  DCHECK(ipc_thread_.task_runner()->BelongsToCurrentThread());
  DCHECK_CALLED_ON_VALID_THREAD(ipc_thread_checker_);

  dbus::Bus::Options opts;
  opts.bus_type = dbus::Bus::SYSTEM;
  scoped_refptr<dbus::Bus> bus = new dbus::Bus(std::move(opts));
  if (!bus->Connect()) {
    DLOG(ERROR) << "Failed to connect to system bus";
    return;
  }

  dbus::ObjectProxy* proxy = bus->GetObjectProxy(
      libvda::kLibvdaServiceName, dbus::ObjectPath(libvda::kLibvdaServicePath));
  if (!proxy) {
    // TODO(alexlau): Would this ever start before Chrome such that we should
    //                call WaitForServiceToBeAvailable here?
    DLOG(ERROR) << "Unable to get dbus proxy for "
                << libvda::kLibvdaServiceName;
    return;
  }

  dbus::MethodCall method_call(libvda::kLibvdaServiceInterface,
                               libvda::kProvideMojoConnectionMethod);
  std::unique_ptr<dbus::Response> response(proxy->CallMethodAndBlock(
      &method_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT));
  if (!response.get()) {
    DLOG(ERROR) << "Unable to get response from method call "
                << libvda::kProvideMojoConnectionMethod;
    return;
  }

  dbus::MessageReader reader(response.get());

  // Read the mojo pipe FD.
  base::ScopedFD fd;
  if (!reader.PopFileDescriptor(&fd)) {
    DLOG(ERROR) << "Unable to read mojo pipe fd";
    return;
  }
  if (!fd.is_valid()) {
    DLOG(ERROR) << "Received invalid mojo pipe fd";
    return;
  }

  std::string pipe_name;
  if (!reader.PopString(&pipe_name)) {
    DLOG(ERROR) << "Unable to read mojo pipe name.";
    return;
  }

  // Setup the mojo pipe.
  mojo::IncomingInvitation invitation = mojo::IncomingInvitation::Accept(
      mojo::PlatformChannelEndpoint(mojo::PlatformHandle(std::move(fd))));
  mojo::PendingRemote<arc::mojom::VideoAcceleratorFactory> pending_factory(
      invitation.ExtractMessagePipe(pipe_name),
      kRequiredVideoAcceleratorFactoryMojoVersion);
  remote_factory_.Bind(std::move(pending_factory));
  remote_factory_.set_disconnect_with_reason_handler(base::BindRepeating(
      &VafConnection::OnFactoryError, base::Unretained(this)));

  *init_success = true;
}

void VafConnection::OnFactoryError(uint32_t custom_reason,
                                   const std::string& description) {
  DCHECK_CALLED_ON_VALID_THREAD(ipc_thread_checker_);
  DLOG(ERROR) << "VideoAcceleratorFactory mojo connection error. custom_reason="
              << custom_reason << " description=" << description;
}

scoped_refptr<base::SingleThreadTaskRunner> VafConnection::GetIpcTaskRunner() {
  return ipc_thread_.task_runner();
}

mojo::Remote<arc::mojom::VideoDecodeAccelerator>
VafConnection::CreateDecodeAccelerator() {
  mojo::Remote<arc::mojom::VideoDecodeAccelerator> remote_vda;
  // Using Unretained is safe here as the IPC thread is owned by this class.
  RunTaskOnThread(
      ipc_thread_.task_runner(),
      base::BindOnce(&VafConnection::CreateDecodeAcceleratorOnIpcThread,
                     base::Unretained(this), &remote_vda));
  return remote_vda;
}

void VafConnection::CreateDecodeAcceleratorOnIpcThread(
    mojo::Remote<arc::mojom::VideoDecodeAccelerator>* remote_vda) {
  remote_factory_->CreateDecodeAccelerator(
      remote_vda->BindNewPipeAndPassReceiver());
}

mojo::Remote<arc::mojom::VideoDecoder> VafConnection::CreateVideoDecoder() {
  mojo::Remote<arc::mojom::VideoDecoder> remote_vd;
  // Using Unretained is safe here as the IPC thread is owned by this class.
  RunTaskOnThread(ipc_thread_.task_runner(),
                  base::BindOnce(&VafConnection::CreateVideoDecoderOnIpcThread,
                                 base::Unretained(this), &remote_vd));
  return remote_vd;
}

void VafConnection::CreateVideoDecoderOnIpcThread(
    mojo::Remote<arc::mojom::VideoDecoder>* remote_vd) {
  remote_factory_->CreateVideoDecoder(remote_vd->BindNewPipeAndPassReceiver());
}

mojo::Remote<arc::mojom::VideoEncodeAccelerator>
VafConnection::CreateEncodeAccelerator() {
  mojo::Remote<arc::mojom::VideoEncodeAccelerator> remote_vea;
  // Using Unretained is safe here as the IPC thread is owned by this class.
  RunTaskOnThread(
      ipc_thread_.task_runner(),
      base::BindOnce(&VafConnection::CreateEncodeAcceleratorOnIpcThread,
                     base::Unretained(this), &remote_vea));
  return remote_vea;
}

void VafConnection::CreateEncodeAcceleratorOnIpcThread(
    mojo::Remote<arc::mojom::VideoEncodeAccelerator>* remote_vea) {
  remote_factory_->CreateEncodeAccelerator(
      remote_vea->BindNewPipeAndPassReceiver());
}

VafConnection* VafConnection::Get() {
  {
    base::AutoLock lock(connection_lock);
    if (connection == nullptr) {
      auto instance = std::unique_ptr<VafConnection>(new VafConnection());
      if (!instance->Initialize()) {
        LOG(ERROR) << "Could not initialize VafConnection.";
        return nullptr;
      }
      connection = instance.release();
    }
  }
  return connection;
}

}  // namespace arc

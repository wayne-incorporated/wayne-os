/*
 * Copyright 2016 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_COMMON_UTILS_CROS_CAMERA_MOJO_UTILS_H_
#define CAMERA_COMMON_UTILS_CROS_CAMERA_MOJO_UTILS_H_

#include <map>
#include <memory>
#include <unordered_map>
#include <utility>

#include <hardware/camera3.h>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/synchronization/lock.h>
#include <base/task/single_thread_task_runner.h>
#include <mojo/public/cpp/bindings/associated_remote.h>
#include <mojo/public/cpp/bindings/pending_receiver.h>
#include <mojo/public/cpp/bindings/pending_remote.h>
#include <mojo/public/cpp/bindings/receiver.h>
#include <mojo/public/cpp/bindings/remote.h>

#include "camera/mojo/camera3.mojom.h"
#include "common/camera_buffer_handle.h"
#include "common/utils/common_types.h"
#include "cros-camera/common.h"
#include "cros-camera/future.h"

namespace cros::internal {

// Serialize / deserialize helper functions.

// SerializeStreamBuffer is used in CameraDeviceAdapter::ProcessCaptureResult to
// pass a result buffer handle through Mojo.  For the input / output buffers, we
// do not need to serialize the whole native handle but instead we can simply
// return their corresponding handle IDs.  When the receiver gets the result it
// will restore using the handle ID the original buffer handles which were
// passed down when the frameworks called process_capture_request.
cros::mojom::Camera3StreamBufferPtr SerializeStreamBuffer(
    const camera3_stream_buffer_t* buffer,
    const ScopedStreams& streams,
    const std::unordered_map<uint64_t, std::unique_ptr<camera_buffer_handle_t>>&
        buffer_handles);

int DeserializeStreamBuffer(
    const cros::mojom::Camera3StreamBufferPtr& ptr,
    const ScopedStreams& streams,
    const std::unordered_map<uint64_t, std::unique_ptr<camera_buffer_handle_t>>&
        buffer_handles,
    camera3_stream_buffer_t* buffer);

cros::mojom::CameraMetadataPtr SerializeCameraMetadata(
    const camera_metadata_t* metadata);

ScopedCameraMetadata DeserializeCameraMetadata(
    const cros::mojom::CameraMetadataPtr& metadata);
// Template classes for Mojo IPC delegates

// A wrapper around a mojo::Remote<T>.  This template class represents a
// Mojo remote to a Mojo receiver implementation of T.
template <typename RemoteType>
class MojoRemoteBase
    : public base::SupportsWeakPtr<MojoRemoteBase<RemoteType>> {
 public:
  using Self = MojoRemoteBase<RemoteType>;
  explicit MojoRemoteBase(
      scoped_refptr<base::SingleThreadTaskRunner> task_runner)
      : task_runner_(task_runner) {}

  // Move-only class.
  MojoRemoteBase(MojoRemoteBase<RemoteType>&& other) = default;
  MojoRemoteBase& operator=(MojoRemoteBase<RemoteType>&& other) = default;
  MojoRemoteBase(const MojoRemoteBase<RemoteType>& other) = delete;
  MojoRemoteBase& operator=(const MojoRemoteBase<RemoteType>& other) = delete;

  void Bind(typename RemoteType::PendingType pending_remote,
            base::OnceClosure disconnect_handler) {
    task_runner_->PostTask(
        FROM_HERE, base::BindOnce(&Self::BindOnThread, base::AsWeakPtr(this),
                                  std::move(pending_remote),
                                  std::move(disconnect_handler)));
  }

  ~MojoRemoteBase() {
    // We need to wait for ResetRemoteOnThread to finish before return
    // otherwise it would cause race condition in destruction of
    // |remote_| and may CHECK.
    auto future = cros::Future<void>::Create(nullptr);
    if (task_runner_->BelongsToCurrentThread()) {
      ResetRemoteOnThread(cros::GetFutureCallback(future));
    } else {
      task_runner_->PostTask(
          FROM_HERE,
          base::BindOnce(&Self::ResetRemoteOnThread, base::AsWeakPtr(this),
                         cros::GetFutureCallback(future)));
    }
    future->Wait();
  }

 protected:
  // All the Mojo communication happens on |task_runner_|.
  const scoped_refptr<base::SingleThreadTaskRunner> task_runner_;

  RemoteType remote_;

  // For the future objects in derived class.
  CancellationRelay relay_;

 private:
  void BindOnThread(typename RemoteType::PendingType pending_remote,
                    base::OnceClosure disconnect_handler) {
    DCHECK(task_runner_->BelongsToCurrentThread());
    remote_.Bind(std::move(pending_remote));
    if (!remote_.is_bound()) {
      LOGF(ERROR) << "Failed to bind pending remote";
      return;
    }
    remote_.set_disconnect_handler(std::move(disconnect_handler));
    LOGF(INFO) << "Bridge ready";
  }

  void ResetRemoteOnThread(base::OnceClosure callback) {
    DCHECK(task_runner_->BelongsToCurrentThread());
    remote_.reset();
    std::move(callback).Run();
  }
};

template <typename T>
using MojoRemote = MojoRemoteBase<mojo::Remote<T>>;

template <typename T>
using MojoAssociatedRemote = MojoRemoteBase<mojo::AssociatedRemote<T>>;

// A wrapper around a mojo::Receiver<T>.  This template class represents a
// receiver implementation of Mojo interface T.
template <typename T>
class MojoReceiver : public T {
 public:
  explicit MojoReceiver(scoped_refptr<base::SingleThreadTaskRunner> task_runner)
      : task_runner_(task_runner), receiver_(this), weak_ptr_factory_(this) {}

  // Move-only class.
  MojoReceiver(MojoReceiver<T>&& other) = default;
  MojoReceiver& operator=(MojoReceiver<T>&& other) = default;
  MojoReceiver(const MojoReceiver<T>& other) = delete;
  MojoReceiver& operator=(const MojoReceiver<T>& other) = delete;

  ~MojoReceiver() {
    // We need to wait for ResetReceiverOnThread to finish before return
    // otherwise it would cause race condition in destruction of |receiver_| and
    // may CHECK.
    auto future = cros::Future<void>::Create(nullptr);
    if (task_runner_->BelongsToCurrentThread()) {
      ResetReceiverOnThread(cros::GetFutureCallback(future));
    } else {
      task_runner_->PostTask(
          FROM_HERE, base::BindOnce(&MojoReceiver<T>::ResetReceiverOnThread,
                                    weak_ptr_factory_.GetWeakPtr(),
                                    cros::GetFutureCallback(future)));
    }
    future->Wait();
  }

  mojo::Remote<T> CreateRemote(base::OnceClosure disconnect_handler) {
    auto future = cros::Future<mojo::Remote<T>>::Create(nullptr);
    if (task_runner_->BelongsToCurrentThread()) {
      CreateRemoteOnThread(std::move(disconnect_handler),
                           cros::GetFutureCallback(future));
    } else {
      task_runner_->PostTask(
          FROM_HERE, base::BindOnce(&MojoReceiver<T>::CreateRemoteOnThread,
                                    weak_ptr_factory_.GetWeakPtr(),
                                    std::move(disconnect_handler),
                                    cros::GetFutureCallback(future)));
    }
    return future->Get();
  }

  void Bind(mojo::PendingReceiver<T> pending_receiver,
            base::OnceClosure disconnect_handler) {
    task_runner_->PostTask(FROM_HERE,
                           base::BindOnce(&MojoReceiver<T>::BindOnThread,
                                          weak_ptr_factory_.GetWeakPtr(),
                                          std::move(pending_receiver),
                                          std::move(disconnect_handler)));
  }

 protected:
  // All the methods of T that this class implements run on |task_runner_|.
  const scoped_refptr<base::SingleThreadTaskRunner> task_runner_;

 private:
  void ResetReceiverOnThread(base::OnceClosure callback) {
    DCHECK(task_runner_->BelongsToCurrentThread());
    if (receiver_.is_bound()) {
      receiver_.reset();
    }
    std::move(callback).Run();
  }

  void CreateRemoteOnThread(base::OnceClosure disconnect_handler,
                            base::OnceCallback<void(mojo::Remote<T>)> cb) {
    // Call BindNewPipeAndPassRemote() on thread_ to serve the mojo IPC.

    DCHECK(task_runner_->BelongsToCurrentThread());
    mojo::Remote<T> remote = receiver_.BindNewPipeAndPassRemote();
    receiver_.set_disconnect_handler(std::move(disconnect_handler));
    std::move(cb).Run(std::move(remote));
  }

  void BindOnThread(mojo::PendingReceiver<T> pending_receiver,
                    base::OnceClosure disconnect_handler) {
    DCHECK(task_runner_->BelongsToCurrentThread());
    receiver_.Bind(std::move(pending_receiver));
    receiver_.set_disconnect_handler(std::move(disconnect_handler));
  }

  mojo::Receiver<T> receiver_;

  base::WeakPtrFactory<MojoReceiver<T>> weak_ptr_factory_;
};

}  // namespace cros::internal

#endif  // CAMERA_COMMON_UTILS_CROS_CAMERA_MOJO_UTILS_H_

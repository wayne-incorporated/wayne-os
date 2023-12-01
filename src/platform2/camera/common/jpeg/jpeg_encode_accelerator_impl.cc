/*
 * Copyright 2018 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "common/jpeg/jpeg_encode_accelerator_impl.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <utility>

#include <algorithm>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/memory/ptr_util.h>
#include <base/posix/eintr_wrapper.h>
#include <base/run_loop.h>
#include <mojo/public/c/system/buffer.h>
#include <mojo/public/cpp/system/buffer.h>
#include <mojo/public/cpp/system/platform_handle.h>

#include "camera/mojo/gpu/dmabuf.mojom.h"
#include "common/jpeg/tracing.h"
#include "cros-camera/common.h"
#include "cros-camera/future.h"
#include "cros-camera/ipc_util.h"

#define STATIC_ASSERT_ENUM(name)                                 \
  static_assert(static_cast<int>(JpegEncodeAccelerator::name) == \
                    static_cast<int>(mojom::EncodeStatus::name), \
                "mismatching enum: " #name)

namespace cros {

STATIC_ASSERT_ENUM(ENCODE_OK);
STATIC_ASSERT_ENUM(HW_JPEG_ENCODE_NOT_SUPPORTED);
STATIC_ASSERT_ENUM(THREAD_CREATION_FAILED);
STATIC_ASSERT_ENUM(INVALID_ARGUMENT);
STATIC_ASSERT_ENUM(INACCESSIBLE_OUTPUT_BUFFER);
STATIC_ASSERT_ENUM(PARSE_IMAGE_FAILED);
STATIC_ASSERT_ENUM(PLATFORM_FAILURE);

// static
std::unique_ptr<JpegEncodeAccelerator> JpegEncodeAccelerator::CreateInstance(
    CameraMojoChannelManagerToken* token) {
  return base::WrapUnique<JpegEncodeAccelerator>(new JpegEncodeAcceleratorImpl(
      CameraMojoChannelManager::FromToken(token)));
}

JpegEncodeAcceleratorImpl::JpegEncodeAcceleratorImpl(
    CameraMojoChannelManager* mojo_manager)
    : task_id_(0),
      mojo_manager_(mojo_manager),
      cancellation_relay_(new CancellationRelay),
      ipc_bridge_(new IPCBridge(mojo_manager, cancellation_relay_.get())) {
  TRACE_JPEG_DEBUG();
}

JpegEncodeAcceleratorImpl::~JpegEncodeAcceleratorImpl() {
  TRACE_JPEG_DEBUG();

  bool result = mojo_manager_->GetIpcTaskRunner()->DeleteSoon(
      FROM_HERE, std::move(ipc_bridge_));
  DCHECK(result);
  cancellation_relay_ = nullptr;
}

bool JpegEncodeAcceleratorImpl::Start() {
  TRACE_JPEG();

  auto is_initialized = Future<bool>::Create(cancellation_relay_.get());

  mojo_manager_->GetIpcTaskRunner()->PostTask(
      FROM_HERE, base::BindOnce(&JpegEncodeAcceleratorImpl::IPCBridge::Start,
                                ipc_bridge_->GetWeakPtr(),
                                cros::GetFutureCallback(is_initialized)));
  if (!is_initialized->Wait()) {
    return false;
  }

  return is_initialized->Get();
}

int JpegEncodeAcceleratorImpl::EncodeSync(int input_fd,
                                          const uint8_t* input_buffer,
                                          uint32_t input_buffer_size,
                                          int32_t coded_size_width,
                                          int32_t coded_size_height,
                                          const uint8_t* exif_buffer,
                                          uint32_t exif_buffer_size,
                                          int output_fd,
                                          uint32_t output_buffer_size,
                                          uint32_t* output_data_size) {
  TRACE_JPEG("width", coded_size_width, "height", coded_size_height);

  int32_t task_id = task_id_;
  // Mask against 30 bits, to avoid (undefined) wraparound on signed integer.
  task_id_ = (task_id_ + 1) & 0x3FFFFFFF;

  auto future = Future<int>::Create(cancellation_relay_.get());
  auto callback =
      base::BindOnce(&JpegEncodeAcceleratorImpl::IPCBridge::EncodeSyncCallback,
                     ipc_bridge_->GetWeakPtr(), GetFutureCallback(future),
                     output_data_size, task_id);

  mojo_manager_->GetIpcTaskRunner()->PostTask(
      FROM_HERE,
      base::BindOnce(&JpegEncodeAcceleratorImpl::IPCBridge::EncodeLegacy,
                     ipc_bridge_->GetWeakPtr(), task_id, input_fd, input_buffer,
                     input_buffer_size, coded_size_width, coded_size_height,
                     exif_buffer, exif_buffer_size, output_fd,
                     output_buffer_size, std::move(callback)));

  if (!future->Wait()) {
    if (!ipc_bridge_->IsReady()) {
      LOGF(WARNING) << "There may be an mojo channel error.";
      return TRY_START_AGAIN;
    }
    LOGF(WARNING) << "There is no encode response from JEA mojo channel.";
    return NO_ENCODE_RESPONSE;
  }

  return future->Get();
}

int JpegEncodeAcceleratorImpl::EncodeSync(
    uint32_t input_format,
    const std::vector<JpegCompressor::DmaBufPlane>& input_planes,
    const std::vector<JpegCompressor::DmaBufPlane>& output_planes,
    const uint8_t* exif_buffer,
    uint32_t exif_buffer_size,
    int coded_size_width,
    int coded_size_height,
    int quality,
    uint64_t input_modifier,
    uint32_t* output_data_size) {
  TRACE_JPEG("width", coded_size_width, "height", coded_size_height);

  int32_t task_id = task_id_;
  // Mask against 30 bits, to avoid (undefined) wraparound on signed integer.
  task_id_ = (task_id_ + 1) & 0x3FFFFFFF;

  auto future = Future<int>::Create(cancellation_relay_.get());
  auto callback =
      base::BindOnce(&JpegEncodeAcceleratorImpl::IPCBridge::EncodeSyncCallback,
                     ipc_bridge_->GetWeakPtr(), GetFutureCallback(future),
                     output_data_size, task_id);

  mojo_manager_->GetIpcTaskRunner()->PostTask(
      FROM_HERE,
      base::BindOnce(&JpegEncodeAcceleratorImpl::IPCBridge::Encode,
                     ipc_bridge_->GetWeakPtr(), task_id, input_format,
                     std::move(input_planes), std::move(output_planes),
                     exif_buffer, exif_buffer_size, coded_size_width,
                     coded_size_height, quality, input_modifier,
                     std::move(callback)));

  if (!future->Wait()) {
    if (!ipc_bridge_->IsReady()) {
      LOGF(WARNING) << "There may be an mojo channel error.";
      return TRY_START_AGAIN;
    }
    LOGF(WARNING) << "There is no encode response from JEA mojo channel.";
    return NO_ENCODE_RESPONSE;
  }

  return future->Get();
}

JpegEncodeAcceleratorImpl::IPCBridge::IPCBridge(
    CameraMojoChannelManager* mojo_manager,
    CancellationRelay* cancellation_relay)
    : mojo_manager_(mojo_manager),
      cancellation_relay_(cancellation_relay),
      ipc_task_runner_(mojo_manager_->GetIpcTaskRunner()) {
  TRACE_JPEG_DEBUG();
}

JpegEncodeAcceleratorImpl::IPCBridge::~IPCBridge() {
  DCHECK(ipc_task_runner_->BelongsToCurrentThread());
  TRACE_JPEG_DEBUG();

  Destroy();
}

void JpegEncodeAcceleratorImpl::IPCBridge::Start(
    base::OnceCallback<void(bool)> callback) {
  DCHECK(ipc_task_runner_->BelongsToCurrentThread());
  TRACE_JPEG_DEBUG();

  if (jea_.is_bound()) {
    std::move(callback).Run(true);
    return;
  }

  mojo::PendingReceiver<mojom::JpegEncodeAccelerator> receiver =
      jea_.BindNewPipeAndPassReceiver();
  jea_.set_disconnect_handler(base::BindOnce(
      &JpegEncodeAcceleratorImpl::IPCBridge::OnJpegEncodeAcceleratorError,
      GetWeakPtr()));
  mojo_manager_->CreateJpegEncodeAccelerator(
      std::move(receiver),
      base::BindOnce(&JpegEncodeAcceleratorImpl::IPCBridge::Initialize,
                     GetWeakPtr(), std::move(callback)),
      base::BindOnce(
          &JpegEncodeAcceleratorImpl::IPCBridge::OnJpegEncodeAcceleratorError,
          GetWeakPtr()));
}

void JpegEncodeAcceleratorImpl::IPCBridge::Destroy() {
  DCHECK(ipc_task_runner_->BelongsToCurrentThread());
  TRACE_JPEG_DEBUG();

  jea_.reset();
}

void JpegEncodeAcceleratorImpl::IPCBridge::EncodeLegacy(
    int32_t task_id,
    int input_fd,
    const uint8_t* input_buffer,
    uint32_t input_buffer_size,
    int32_t coded_size_width,
    int32_t coded_size_height,
    const uint8_t* exif_buffer,
    uint32_t exif_buffer_size,
    int output_fd,
    uint32_t output_buffer_size,
    EncodeWithFDCallback callback) {
  DCHECK(ipc_task_runner_->BelongsToCurrentThread());
  TRACE_JPEG_DEBUG("width", coded_size_width, "height", coded_size_height);

  if (!jea_.is_bound()) {
    std::move(callback).Run(0, TRY_START_AGAIN);
    return;
  }

  base::WritableSharedMemoryRegion input_shm_region =
      base::WritableSharedMemoryRegion::Create(input_buffer_size);
  if (!input_shm_region.IsValid()) {
    LOGF(WARNING) << "Create shared memory region for input failed, size="
                  << input_buffer_size;
    std::move(callback).Run(0, SHARED_MEMORY_FAIL);
    return;
  }
  base::WritableSharedMemoryMapping input_shm_mapping = input_shm_region.Map();
  if (!input_shm_mapping.IsValid()) {
    LOGF(WARNING) << "Create mapping for input failed, size="
                  << input_buffer_size;
    std::move(callback).Run(0, SHARED_MEMORY_FAIL);
    return;
  }
  // Copy content from input buffer or file descriptor to shared memory.
  if (input_buffer) {
    memcpy(input_shm_mapping.memory(), input_buffer, input_buffer_size);
  } else {
    uint8_t* mmap_buf = static_cast<uint8_t*>(
        mmap(NULL, input_buffer_size, PROT_READ, MAP_SHARED, input_fd, 0));

    if (mmap_buf == MAP_FAILED) {
      LOGF(WARNING) << "MMAP for input_fd:" << input_fd << " Failed.";
      std::move(callback).Run(0, MMAP_FAIL);
      return;
    }

    memcpy(input_shm_mapping.memory(), mmap_buf, input_buffer_size);
    munmap(mmap_buf, input_buffer_size);
  }

  // Create WritableSharedMemory{Region,Mapping} for Exif buffer and copy data
  // into it.
  // Create a dummy |exif_shm| even if |exif_buffer_size| is 0.
  uint32_t exif_shm_size = std::max(exif_buffer_size, 1u);
  base::WritableSharedMemoryRegion exif_shm_region =
      base::WritableSharedMemoryRegion::Create(exif_shm_size);
  base::WritableSharedMemoryMapping exif_shm_mapping = exif_shm_region.Map();
  if (!exif_shm_mapping.IsValid()) {
    LOGF(WARNING) << "Create and Map for exif failed, size=" << exif_shm_size;
    std::move(callback).Run(0, SHARED_MEMORY_FAIL);
    return;
  }
  if (exif_buffer_size) {
    memcpy(exif_shm_mapping.memory(), exif_buffer, exif_buffer_size);
  }

  base::subtle::PlatformSharedMemoryRegion input_platform_shm =
      base::WritableSharedMemoryRegion::TakeHandleForSerialization(
          std::move(input_shm_region));
  base::subtle::PlatformSharedMemoryRegion exif_platform_shm =
      base::WritableSharedMemoryRegion::TakeHandleForSerialization(
          std::move(exif_shm_region));

  int dup_output_fd = HANDLE_EINTR(dup(output_fd));

  mojo::ScopedHandle input_handle = mojo::WrapPlatformFile(
      std::move(input_platform_shm.PassPlatformHandle().fd));
  mojo::ScopedHandle exif_handle = mojo::WrapPlatformFile(
      std::move(exif_platform_shm.PassPlatformHandle().fd));
  mojo::ScopedHandle output_handle =
      mojo::WrapPlatformFile(base::ScopedPlatformFile(dup_output_fd));

  jea_->EncodeWithFD(
      task_id, std::move(input_handle), input_buffer_size, coded_size_width,
      coded_size_height, std::move(exif_handle), exif_buffer_size,
      std::move(output_handle), output_buffer_size,
      base::BindOnce(&JpegEncodeAcceleratorImpl::IPCBridge::OnEncodeAck,
                     GetWeakPtr(), std::move(callback)));
}

void JpegEncodeAcceleratorImpl::IPCBridge::Encode(
    int32_t task_id,
    uint32_t input_format,
    const std::vector<JpegCompressor::DmaBufPlane>& input_planes,
    const std::vector<JpegCompressor::DmaBufPlane>& output_planes,
    const uint8_t* exif_buffer,
    uint32_t exif_buffer_size,
    int coded_size_width,
    int coded_size_height,
    int quality,
    uint64_t input_modifier,
    EncodeWithDmaBufCallback callback) {
  DCHECK(ipc_task_runner_->BelongsToCurrentThread());
  TRACE_JPEG_DEBUG("width", coded_size_width, "height", coded_size_height);

  if (!jea_.is_bound()) {
    std::move(callback).Run(0, TRY_START_AGAIN);
    return;
  }

  // Create SharedMemory for Exif buffer and copy data into it.
  // Create a dummy |exif_shm| even if |exif_buffer_size| is 0.
  uint32_t exif_shm_size = std::max(exif_buffer_size, 1u);
  base::WritableSharedMemoryRegion exif_shm_region =
      base::WritableSharedMemoryRegion::Create(exif_shm_size);
  if (!exif_shm_region.IsValid()) {
    LOGF(WARNING) << "Create shared memory region for exif failed, size="
                  << exif_shm_size;
    std::move(callback).Run(0, SHARED_MEMORY_FAIL);
    return;
  }
  base::WritableSharedMemoryMapping exif_shm_mapping = exif_shm_region.Map();
  if (!exif_shm_mapping.IsValid()) {
    LOGF(WARNING) << "Create mapping for exif failed, size=" << exif_shm_size;
    std::move(callback).Run(0, SHARED_MEMORY_FAIL);
    return;
  }
  if (exif_buffer_size) {
    memcpy(exif_shm_mapping.memory(), exif_buffer, exif_buffer_size);
  }
  base::subtle::PlatformSharedMemoryRegion exif_platform_shm =
      base::WritableSharedMemoryRegion::TakeHandleForSerialization(
          std::move(exif_shm_region));

  mojo::ScopedHandle exif_handle = mojo::WrapPlatformFile(
      std::move(exif_platform_shm.PassPlatformHandle().fd));

  auto WrapToMojoPlanes =
      [](const std::vector<JpegCompressor::DmaBufPlane>& planes) {
        std::vector<cros::mojom::DmaBufPlanePtr> mojo_planes;
        for (auto plane : planes) {
          auto mojo_plane = cros::mojom::DmaBufPlane::New();
          mojo_plane->fd_handle = mojo::WrapPlatformFile(
              base::ScopedPlatformFile(HANDLE_EINTR(dup(plane.fd))));
          mojo_plane->stride = plane.stride;
          mojo_plane->offset = plane.offset;
          mojo_plane->size = plane.size;
          mojo_planes.push_back(std::move(mojo_plane));
        }
        return mojo_planes;
      };

  std::vector<cros::mojom::DmaBufPlanePtr> mojo_input_planes =
      WrapToMojoPlanes(input_planes);
  std::vector<cros::mojom::DmaBufPlanePtr> mojo_output_planes =
      WrapToMojoPlanes(output_planes);

  jea_->EncodeWithDmaBuf(
      task_id, input_format, std::move(mojo_input_planes),
      std::move(mojo_output_planes), std::move(exif_handle), exif_buffer_size,
      coded_size_width, coded_size_height, quality, /*has_input_modifier=*/true,
      input_modifier,
      base::BindOnce(&JpegEncodeAcceleratorImpl::IPCBridge::OnEncodeDmaBufAck,
                     GetWeakPtr(), std::move(callback)));
}

void JpegEncodeAcceleratorImpl::IPCBridge::EncodeSyncCallback(
    base::OnceCallback<void(int)> callback,
    uint32_t* output_data_size,
    int32_t task_id,
    uint32_t output_size,
    int status) {
  DCHECK(ipc_task_runner_->BelongsToCurrentThread());
  *output_data_size = output_size;
  std::move(callback).Run(status);
}

base::WeakPtr<JpegEncodeAcceleratorImpl::IPCBridge>
JpegEncodeAcceleratorImpl::IPCBridge::GetWeakPtr() {
  return weak_ptr_factory_.GetWeakPtr();
}

bool JpegEncodeAcceleratorImpl::IPCBridge::IsReady() {
  return jea_.is_bound();
}

void JpegEncodeAcceleratorImpl::IPCBridge::Initialize(
    base::OnceCallback<void(bool)> callback) {
  DCHECK(ipc_task_runner_->BelongsToCurrentThread());
  TRACE_JPEG_DEBUG();

  jea_->Initialize(std::move(callback));
}

void JpegEncodeAcceleratorImpl::IPCBridge::OnJpegEncodeAcceleratorError() {
  DCHECK(ipc_task_runner_->BelongsToCurrentThread());
  TRACE_JPEG();

  LOGF(ERROR) << "There is a mojo error for JpegEncodeAccelerator";
  jea_.reset();
  cancellation_relay_->CancelAllFutures();
  Destroy();
}

void JpegEncodeAcceleratorImpl::IPCBridge::OnEncodeAck(
    EncodeWithFDCallback callback,
    int32_t task_id,
    uint32_t output_size,
    mojom::EncodeStatus status) {
  DCHECK(ipc_task_runner_->BelongsToCurrentThread());
  std::move(callback).Run(output_size, static_cast<int>(status));
}

void JpegEncodeAcceleratorImpl::IPCBridge::OnEncodeDmaBufAck(
    EncodeWithDmaBufCallback callback,
    uint32_t output_size,
    mojom::EncodeStatus status) {
  DCHECK(ipc_task_runner_->BelongsToCurrentThread());
  std::move(callback).Run(output_size, static_cast<int>(status));
}

}  // namespace cros

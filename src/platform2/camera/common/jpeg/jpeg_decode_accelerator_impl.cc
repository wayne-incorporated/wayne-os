/*
 * Copyright 2018 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "common/jpeg/jpeg_decode_accelerator_impl.h"

#include <fcntl.h>
#include <linux/videodev2.h>
#include <sys/mman.h>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/containers/contains.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/memory/ptr_util.h>
#include <base/posix/eintr_wrapper.h>
#include <base/run_loop.h>
#include <base/timer/elapsed_timer.h>
#include <mojo/public/c/system/buffer.h>
#include <mojo/public/cpp/system/buffer.h>
#include <mojo/public/cpp/system/platform_handle.h>

#include "camera/mojo/gpu/dmabuf.mojom.h"
#include "common/jpeg/tracing.h"
#include "cros-camera/camera_buffer_manager.h"
#include "cros-camera/common.h"
#include "cros-camera/future.h"
#include "cros-camera/ipc_util.h"

#define STATIC_ASSERT_ENUM(name)                                        \
  static_assert(static_cast<int>(JpegDecodeAccelerator::Error::name) == \
                    static_cast<int>(mojom::DecodeError::name),         \
                "mismatching enum: " #name)

namespace cros {

STATIC_ASSERT_ENUM(NO_ERRORS);
STATIC_ASSERT_ENUM(INVALID_ARGUMENT);
STATIC_ASSERT_ENUM(UNREADABLE_INPUT);
STATIC_ASSERT_ENUM(PARSE_JPEG_FAILED);
STATIC_ASSERT_ENUM(UNSUPPORTED_JPEG);
STATIC_ASSERT_ENUM(PLATFORM_FAILURE);

namespace {

static mojom::VideoPixelFormat V4L2PixelFormatToMojoFormat(
    uint32_t v4l2_format) {
  switch (v4l2_format) {
    case V4L2_PIX_FMT_YUV420:
    case V4L2_PIX_FMT_YUV420M:
      return mojom::VideoPixelFormat::PIXEL_FORMAT_I420;
    case V4L2_PIX_FMT_NV12:
    case V4L2_PIX_FMT_NV12M:
      return mojom::VideoPixelFormat::PIXEL_FORMAT_NV12;
    default:
      return mojom::VideoPixelFormat::PIXEL_FORMAT_UNKNOWN;
  }
}

}  // namespace

// static
std::unique_ptr<JpegDecodeAccelerator> JpegDecodeAccelerator::CreateInstance() {
  return JpegDecodeAccelerator::CreateInstance(
      CameraMojoChannelManager::GetInstance());
}

// static
std::unique_ptr<JpegDecodeAccelerator> JpegDecodeAccelerator::CreateInstance(
    CameraMojoChannelManagerToken* token) {
  return base::WrapUnique<JpegDecodeAccelerator>(new JpegDecodeAcceleratorImpl(
      CameraMojoChannelManager::FromToken(token)));
}

JpegDecodeAcceleratorImpl::JpegDecodeAcceleratorImpl(
    CameraMojoChannelManager* mojo_manager)
    : buffer_id_(0),
      mojo_manager_(mojo_manager),
      cancellation_relay_(new CancellationRelay),
      ipc_bridge_(new IPCBridge(mojo_manager, cancellation_relay_.get())),
      camera_metrics_(CameraMetrics::New()) {
  TRACE_JPEG_DEBUG();
}

JpegDecodeAcceleratorImpl::~JpegDecodeAcceleratorImpl() {
  TRACE_JPEG_DEBUG();

  bool result = mojo_manager_->GetIpcTaskRunner()->DeleteSoon(
      FROM_HERE, std::move(ipc_bridge_));
  DCHECK(result);
  cancellation_relay_ = nullptr;
}

bool JpegDecodeAcceleratorImpl::Start() {
  TRACE_JPEG();

  auto is_initialized = cros::Future<bool>::Create(cancellation_relay_.get());

  mojo_manager_->GetIpcTaskRunner()->PostTask(
      FROM_HERE, base::BindOnce(&JpegDecodeAcceleratorImpl::IPCBridge::Start,
                                ipc_bridge_->GetWeakPtr(),
                                cros::GetFutureCallback(is_initialized)));
  if (!is_initialized->Wait()) {
    return false;
  }

  return is_initialized->Get();
}

JpegDecodeAccelerator::Error JpegDecodeAcceleratorImpl::DecodeSync(
    int input_fd,
    uint32_t input_buffer_size,
    uint32_t input_buffer_offset,
    buffer_handle_t output_buffer) {
  CameraBufferManager* buffer_manager = CameraBufferManager::GetInstance();
  TRACE_JPEG("width", buffer_manager->GetWidth(output_buffer), "height",
             buffer_manager->GetHeight(output_buffer));

  auto future = cros::Future<int>::Create(cancellation_relay_.get());

  Decode(input_fd, input_buffer_size, input_buffer_offset, output_buffer,
         base::BindOnce(
             &JpegDecodeAcceleratorImpl::IPCBridge::DecodeSyncCallback,
             ipc_bridge_->GetWeakPtr(), cros::GetFutureCallback(future)));

  if (!future->Wait()) {
    if (!ipc_bridge_->IsReady()) {
      LOGF(WARNING) << "There may be an mojo channel error.";
      return Error::TRY_START_AGAIN;
    }
    LOGF(WARNING) << "There is no decode response from JDA mojo channel.";
    return Error::NO_DECODE_RESPONSE;
  }
  return static_cast<Error>(future->Get());
}

int32_t JpegDecodeAcceleratorImpl::Decode(int input_fd,
                                          uint32_t input_buffer_size,
                                          uint32_t input_buffer_offset,
                                          buffer_handle_t output_buffer,
                                          DecodeCallback callback) {
  CameraBufferManager* buffer_manager = CameraBufferManager::GetInstance();
  TRACE_JPEG("width", buffer_manager->GetWidth(output_buffer), "height",
             buffer_manager->GetHeight(output_buffer));

  int32_t buffer_id = buffer_id_;

  // Mask against 30 bits, to avoid (undefined) wraparound on signed integer.
  buffer_id_ = (buffer_id_ + 1) & 0x3FFFFFFF;

  mojo_manager_->GetIpcTaskRunner()->PostTask(
      FROM_HERE, base::BindOnce(&JpegDecodeAcceleratorImpl::IPCBridge::Decode,
                                ipc_bridge_->GetWeakPtr(), buffer_id, input_fd,
                                input_buffer_size, input_buffer_offset,
                                output_buffer, std::move(callback)));
  return buffer_id;
}

JpegDecodeAcceleratorImpl::IPCBridge::IPCBridge(
    CameraMojoChannelManager* mojo_manager,
    CancellationRelay* cancellation_relay)
    : mojo_manager_(mojo_manager),
      cancellation_relay_(cancellation_relay),
      ipc_task_runner_(mojo_manager_->GetIpcTaskRunner()) {
  TRACE_JPEG_DEBUG();
}

JpegDecodeAcceleratorImpl::IPCBridge::~IPCBridge() {
  DCHECK(ipc_task_runner_->BelongsToCurrentThread());
  TRACE_JPEG_DEBUG();

  Destroy();
}

void JpegDecodeAcceleratorImpl::IPCBridge::Start(
    base::OnceCallback<void(bool)> callback) {
  DCHECK(ipc_task_runner_->BelongsToCurrentThread());
  TRACE_JPEG_DEBUG();

  if (jda_.is_bound()) {
    std::move(callback).Run(true);
    return;
  }

  mojo::PendingReceiver<mojom::MjpegDecodeAccelerator> receiver =
      jda_.BindNewPipeAndPassReceiver();
  jda_.set_disconnect_handler(base::BindOnce(
      &JpegDecodeAcceleratorImpl::IPCBridge::OnJpegDecodeAcceleratorError,
      GetWeakPtr()));
  mojo_manager_->CreateMjpegDecodeAccelerator(
      std::move(receiver),
      base::BindOnce(&JpegDecodeAcceleratorImpl::IPCBridge::Initialize,
                     GetWeakPtr(), std::move(callback)),
      base::BindOnce(
          &JpegDecodeAcceleratorImpl::IPCBridge::OnJpegDecodeAcceleratorError,
          GetWeakPtr()));
}

void JpegDecodeAcceleratorImpl::IPCBridge::Destroy() {
  DCHECK(ipc_task_runner_->BelongsToCurrentThread());
  TRACE_JPEG_DEBUG();

  jda_.reset();
  inflight_buffer_ids_.clear();
}

void JpegDecodeAcceleratorImpl::IPCBridge::Decode(int32_t buffer_id,
                                                  int input_fd,
                                                  uint32_t input_buffer_size,
                                                  uint32_t input_buffer_offset,
                                                  buffer_handle_t output_buffer,
                                                  DecodeCallback callback) {
  DCHECK(ipc_task_runner_->BelongsToCurrentThread());
  DCHECK(!base::Contains(inflight_buffer_ids_, buffer_id));

  CameraBufferManager* buffer_manager = CameraBufferManager::GetInstance();
  TRACE_JPEG_DEBUG("width", buffer_manager->GetWidth(output_buffer), "height",
                   buffer_manager->GetHeight(output_buffer));

  if (!jda_.is_bound()) {
    std::move(callback).Run(buffer_id,
                            static_cast<int>(Error::TRY_START_AGAIN));
    return;
  }

  // Wrap output buffer into mojom::DmaBufVideoFrame.
  mojom::VideoPixelFormat mojo_format = V4L2PixelFormatToMojoFormat(
      buffer_manager->GetV4L2PixelFormat(output_buffer));
  if (mojo_format == mojom::VideoPixelFormat::PIXEL_FORMAT_UNKNOWN) {
    std::move(callback).Run(buffer_id,
                            static_cast<int>(Error::INVALID_ARGUMENT));
    return;
  }
  const uint32_t num_planes = buffer_manager->GetNumPlanes(output_buffer);
  std::vector<mojom::DmaBufPlanePtr> planes(num_planes);
  for (uint32_t i = 0; i < num_planes; ++i) {
    mojo::ScopedHandle fd_handle = mojo::WrapPlatformFile(
        base::ScopedPlatformFile(HANDLE_EINTR(dup(output_buffer->data[i]))));
    const int32_t stride = base::checked_cast<int32_t>(
        buffer_manager->GetPlaneStride(output_buffer, i));
    const uint32_t offset = base::checked_cast<uint32_t>(
        buffer_manager->GetPlaneOffset(output_buffer, i));
    const uint32_t size = base::checked_cast<uint32_t>(
        buffer_manager->GetPlaneSize(output_buffer, i));
    planes[i] =
        mojom::DmaBufPlane::New(std::move(fd_handle), stride, offset, size);
  }
  auto output_frame = mojom::DmaBufVideoFrame::New(
      mojo_format, buffer_manager->GetWidth(output_buffer),
      buffer_manager->GetHeight(output_buffer), std::move(planes),
      /*has_modifier=*/true, buffer_manager->GetModifier(output_buffer));

  mojo::ScopedHandle input_handle = mojo::WrapPlatformFile(
      base::ScopedPlatformFile(HANDLE_EINTR(dup(input_fd))));

  inflight_buffer_ids_.insert(buffer_id);
  jda_->DecodeWithDmaBuf(
      buffer_id, std::move(input_handle), input_buffer_size,
      input_buffer_offset, std::move(output_frame),
      base::BindOnce(&JpegDecodeAcceleratorImpl::IPCBridge::OnDecodeAck,
                     GetWeakPtr(), std::move(callback), buffer_id));
}

void JpegDecodeAcceleratorImpl::IPCBridge::DecodeSyncCallback(
    base::OnceCallback<void(int)> callback, int32_t buffer_id, int error) {
  DCHECK(ipc_task_runner_->BelongsToCurrentThread());
  std::move(callback).Run(error);
}

void JpegDecodeAcceleratorImpl::IPCBridge::TestResetJDAChannel(
    scoped_refptr<cros::Future<void>> future) {
  DCHECK(ipc_task_runner_->BelongsToCurrentThread());
  jda_.reset();
  future->Set();
}

base::WeakPtr<JpegDecodeAcceleratorImpl::IPCBridge>
JpegDecodeAcceleratorImpl::IPCBridge::GetWeakPtr() {
  return weak_ptr_factory_.GetWeakPtr();
}

bool JpegDecodeAcceleratorImpl::IPCBridge::IsReady() {
  return jda_.is_bound();
}

void JpegDecodeAcceleratorImpl::IPCBridge::Initialize(
    base::OnceCallback<void(bool)> callback) {
  DCHECK(ipc_task_runner_->BelongsToCurrentThread());
  TRACE_JPEG_DEBUG();

  jda_->Initialize(std::move(callback));
}

void JpegDecodeAcceleratorImpl::IPCBridge::OnJpegDecodeAcceleratorError() {
  DCHECK(ipc_task_runner_->BelongsToCurrentThread());
  TRACE_JPEG();

  LOGF(ERROR) << "There is a mojo error for JpegDecodeAccelerator";
  cancellation_relay_->CancelAllFutures();
  Destroy();
}

void JpegDecodeAcceleratorImpl::IPCBridge::OnDecodeAck(
    DecodeCallback callback,
    int32_t buffer_id,
    cros::mojom::DecodeError error) {
  DCHECK(ipc_task_runner_->BelongsToCurrentThread());
  DCHECK(base::Contains(inflight_buffer_ids_, buffer_id));
  TRACE_JPEG_DEBUG();

  inflight_buffer_ids_.erase(buffer_id);
  std::move(callback).Run(buffer_id, static_cast<int>(error));
}

void JpegDecodeAcceleratorImpl::TestResetJDAChannel() {
  auto future = cros::Future<void>::Create(nullptr);

  mojo_manager_->GetIpcTaskRunner()->PostTask(
      FROM_HERE,
      base::BindOnce(&JpegDecodeAcceleratorImpl::IPCBridge::TestResetJDAChannel,
                     ipc_bridge_->GetWeakPtr(), base::RetainedRef(future)));
  future->Wait();
}

}  // namespace cros

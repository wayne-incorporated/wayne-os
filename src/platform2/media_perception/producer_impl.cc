// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "media_perception/producer_impl.h"

#include <stdlib.h>

#include <algorithm>
#include <cstring>
#include <utility>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <mojo/public/cpp/system/handle.h>
#include <mojo/public/cpp/system/platform_handle.h>

#include "media_perception/mojom/constants.mojom.h"
#include "media_perception/mojom/video_capture_buffer.mojom.h"
#include "media_perception/mojom/video_capture_types.mojom.h"

namespace mri {

mojo::PendingRemote<video_capture::mojom::Producer>
ProducerImpl::CreateInterfacePendingRemote() {
  mojo::PendingRemote<video_capture::mojom::Producer> producer;
  receiver_.Bind(producer.InitWithNewPipeAndPassReceiver());
  return producer;
}

void ProducerImpl::RegisterVirtualDevice(
    mojo::Remote<video_capture::mojom::VideoSourceProvider>* provider,
    media::mojom::VideoCaptureDeviceInfoPtr info) {
  (*provider)->AddSharedMemoryVirtualDevice(
      std::move(info), CreateInterfacePendingRemote(), true,
      virtual_device_.BindNewPipeAndPassReceiver());
}

void ProducerImpl::OnNewBuffer(int32_t buffer_id,
                               media::mojom::VideoBufferHandlePtr buffer_handle,
                               OnNewBufferCallback callback) {
  CHECK(buffer_handle->is_shared_memory_via_raw_file_descriptor());
  base::ScopedPlatformFile platform_file;
  MojoResult mojo_result = mojo::UnwrapPlatformFile(
      std::move(buffer_handle->get_shared_memory_via_raw_file_descriptor()
                    ->file_descriptor_handle),
      &platform_file);
  if (mojo_result != MOJO_RESULT_OK) {
    LOG(ERROR) << "Failed to unwrap handle: " << mojo_result;
    return;
  }
  base::UnsafeSharedMemoryRegion shm_region =
      base::UnsafeSharedMemoryRegion::Deserialize(
          base::subtle::PlatformSharedMemoryRegion::Take(
              base::ScopedFD(std::move(platform_file)),
              base::subtle::PlatformSharedMemoryRegion::Mode::kUnsafe,
              buffer_handle->get_shared_memory_via_raw_file_descriptor()
                  ->shared_memory_size_in_bytes,
              base::UnguessableToken::Create()));
  if (!shm_region.IsValid()) {
    LOG(ERROR) << "Failed to take shared memory region.";
    return;
  }
  base::WritableSharedMemoryMapping shm_mapping = shm_region.Map();
  if (!shm_mapping.IsValid()) {
    LOG(ERROR) << "Failed to map shared memory region.";
    return;
  }
  outgoing_buffer_id_to_buffer_map_.insert(
      std::make_pair(buffer_id, std::move(shm_mapping)));
  std::move(callback).Run();
}

void ProducerImpl::OnBufferRetired(int32_t buffer_id) {
  outgoing_buffer_id_to_buffer_map_.erase(buffer_id);
}

void ProducerImpl::PushNextFrame(
    std::shared_ptr<ProducerImpl> producer_impl,
    base::TimeDelta timestamp,
    std::unique_ptr<const uint8_t[]> data,
    int data_size,
    media::mojom::VideoCapturePixelFormat pixel_format,
    int width,
    int height) {
  gfx::mojom::SizePtr size = gfx::mojom::Size::New();
  size->width = width;
  size->height = height;
  virtual_device_->RequestFrameBuffer(
      std::move(size), pixel_format, nullptr,
      base::BindOnce(&ProducerImpl::OnFrameBufferReceived,
                     base::Unretained(this), producer_impl, timestamp,
                     std::move(data), data_size, pixel_format, width, height));
}

void ProducerImpl::OnFrameBufferReceived(
    std::shared_ptr<ProducerImpl> producer_impl,
    base::TimeDelta timestamp,
    std::unique_ptr<const uint8_t[]> data,
    int data_size,
    media::mojom::VideoCapturePixelFormat pixel_format,
    int width,
    int height,
    int32_t buffer_id) {
  if (buffer_id == video_capture::mojom::kInvalidBufferId) {
    LOG(ERROR) << "Got invalid buffer id.";
    return;
  }

  media::mojom::VideoFrameInfoPtr info = media::mojom::VideoFrameInfo::New();
  info->timestamp = mojo_base::mojom::TimeDelta::New();
  info->timestamp->microseconds = timestamp.InMicroseconds();
  info->pixel_format = pixel_format;
  gfx::mojom::SizePtr size = gfx::mojom::Size::New();
  size->width = width;
  size->height = height;
  info->coded_size = std::move(size);
  gfx::mojom::RectPtr rect = gfx::mojom::Rect::New();
  rect->width = width;
  rect->height = height;
  info->visible_rect = std::move(rect);
  info->metadata = media::mojom::VideoFrameMetadata::New();
  info->metadata->reference_time = mojo_base::mojom::TimeTicks::New();
  info->metadata->reference_time->internal_value = timestamp.InMicroseconds();

  base::WritableSharedMemoryMapping* outgoing_buffer =
      &outgoing_buffer_id_to_buffer_map_.at(buffer_id);
  std::memcpy(
      outgoing_buffer->GetMemoryAs<uint8_t>(), data.get(),
      std::min(outgoing_buffer->mapped_size(), static_cast<size_t>(data_size)));
  virtual_device_->OnFrameReadyInBuffer(buffer_id, std::move(info));
}

}  // namespace mri

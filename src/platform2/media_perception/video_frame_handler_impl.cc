// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "media_perception/video_frame_handler_impl.h"

#include <utility>

#include <base/check.h>
#include <base/logging.h>
#include <mojo/public/cpp/system/handle.h>
#include <mojo/public/cpp/system/platform_handle.h>

#include "media_perception/mojom/scoped_access_permission.mojom.h"
#include "media_perception/mojom/video_capture_types.mojom.h"

namespace mri {

bool VideoFrameHandlerImpl::HasValidCaptureFormat() {
  return capture_format_.width_in_pixels() > 0 &&
         capture_format_.height_in_pixels() > 0;
}

void VideoFrameHandlerImpl::SetCaptureFormat(const VideoStreamParams& params) {
  capture_format_ = params;
}

bool VideoFrameHandlerImpl::CaptureFormatsMatch(
    const VideoStreamParams& params) {
  return capture_format_.width_in_pixels() == params.width_in_pixels() &&
         capture_format_.height_in_pixels() == params.height_in_pixels() &&
         capture_format_.frame_rate_in_frames_per_second() ==
             params.frame_rate_in_frames_per_second();
}

VideoStreamParams VideoFrameHandlerImpl::GetCaptureFormat() {
  return capture_format_;
}

int VideoFrameHandlerImpl::GetFrameHandlerCount() {
  return frame_handler_map_.size();
}

int VideoFrameHandlerImpl::AddFrameHandler(
    VideoCaptureServiceClient::FrameHandler frame_handler) {
  frame_handler_id_counter_++;
  frame_handler_map_.insert(
      std::make_pair(frame_handler_id_counter_, std::move(frame_handler)));
  return frame_handler_id_counter_;
}

bool VideoFrameHandlerImpl::RemoveFrameHandler(int frame_handler_id) {
  std::map<int, VideoCaptureServiceClient::FrameHandler>::iterator it =
      frame_handler_map_.find(frame_handler_id);
  if (it == frame_handler_map_.end()) {
    return false;
  }
  frame_handler_map_.erase(frame_handler_id);
  return true;
}

mojo::PendingRemote<video_capture::mojom::VideoFrameHandler>
VideoFrameHandlerImpl::CreateInterfacePendingRemote() {
  mojo::PendingRemote<video_capture::mojom::VideoFrameHandler> handler;
  receiver_.Bind(handler.InitWithNewPipeAndPassReceiver());
  return handler;
}

void VideoFrameHandlerImpl::OnNewBuffer(
    int32_t buffer_id, media::mojom::VideoBufferHandlePtr buffer_handle) {
  LOG(INFO) << "On new buffer";
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
    LOG(ERROR) << "Failed to unwrap handle to valid shared memory region.";
    return;
  }
  base::WritableSharedMemoryMapping shm_mapping = shm_region.Map();
  if (!shm_mapping.IsValid()) {
    LOG(ERROR) << "Failed to map shared memory region.";
    return;
  }
  incoming_buffer_id_to_buffer_map_.insert(
      std::make_pair(buffer_id, std::move(shm_mapping)));
}

void VideoFrameHandlerImpl::OnFrameAccessHandlerReady(
    mojo::PendingRemote<video_capture::mojom::VideoFrameAccessHandler>
        frame_access_handler) {
  LOG(INFO) << "Got call to OnFrameAccessHandlerReady";
  frame_access_handler_.Bind(std::move(frame_access_handler));
}

void VideoFrameHandlerImpl::OnFrameReadyInBuffer(
    video_capture::mojom::ReadyFrameInBufferPtr buffer,
    std::vector<video_capture::mojom::ReadyFrameInBufferPtr> scaled_buffers) {
  base::WritableSharedMemoryMapping* incoming_buffer =
      &incoming_buffer_id_to_buffer_map_.at(buffer->buffer_id);
  // Loop through all the registered frame handlers and push a frame out.
  for (auto& entry : frame_handler_map_) {
    entry.second(buffer->frame_info->timestamp->microseconds,
                 incoming_buffer->GetMemoryAs<const uint8_t>(),
                 incoming_buffer->size(), capture_format_.width_in_pixels(),
                 capture_format_.height_in_pixels());
  }
  frame_access_handler_->OnFinishedConsumingBuffer(buffer->buffer_id);
}

void VideoFrameHandlerImpl::OnFrameDropped(
    ::media::mojom::VideoCaptureFrameDropReason reason) {
  LOG(WARNING) << "Got call to OnFrameDropped: " << reason;
}

void VideoFrameHandlerImpl::OnBufferRetired(int32_t buffer_id) {
  incoming_buffer_id_to_buffer_map_.erase(buffer_id);
}

// The following methods are not needed to be implementated, as far as we know
// now.
void VideoFrameHandlerImpl::OnError(::media::mojom::VideoCaptureError error) {
  LOG(ERROR) << "Got call to OnError: " << error;
}

void VideoFrameHandlerImpl::OnFrameWithEmptyRegionCapture() {
  LOG(INFO) << "Got call to OnFrameWithEmptyRegionCapture";
}

void VideoFrameHandlerImpl::OnLog(const std::string& message) {
  LOG(INFO) << "Got call to OnLog: " << message;
}

void VideoFrameHandlerImpl::OnStarted() {
  LOG(INFO) << "Got call to OnStarted";
}

void VideoFrameHandlerImpl::OnStartedUsingGpuDecode() {
  LOG(INFO) << "Got call on OnStartedUsingGpuDecode";
}

void VideoFrameHandlerImpl::OnStopped() {
  LOG(INFO) << "Got call to OnStopped";
}

}  // namespace mri

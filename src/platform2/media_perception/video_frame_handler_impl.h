// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MEDIA_PERCEPTION_VIDEO_FRAME_HANDLER_IMPL_H_
#define MEDIA_PERCEPTION_VIDEO_FRAME_HANDLER_IMPL_H_

#include <map>
#include <string>
#include <vector>

#include <base/memory/unsafe_shared_memory_region.h>
#include <mojo/public/cpp/bindings/pending_remote.h>
#include <mojo/public/cpp/bindings/receiver.h>
#include <mojo/public/cpp/bindings/remote.h>

#include "media_perception/device_management.pb.h"
#include "media_perception/mojom/device_factory.mojom.h"
#include "media_perception/mojom/video_frame_handler.mojom.h"
#include "media_perception/video_capture_service_client.h"

namespace mri {

class VideoFrameHandlerImpl : public video_capture::mojom::VideoFrameHandler {
 public:
  VideoFrameHandlerImpl() : frame_handler_id_counter_(0), receiver_(this) {}

  bool HasValidCaptureFormat();

  void SetCaptureFormat(const VideoStreamParams& params);

  VideoStreamParams GetCaptureFormat();

  // Checks if the frame dimensions match the current dimensions.
  bool CaptureFormatsMatch(const VideoStreamParams& params);

  // Creates a local proxy of the VideoFrameHandler interface.
  mojo::PendingRemote<video_capture::mojom::VideoFrameHandler>
  CreateInterfacePendingRemote();

  // Returns the count of active frame handlers on this handler.
  int GetFrameHandlerCount();

  // Add a handler that will be called when new frames come from the associated
  // device. Return value is an id for this frame handler.
  int AddFrameHandler(VideoCaptureServiceClient::FrameHandler frame_handler);

  // Removes a frame handler on this device with this id. Return value indicates
  // if the removal was successful.
  bool RemoveFrameHandler(int frame_handler_id);

  // video_capture::mojom::VideoFrameHandler overrides.
  void OnNewBuffer(int32_t buffer_id,
                   media::mojom::VideoBufferHandlePtr buffer_handle) override;
  void OnFrameAccessHandlerReady(
      mojo::PendingRemote<video_capture::mojom::VideoFrameAccessHandler>
          frame_access_handler) override;
  void OnFrameReadyInBuffer(
      video_capture::mojom::ReadyFrameInBufferPtr buffer,
      std::vector<video_capture::mojom::ReadyFrameInBufferPtr> scaled_buffers)
      override;
  void OnFrameDropped(
      ::media::mojom::VideoCaptureFrameDropReason reason) override;
  void OnBufferRetired(int32_t buffer_id) override;
  void OnError(::media::mojom::VideoCaptureError error) override;
  void OnFrameWithEmptyRegionCapture() override;
  void OnLog(const std::string& message) override;
  void OnStarted() override;
  void OnStartedUsingGpuDecode() override;
  void OnStopped() override;

 private:
  // Incremented to create unique frame handler ids.
  int frame_handler_id_counter_;

  // Frame handler map for forwarding frames to one or more clients.
  std::map<int, VideoCaptureServiceClient::FrameHandler> frame_handler_map_;

  // Binding of the Recevier interface to message pipe.
  mojo::Receiver<video_capture::mojom::VideoFrameHandler> receiver_;

  // Stores the frame access handler to let the producer of frames know when we
  // are done with a frame.
  mojo::Remote<video_capture::mojom::VideoFrameAccessHandler>
      frame_access_handler_;

  // Stores the capture format requested from the open device.
  VideoStreamParams capture_format_;

  std::map<int32_t /*buffer_id*/, base::WritableSharedMemoryMapping>
      incoming_buffer_id_to_buffer_map_;
};

}  // namespace mri

#endif  // MEDIA_PERCEPTION_VIDEO_FRAME_HANDLER_IMPL_H_

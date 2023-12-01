// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MEDIA_PERCEPTION_VIDEO_CAPTURE_SERVICE_CLIENT_IMPL_H_
#define MEDIA_PERCEPTION_VIDEO_CAPTURE_SERVICE_CLIENT_IMPL_H_

#include "media_perception/video_capture_service_client.h"

#include <map>
#include <memory>
// NOLINTNEXTLINE
#include <mutex>
#include <string>

#include "media_perception/mojo_connector.h"
#include "media_perception/mojom/media_perception_service.mojom.h"
#include "media_perception/producer_impl.h"
#include "media_perception/video_frame_handler_impl.h"

namespace mri {

// Implementation of the VideoCaptureServiceClient interface for interacting
// with the Chrome VideoCaptureService using google3 code.
class VideoCaptureServiceClientImpl : public VideoCaptureServiceClient {
 public:
  VideoCaptureServiceClientImpl() : mojo_connector_(nullptr) {}

  // Set the global mojo connector object for use with talking to the video
  // capture service.
  void SetMojoConnector(MojoConnector* mojo_connector);

  // VideoCaptureServiceClient overrides:
  bool Connect() override;
  bool IsConnected() override;
  void GetDevices(const GetDevicesCallback& callback) override;
  void OpenDevice(const std::string& device_id,
                  bool force_reopen_with_settings,
                  const SerializedVideoStreamParams& capture_format,
                  const OpenDeviceCallback& callback) override;
  bool IsVideoCaptureStartedForDevice(
      const std::string& device_id,
      SerializedVideoStreamParams* capture_format) override;
  int AddFrameHandler(const std::string& device_id,
                      FrameHandler handler) override;
  bool RemoveFrameHandler(const std::string& device_id,
                          int frame_handler_id) override;
  void CreateVirtualDevice(const SerializedVideoDevice& video_device,
                           const VirtualDeviceCallback& callback) override;
  void PushFrameToVirtualDevice(const std::string& device_id,
                                uint64_t timestamp_in_microseconds,
                                std::unique_ptr<const uint8_t[]> data,
                                int data_size,
                                RawPixelFormat pixel_format,
                                int frame_width,
                                int frame_height) override;
  void CloseVirtualDevice(const std::string& device_id) override;

 private:
  void OnOpenDeviceCallback(const OpenDeviceCallback& callback,
                            std::string device_id,
                            CreatePushSubscriptionResultCode code,
                            SerializedVideoStreamParams params);

  MojoConnector* mojo_connector_;

  // Stores a map of device ids to video_frame_handlers for receiving frame for
  // the correct mojo object associated with an open device.
  std::map<std::string /*device_id*/, std::shared_ptr<VideoFrameHandlerImpl>>
      device_id_to_video_frame_handler_map_;

  // Guards against concurrent changes to
  // |device_id_to_video_frame_handler_map_|.
  mutable std::mutex device_id_to_video_frame_handler_map_lock_;

  // Stores a map of device ids to producers for pushing frames to the correct
  // mojo object when PushFrameToVirtualDevice is called.
  // ProducerImpl objects provide an interface for buffer info updates of an
  // associated virtual device.
  std::map<std::string /*device_id*/, std::shared_ptr<ProducerImpl>>
      device_id_to_producer_map_;

  // Guards against concurrent changes to |device_id_to_producer_map_|.
  // TODO(crbug.com/918668): Remove use of locks if possible.
  mutable std::mutex device_id_to_producer_map_lock_;
};

}  // namespace mri

#endif  // MEDIA_PERCEPTION_VIDEO_CAPTURE_SERVICE_CLIENT_IMPL_H_

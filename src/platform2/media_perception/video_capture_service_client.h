// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MEDIA_PERCEPTION_VIDEO_CAPTURE_SERVICE_CLIENT_H_
#define MEDIA_PERCEPTION_VIDEO_CAPTURE_SERVICE_CLIENT_H_

// This header needs to be buildable from both Google3 and outside, so it cannot
// rely on Google3 dependencies.

#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace mri {

// Typdefs for readability. Serialized protos are passed back and forth across
// the boundary between platform2 code and librtanalytics.so
using SerializedVideoStreamParams = std::vector<uint8_t>;
using SerializedVideoDevice = std::vector<uint8_t>;
using RawPixelFormat = uint32_t;

enum CreatePushSubscriptionResultCode {
  RESULT_UNKNOWN,
  CREATED_WITH_REQUESTED_SETTINGS,
  CREATED_WITH_DIFFERENT_SETTINGS,
  ALREADY_OPEN,
  FAILED
};

// Provides the interface definition for the rtanalytics library to interact
// with the Chrome Video Capture Service. Note that the
// VideoCaptureServiceClient is thread-safe and can be shared between multiple
// clients.
class VideoCaptureServiceClient {
 public:
  using GetDevicesCallback =
      std::function<void(std::vector<SerializedVideoDevice>)>;
  using OpenDeviceCallback =
      std::function<void(std::string, /* device_id */
                         CreatePushSubscriptionResultCode,
                         SerializedVideoStreamParams)>;
  using VirtualDeviceCallback = std::function<void(SerializedVideoDevice)>;
  using FrameHandler = std::function<void(uint64_t timestamp_us,
                                          const uint8_t* data,
                                          int data_size,
                                          int frame_width,
                                          int frame_height)>;

  virtual ~VideoCaptureServiceClient() {}

  // Connects to the Video Capture Service over Mojo IPC.
  virtual bool Connect() = 0;

  // Check if the service is connected.
  virtual bool IsConnected() = 0;

  // Gets a list of video devices available.
  virtual void GetDevices(const GetDevicesCallback& callback) = 0;

  // Sets a device to be opened by the Video Capture Service with the exact
  // device_id specified. OpenDeviceCallback provides information on the success
  // or failure of the request.
  // |force_reopen_with_settings| enables a client to command the VCS to reopen
  // a video device with the requested settings. This should be used sparingly
  // as it can disrupt the video experience for frontend facing applications.
  virtual void OpenDevice(const std::string& device_id,
                          bool force_reopen_with_settings,
                          const SerializedVideoStreamParams& capture_format,
                          const OpenDeviceCallback& callback) = 0;

  // Determines if a particular device has already started capture and if it
  // has, fills in the |capture_format| with the current parameters used to
  // read frames from the device.
  virtual bool IsVideoCaptureStartedForDevice(
      const std::string& device_id,
      SerializedVideoStreamParams* capture_format) = 0;

  // Add a frame handler for a particular device id. Return value is the handler
  // id. Note that multiple clients can add a frame handler for a single device.
  // AddFrameHandler will start video capture on a device if it is not already
  // started. An return value of 0 indicates a failure to add the handler or
  // start video capture.
  virtual int AddFrameHandler(const std::string& device_id,
                              FrameHandler handler) = 0;

  // Remove a frame handler for a particular device by specifying the frame
  // handler id. Video capture on a particular device will only stop when all
  // frame handlers are removed for a particular device.
  virtual bool RemoveFrameHandler(const std::string& device_id,
                                  int frame_handler_id) = 0;

  // Interface for creating a virtual device with a set of parameters.
  virtual void CreateVirtualDevice(const SerializedVideoDevice& video_device,
                                   const VirtualDeviceCallback& callback) = 0;

  // Pushes frame data to the specified virtual device, if opened.
  virtual void PushFrameToVirtualDevice(const std::string& device_id,
                                        uint64_t timestamp_us,
                                        std::unique_ptr<const uint8_t[]> data,
                                        int data_size,
                                        RawPixelFormat pixel_format,
                                        int frame_width,
                                        int frame_height) = 0;

  // Closes the specified virtual device.
  virtual void CloseVirtualDevice(const std::string& device_id) = 0;
};

}  // namespace mri

#endif  // MEDIA_PERCEPTION_VIDEO_CAPTURE_SERVICE_CLIENT_H_

// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FACED_CAMERA_CAMERA_CLIENT_H_
#define FACED_CAMERA_CAMERA_CLIENT_H_

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <absl/status/status.h>
#include <absl/status/statusor.h>
#include <base/cancelable_callback.h>
#include <base/functional/callback_forward.h>
#include <base/memory/ref_counted.h>
#include <base/run_loop.h>
#include <base/task/sequenced_task_runner.h>
#include <base/task/thread_pool.h>
#include <base/threading/thread.h>
#include <cros-camera/camera_service_connector.h>
#include <unordered_map>

#include "faced/camera/camera_service.h"
#include "faced/camera/frame.h"

namespace faced {

// Converts a fourcc (four character code) to a Drm format name string
//
// For example, FourccToString(0x43724f53) is "CrOS".
std::string FourccToString(uint32_t fourcc);

// Checks if two cros_cam_format_info_t types are the same
bool IsFormatEqual(const cros_cam_format_info_t& fmt1,
                   const cros_cam_format_info_t& fmt2);

// Abstract interface for the class that processes incoming frames.
class FrameProcessor : public base::RefCountedThreadSafe<FrameProcessor> {
 public:
  virtual ~FrameProcessor() = default;

  // Overriden function to process frames.
  //
  // This function will be called by the CameraClient once for each frame until
  // `done` is called with a status.
  //
  // If `done` is called with `std::nullopt`, the CameraClient will continue
  // capture.
  //
  // It is guaranteed that the CameraClient will call this function in a single
  // sequence and never twice at once.
  //
  // If a second frame arrives from the camera prior to this function returning,
  // `done`, then that frame will be dropped.
  using ProcessFrameDoneCallback =
      base::OnceCallback<void(std::optional<absl::Status>)>;
  virtual void ProcessFrame(std::unique_ptr<Frame> frame,
                            ProcessFrameDoneCallback done) = 0;

 private:
  friend class base::RefCountedThreadSafe<FrameProcessor>;
};

// A CameraClient provides a high-level interface to the device camera.
class CameraClient {
 public:
  virtual ~CameraClient() = default;

  // Config struct for setting parameters for capture
  struct CaptureFramesConfig {
    // Camera id for capture
    int32_t camera_id;

    // Requested format for capture.
    // Contains resolution, file type and FPS.
    cros_cam_format_info_t format;
  };

  // Start capturing and processing frames from the camera.
  //
  // This function calls frame_processor->ProcessFrame each time a new frame
  // arrives.
  //
  // The frame_processor `ProcessFrame` implementation should return quickly,
  // performing any long-running actions asynchronously
  using StopCaptureCallback = base::OnceCallback<void(absl::Status)>;
  virtual void CaptureFrames(
      const CaptureFramesConfig& config,
      const scoped_refptr<FrameProcessor>& frame_processor,
      StopCaptureCallback capture_complete) = 0;

  // Return devices, capture formats, and resolutions supported by this
  // CrosCameraClient.
  struct DeviceInfo {
    // Camera ID
    int id;

    // User-friendly camera name, UTF-8.
    std::string name;

    // Supported formats and resolutions.
    std::vector<cros_cam_format_info_t> formats;
  };
  virtual absl::StatusOr<std::vector<DeviceInfo>> GetDevices() = 0;

  // Return information about the given device.
  virtual absl::StatusOr<DeviceInfo> GetDevice(int id) = 0;
};

// CameraClient communicates with cros-camera-service to extract camera frames
class CrosCameraClient : public CameraClient {
 public:
  // Construct CameraClient using the given camera service.
  //
  // CrosCameraClient has ownership of `camera_service`
  static absl::StatusOr<std::unique_ptr<CrosCameraClient>> Create(
      std::unique_ptr<CameraService> camera_service);

  // CrosCameraClient is not copyable
  CrosCameraClient(const CrosCameraClient&) = delete;
  CrosCameraClient& operator=(const CrosCameraClient&) = delete;

  // `CameraClient` implementation.
  void CaptureFrames(const CaptureFramesConfig& config,
                     const scoped_refptr<FrameProcessor>& frame_processor,
                     StopCaptureCallback capture_complete) override;
  absl::StatusOr<std::vector<DeviceInfo>> GetDevices() override;
  absl::StatusOr<DeviceInfo> GetDevice(int id) override;

 private:
  // CrosCameraClient can only be constructed via CrosCameraClient::Create()
  explicit CrosCameraClient(std::unique_ptr<CameraService> camera_service)
      : task_runner_(base::SequencedTaskRunner::GetCurrentDefault()),
        camera_service_(std::move(camera_service)) {}

  // Callback for the cros-camera-service to process camera captures when they
  // arrive
  //
  // Returns 0 if more frames should be captured
  static int OnCaptureResultAvailable(void* context,
                                      const cros_cam_capture_result_t* result);

  // Callback to mark completion of a single process frame operation.
  //
  // Calling with std::nullopt continues captures
  // Calling with any status, stops capture and calls capture_complete_ with
  // that status
  void CompletedProcessFrame(std::optional<absl::Status> opt_status);

  // Details about an active capture
  int camera_id_ = 0;
  cros_cam_format_info_t format_;
  bool pending_request_ =
      false;  // If there is a pending process frame request, any frames
              // received from the camera will be dropped

  // Called each time a frame is received.
  base::CancelableRepeatingCallback<void(
      std::unique_ptr<Frame>, FrameProcessor::ProcessFrameDoneCallback)>
      process_frame_callback_;

  // Task runner to call `process_frame_callback_` on.
  //
  // Required because the process frame callback is called from the
  // CameraHAL's thread.
  scoped_refptr<base::SequencedTaskRunner> task_runner_;

  StopCaptureCallback capture_complete_;

  std::unique_ptr<CameraService> camera_service_;

  // Status to return upon completion of processing frames.
  absl::Status completion_status_;
};

// Return the highest resolution format of the given device.
//
// If provided, only formats fulfilling the given predicate will be considered.
std::optional<CameraClient::CaptureFramesConfig> GetHighestResolutionFormat(
    const CameraClient::DeviceInfo& device,
    std::function<bool(const cros_cam_format_info_t&)> predicate =
        [](const cros_cam_format_info_t&) { return true; });

}  // namespace faced

#endif  // FACED_CAMERA_CAMERA_CLIENT_H_

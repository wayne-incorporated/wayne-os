/* Copyright 2016 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_HAL_USB_CAMERA_CLIENT_H_
#define CAMERA_HAL_USB_CAMERA_CLIENT_H_

#include <memory>
#include <queue>
#include <string>
#include <vector>

#include <base/functional/bind.h>
#include <base/synchronization/lock.h>
#include <base/threading/thread.h>
#include <base/threading/thread_checker.h>
#include <camera/camera_metadata.h>
#include <hardware/camera3.h>
#include <hardware/hardware.h>

#include "base/types/expected.h"
#include "cros-camera/camera_buffer_manager.h"
#include "cros-camera/camera_metrics.h"
#include "cros-camera/face_detector_client_cros_wrapper.h"
#include "cros-camera/future.h"
#include "hal/usb/cached_frame.h"
#include "hal/usb/camera_privacy_switch_monitor.h"
#include "hal/usb/capture_request.h"
#include "hal/usb/common_types.h"
#include "hal/usb/frame_buffer.h"
#include "hal/usb/metadata_handler.h"
#include "hal/usb/test_pattern.h"
#include "hal/usb/v4l2_camera_device.h"

namespace cros {

// CameraClient class is not thread-safe. There are three threads in this
// class.
// 1. Hal thread: Called from hal adapter. Constructor and OpenDevice are called
//    on hal thread.
// 2. Device ops thread: Called from hal adapter. Camera v3 Device Operations
//    (except dump) run on this thread. CloseDevice also runs on this thread.
// 3. Request thread: Owned by this class. Used to handle all requests. The
//    functions in RequestHandler run on request thread.
//
// Android framework synchronizes Constructor, OpenDevice, CloseDevice, and
// device ops. The following items are guaranteed by Android frameworks. Note
// that HAL adapter has more restrictions that all functions of device ops
// (except dump) run on the same thread.
// 1. Open, Initialize, and Close are not concurrent with any of the method in
//    device ops.
// 2. Dump can be called at any time.
// 3. ConfigureStreams is not concurrent with either ProcessCaptureRequest or
//    Flush.
// 4. Flush can be called concurrently with ProcessCaptureRequest.
// 5. ConstructDefaultRequestSettings may be called concurrently to any of the
//    device ops.
class CameraClient {
 public:
  // id is used to distinguish cameras. 0 <= id < number of cameras.
  CameraClient(int id,
               const DeviceInfo& device_info,
               const camera_metadata_t& static_metadata,
               const camera_metadata_t& request_template,
               const hw_module_t* module,
               hw_device_t** hw_device,
               CameraPrivacySwitchMonitor* hw_privacy_switch_monitor,
               ClientType client_type,
               bool sw_privacy_switch_on);
  CameraClient(const CameraClient&) = delete;
  CameraClient& operator=(const CameraClient&) = delete;
  ~CameraClient();

  // Camera Device Operations from CameraHal.
  int OpenDevice();
  int CloseDevice();
  void SetPrivacySwitchState(bool on);

  int GetId() const { return id_; }

  // Camera v3 Device Operations (see <hardware/camera3.h>)
  int Initialize(const camera3_callback_ops_t* callback_ops);
  int ConfigureStreams(camera3_stream_configuration_t* stream_config);
  // |type| is camera3_request_template_t in camera3.h.
  const camera_metadata_t* ConstructDefaultRequestSettings(int type);
  int ProcessCaptureRequest(camera3_capture_request_t* request);
  void Dump(int fd);
  int Flush(const camera3_device_t* dev);

 private:
  // StreamOnParameters is a wrapper for the parameters of StreamOn().
  struct StreamOnParameters {
    Size resolution = {0, 0};
    int crop_rotate_scale_degrees = 0;
    bool use_native_sensor_ratio = false;
    int frame_rate = 0;
  };

  using Error = int;
  // Returns Error value or a StreamOnParameters object resolving
  // |stream_config|. Parses |frame_rate| from
  // |stream_config->session_parameters| if it's available, otherwise
  // chooses device's max frame rate for the selected resolution.
  base::expected<StreamOnParameters, Error> BuildStreamOnParameters(
      const camera3_stream_configuration_t* stream_config,
      std::vector<camera3_stream_t*>& streams);

  // Verify a set of streams in aggregate.
  bool IsValidStreamSet(const std::vector<camera3_stream_t*>& streams);

  // Calculate usage and maximum number of buffers of each stream.
  void SetUpStreams(int num_buffers, std::vector<camera3_stream_t*>* streams);

  // Start |request_thread_| and streaming. Returns the
  // number of buffers or Error value.
  base::expected<int, Error> StreamOn(
      const CameraClient::StreamOnParameters& streamon_params);

  // Stop streaming and |request_thread_|.
  void StreamOff();

  // Callback function for RequestHandler::StreamOn.
  void StreamOnCallback(
      scoped_refptr<cros::Future<base::expected<int, Error>>> future,
      int num_buffers,
      Error error);

  // Callback function for RequestHandler::StreamOff.
  void StreamOffCallback(scoped_refptr<cros::Future<Error>> future,
                         Error error);

  // Check if we need and can use native sensor ratio.
  // Return true means we need to use native sensor ratio. The resolution will
  // be returned in |resolution|.
  // Use aspect ratio of native resolution to crop/scale to other resolutions in
  // HAL when there are more than 1 resolution. So we can prevent stream on/off
  // operations. Some USB cameras performance is not good for stream on/off.
  // If we can't find the resolution with native ratio, we fallback to
  // 1) stream on/off operations for BLOB format stream.
  // 2) crop/scale image of the maximum resolution stream for other streams.
  //    It may do scale up operation.
  bool ShouldUseNativeSensorRatio(
      const camera3_stream_configuration_t& stream_config, Size* resolution);

  // Camera device id.
  const int id_;

  // Camera device information.
  const DeviceInfo device_info_;

  // Camera static characteristics.
  const android::CameraMetadata static_metadata_;

  // Delegate to communicate with camera device.
  std::unique_ptr<V4L2CameraDevice> device_;

  // Camera device handle returned to framework for use.
  camera3_device_t camera3_device_;

  // Use to check the constructor and OpenDevice are called on the same thread.
  base::ThreadChecker thread_checker_;

  // Use to check camera v3 device operations are called on the same thread.
  base::ThreadChecker ops_thread_checker_;

  // Methods used to call back into the framework.
  const camera3_callback_ops_t* callback_ops_;

  // Handle metadata events and store states.
  std::unique_ptr<MetadataHandler> metadata_handler_;

  // Metadata for latest request.
  android::CameraMetadata latest_request_metadata_;

  // The formats used to report to apps.
  SupportedFormats qualified_formats_;

  // max stream resolution
  int max_stream_width_;
  int max_stream_height_;

  // max resolution used for JDA
  Size jda_resolution_cap_;

  // SW privacy switch state.
  bool sw_privacy_switch_on_;

  // RequestHandler is used to handle in-flight requests. All functions in the
  // class run on |request_thread_|. The class will be created in StreamOn and
  // destroyed in StreamOff.
  class RequestHandler {
   public:
    RequestHandler(
        const int device_id,
        const DeviceInfo& device_info,
        const android::CameraMetadata& static_metadata,
        V4L2CameraDevice* device,
        const camera3_callback_ops_t* callback_ops,
        const scoped_refptr<base::SingleThreadTaskRunner>& task_runner,
        MetadataHandler* metadata_handler,
        bool sw_privacy_switch_on_);
    ~RequestHandler();

    // Synchronous call to start streaming.
    void StreamOn(const CameraClient::StreamOnParameters& streamon_params,
                  base::OnceCallback<void(int, int)> callback);

    // Synchronous call to stop streaming.
    void StreamOff(base::OnceCallback<void(int)> callback);

    // Handle one request.
    void HandleRequest(std::unique_ptr<CaptureRequest> request);

    // Handle flush request. This function can be called on any thread.
    void HandleFlush(base::OnceCallback<void(int)> callback);

    // Get the maximum number of detected faces.
    int GetMaxNumDetectedFaces();

    // Set SW privacy switch state.
    void SetPrivacySwitchState(bool on);

   private:
    // Start streaming implementation.
    int StreamOnImpl(const CameraClient::StreamOnParameters& streamon_params);

    // Stop streaming implementation.
    int StreamOffImpl();

    // Handle aborted request when flush is called.
    void HandleAbortedRequest(camera3_capture_result_t* capture_result);

    // Check whether we should drop frames when frame is out of date.
    bool IsVideoRecording(const android::CameraMetadata& metadata);

    // Returns true if the connected device is an external camera.
    bool IsExternalCamera();

    // Returns the current buffer timestamp. It chooses hardware timestamp from
    // v4l2 buffer or software timestamp from userspace based on the device
    // specific quirks.
    uint64_t CurrentBufferTimestamp();

    // Check whether we should enable constant frame rate according to metadata.
    bool ShouldEnableConstantFrameRate(const android::CameraMetadata& metadata);

    // Check whether given |frame_rate| is valid according to
    // |static_metadata_|.
    bool IsValidFrameRate(int frame_rate);

    // Convert to |capture_result->output_buffers| with |cached_frame_|.
    int WriteStreamBuffers(const android::CameraMetadata& request_metadata,
                           camera3_capture_result_t* capture_result);

    // Some devices may output invalid image after stream on. Skip frames
    // after stream on.
    void SkipFramesAfterStreamOn(int num_frames);

    // Wait output buffer synced. Return false if fence timeout.
    bool WaitGrallocBufferSync(camera3_capture_result_t* capture_result);

    // Do not wait buffer sync for aborted requests.
    void AbortGrallocBufferSync(camera3_capture_result_t* capture_result);

    // Notify shutter event.
    void NotifyShutter(uint32_t frame_number);

    // Notify request error event.
    void NotifyRequestError(uint32_t frame_number);

    // Dequeue V4L2 frame buffer.
    int DequeueV4L2Buffer(int32_t pattern_mode);

    // Enqueue V4L2 frame buffer.
    int EnqueueV4L2Buffer();

    // Discard all out-of-date V4L2 frame buffers.
    void DiscardOutdatedBuffers();

    // Used to notify caller that all requests are handled.
    void FlushDone(base::OnceCallback<void(int)> callback);

    // Initialize |black_frame_| and fills |black_frame_| with black.
    // |stream_on_resolution_| must be set before calling this method.
    void InitializeBlackFrame();

    // Variables from CameraClient:

    const int device_id_;

    const DeviceInfo device_info_;

    const android::CameraMetadata static_metadata_;

    // Delegate to communicate with camera device. Caller owns the ownership.
    V4L2CameraDevice* device_;

    // Methods used to call back into the framework.
    const camera3_callback_ops_t* callback_ops_;

    // Task runner for request thread.
    const scoped_refptr<base::SingleThreadTaskRunner> task_runner_;

    // Variables only for RequestHandler:

    // The formats used to report to apps.
    SupportedFormats qualified_formats_;

    // Memory mapped buffers which are shared from |device_|.
    std::vector<std::unique_ptr<V4L2FrameBuffer>> input_buffers_;

    // Used to convert to different output formats.
    CachedFrame cached_frame_;

    // Handle metadata events and store states. CameraClient takes the
    // ownership.
    MetadataHandler* metadata_handler_;

    // The frame rate for stream on.
    float stream_on_fps_;

    // The current resolution for stream on.
    Size stream_on_resolution_;

    // The default resolution decided from ConfigureStreams for preview.
    Size default_resolution_;

    // Use the resolution of native sensor ratio.
    // So the image is not cropped by USB device, it is cropped in SW.
    bool use_native_sensor_ratio_;

    // Current using buffer id for |input_buffers_|.
    int current_v4l2_buffer_id_;

    // Current buffer timestamp in v4l2 buffer.
    uint64_t current_buffer_timestamp_in_v4l2_;

    // Current buffer timestamp in user space.
    uint64_t current_buffer_timestamp_in_user_;

    // Used to notify that flush is called from framework.
    bool flush_started_;

    // Used to generate test pattern.
    std::unique_ptr<TestPattern> test_pattern_;

    // Used to enable crop, rotate, and scale capability for portriat preview.
    int crop_rotate_scale_degrees_;

    bool is_video_recording_;

    std::vector<human_sensing::CrosFace> detected_faces_;

    // Used to guard |flush_started_|.
    base::Lock flush_lock_;

    // The maximum number of detected faces in the camera opening session.
    size_t max_num_detected_faces_;

    // SW privacy switch state.
    bool sw_privacy_switch_on_;

    // Set true if SW privacy switch fails to STREAMON/OFF according to the
    // switch state. When true, need to restart streaming to sync the streaming
    // state with the SW privacy switch state.
    bool sw_privacy_switch_error_occurred_ = false;

    // After the SW privacy switch is disabled, skip frames produced by
    // V4L2CameraDevice |device_| and instead send black frames until
    // |frames_to_skip_after_privacy_switch_disabled_| becomes 0.
    // |frames_to_skip_after_privacy_switch_disabled_| will be initialized by
    // |device_info_.frames_to_skip_after_streamon| after the SW privacy switch
    // changes ON from OFF. |frames_to_skip_after_privacy_switch_disabled_| will
    // be decremented every time a frame is produced.
    uint32_t frames_to_skip_after_privacy_switch_disabled_ = 0;

    // Used to fill in output frames with black pixels when the SW privacy
    // switch is ON.
    std::unique_ptr<SharedFrameBuffer> black_frame_;
  };

  std::unique_ptr<RequestHandler> request_handler_;

  // Used to handle requests.
  base::Thread request_thread_;

  // Task runner for request thread.
  scoped_refptr<base::SingleThreadTaskRunner> request_task_runner_;

  // Metrics that used to record face ae metrics.
  std::unique_ptr<CameraMetrics> camera_metrics_;
};

}  // namespace cros

#endif  // CAMERA_HAL_USB_CAMERA_CLIENT_H_

// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CAMERA_CAMERA3_TEST_CAMERA3_DEVICE_H_
#define CAMERA_CAMERA3_TEST_CAMERA3_DEVICE_H_

#include <map>
#include <memory>
#include <set>
#include <utility>
#include <vector>

#include <base/functional/callback.h>
#include <hardware/camera3.h>

#include "camera3_test/camera3_test_gralloc.h"
#include "camera3_test/common_types.h"
#include "common/utils/common_types.h"

using cros::internal::ScopedCameraMetadata;

namespace camera3_test {

// Forward declaration
class Camera3Module;
class Camera3DeviceImpl;

class Camera3Device {
 public:
  explicit Camera3Device(int cam_id);

  Camera3Device(const Camera3Device&) = delete;
  Camera3Device& operator=(const Camera3Device&) = delete;

  ~Camera3Device();

  // Initialize the device.
  int Initialize(Camera3Module* cam_module);

  // Destroy the device.
  void Destroy();

  typedef base::RepeatingCallback<void(const camera3_capture_result* result)>
      ProcessCaptureResultCallback;
  typedef base::RepeatingCallback<void(const camera3_notify_msg* msg)>
      NotifyCallback;
  typedef base::RepeatingCallback<void(
      uint32_t frame_number,
      ScopedCameraMetadata metadata,
      std::vector<cros::ScopedBufferHandle> buffers)>
      ProcessResultMetadataOutputBuffersCallback;
  typedef base::RepeatingCallback<void(
      std::vector<ScopedCameraMetadata>* partial_metadata)>
      ProcessPartialMetadataCallback;

  // Register callback function to process capture result.
  void RegisterProcessCaptureResultCallback(ProcessCaptureResultCallback cb);

  // Register callback function for notification.
  void RegisterNotifyCallback(NotifyCallback cb);

  // Register callback function to process result metadata and output buffers.
  void RegisterResultMetadataOutputBufferCallback(
      ProcessResultMetadataOutputBuffersCallback cb);

  // Register callback function to process partial metadata.
  void RegisterPartialMetadataCallback(ProcessPartialMetadataCallback cb);

  // Whether or not the template is supported.
  bool IsTemplateSupported(int32_t type);

  // Construct default request settings.
  const camera_metadata_t* ConstructDefaultRequestSettings(int type);

  // Add output stream in preparation for stream configuration.
  void AddOutputStream(int format,
                       int width,
                       int height,
                       camera3_stream_rotation_t crop_rotate_scale_degrees);

  // Add input stream in preparation for stream configuration.
  void AddInputStream(int format, int width, int height);

  // Add bidirection stream in preparation for stream configuration.
  void AddBidirectionalStream(int format, int width, int height);

  // Add output stream with raw |crop_rotate_scale_degrees| values. This
  // function should be used for testing invalid values only.
  void AddOutputStreamWithRawDegrees(int format,
                                     int width,
                                     int height,
                                     int crop_rotate_scale_degrees);

  // Configure streams and return configured streams if |streams| is not null.
  int ConfigureStreams(std::vector<const camera3_stream_t*>* streams);

  // Allocate output buffers for all configured streams and return them
  // in the stream buffer format, which has the buffer associated to the
  // corresponding stream. The allocated buffers are owned by Camera3Device.
  int AllocateOutputStreamBuffers(
      std::vector<camera3_stream_buffer_t>* output_buffers);

  // Allocate output buffers for given streams |streams| and return them
  // in the stream buffer format, which has the buffer associated to the
  // corresponding stream. The allocated buffers are owned by Camera3Device.
  int AllocateOutputBuffersByStreams(
      const std::vector<const camera3_stream_t*>& streams,
      std::vector<camera3_stream_buffer_t>* output_buffers);

  // Register buffer |unique_buffer| that is associated with the given stream
  // |stream|. Camera3Device takes buffer ownership.
  int RegisterOutputBuffer(const camera3_stream_t& stream,
                           cros::ScopedBufferHandle unique_buffer);

  // Process given capture request |capture_request|. The frame number field of
  // |capture_request| will be overwritten if this method returns 0 on success.
  int ProcessCaptureRequest(camera3_capture_request_t* capture_request);

  // Wait for shutter with timeout. |abs_timeout| specifies an absolute timeout
  // in seconds and nanoseconds since the Epoch, 1970-01-01 00:00:00 +0000
  // (UTC), that the call should block if the shutter is immediately available.
  int WaitShutter(const struct timespec& abs_timeout);

  // Wait for capture result with timeout. |abs_timeout| specifies an absolute
  // timeout in seconds and nanoseconds since the Epoch, 1970-01-01 00:00:00
  // +0000 (UTC), that the call should block if the shutter is immediately
  // available.
  int WaitCaptureResult(const struct timespec& abs_timeout);

  // Flush all currently in-process captures and all buffers in the pipeline.
  int Flush();

  // Get static information.
  class StaticInfo;
  const StaticInfo* GetStaticInfo() const;

 private:
  std::unique_ptr<Camera3DeviceImpl> impl_;
};

class Camera3Device::StaticInfo {
 public:
  explicit StaticInfo(const camera_info& cam_info);

  StaticInfo(const StaticInfo&) = delete;
  StaticInfo& operator=(const StaticInfo&) = delete;

  // Determine whether or not all the keys are available
  bool IsKeyAvailable(uint32_t tag) const;
  bool AreKeysAvailable(std::vector<uint32_t> tags) const;

  // Whether or not the hardware level reported is at least full
  bool IsHardwareLevelAtLeastFull() const;

  // Whether or not the hardware level reported is at least external
  bool IsHardwareLevelAtLeastExternal() const;

  // Determine whether the current device supports a capability or not
  bool IsCapabilitySupported(uint8_t capability) const;

  // Check if depth output is supported, based on the depth capability
  bool IsDepthOutputSupported() const;

  // Check if standard outputs (PRIVATE, YUV, JPEG) outputs are supported,
  // based on the backwards-compatible capability
  bool IsColorOutputSupported() const;

  // Whether or not the key is in the list of available request keys.
  bool HasAvailableRequestKey(int32_t key) const;

  // Get available edge modes
  std::set<uint8_t> GetAvailableEdgeModes() const;

  // Get available noise reduction modes
  std::set<uint8_t> GetAvailableNoiseReductionModes() const;

  // Get available noise reduction modes
  std::set<uint8_t> GetAvailableColorAberrationModes() const;

  // Get available tone map modes
  std::set<uint8_t> GetAvailableToneMapModes() const;

  // Get available fps ranges
  std::set<std::pair<int32_t, int32_t>> GetAvailableFpsRanges() const;

  // Get available formats for a given direction
  // direction: ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS_OUTPUT or
  //            ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS_INPUT
  std::set<int32_t> GetAvailableFormats(int32_t direction) const;

  // Check if a stream format is supported
  bool IsFormatAvailable(int format) const;

  // Get the image output resolutions in this stream configuration
  std::vector<ResolutionInfo> GetSortedOutputResolutions(int32_t format) const;

  // Get the image input resolutions in this stream configuration
  std::vector<ResolutionInfo> GetSortedInputResolutions(int32_t format) const;

  // Get the image resolutions in this stream configuration
  std::vector<ResolutionInfo> GetSortedResolutions(int32_t format,
                                                   bool is_output) const;

  // Get available input format to output format
  bool GetInputOutputConfigurationMap(
      std::map<int32_t, std::vector<int32_t>>* config_map) const;

  // Determine if camera device support AE lock control
  bool IsAELockSupported() const;

  // Determine if camera device support AWB lock control
  bool IsAWBLockSupported() const;

  // Get the maximum number of partial result a request can expect
  // Returns: maximum number of partial results; it is 1 by default.
  int32_t GetPartialResultCount() const;

  // Get the number of maximum pipeline stages a frame has to go through from
  // when it's exposed to when it's available to the framework
  // Returns: number of maximum pipeline stages on success; corresponding error
  // code on failure.
  uint8_t GetRequestPipelineMaxDepth() const;

  // Get the maximum size of JPEG image
  // Returns: maximum size of JPEG image on success; corresponding error code
  // on failure.
  int32_t GetJpegMaxSize() const;

  // Get the sensor orientation
  // Returns: degrees on success; corresponding error code on failure.
  int32_t GetSensorOrientation() const;

  // Get available thumbnail sizes
  // Returns: 0 on success; corresponding error code on failure.
  int32_t GetAvailableThumbnailSizes(
      std::vector<ResolutionInfo>* resolutions) const;

  // Get available focal lengths
  // Returns: 0 on success; corresponding error code on failure.
  int32_t GetAvailableFocalLengths(std::vector<float>* focal_lengths) const;

  // Get available apertures
  // Returns: 0 on success; corresponding error code on failure.
  int32_t GetAvailableApertures(std::vector<float>* apertures) const;

  // Get available AF modes
  // Returns: 0 on success; corresponding error code on failure.
  int32_t GetAvailableAFModes(std::vector<uint8_t>* af_modes) const;

  // Get available sensor test pattern modes
  // Returns: 0 on success; corresponding error code on failure.
  int32_t GetAvailableTestPatternModes(
      std::vector<int32_t>* test_pattern_modes) const;

  // Get available face detection modes
  // Returns: 0 on success; corresponding error code on failure.
  int32_t GetAvailableFaceDetectModes(
      std::set<uint8_t>* face_detect_modes) const;

  // Get max AE regions
  int32_t GetAeMaxRegions() const;

  // Get max AWB regions
  int32_t GetAwbMaxRegions() const;

  // Get max AF regions
  int32_t GetAfMaxRegions() const;

  // Get sensor pixel array size
  int32_t GetSensorPixelArraySize(uint32_t* width, uint32_t* height) const;

  // Return the supported hardware level of the device, or fail if no value is
  // reported
  uint8_t GetHardwareLevel() const;

  // Get ANDROID_SCALER_AVAILABLE_ROTATE_AND_CROP_MODES.
  std::set<uint8_t> GetAvailableRotateAndCropModes() const;

 private:
  bool IsHardwareLevelAtLeast(uint8_t level) const;

  std::set<uint8_t> GetAvailableModes(int32_t key,
                                      int32_t min_value,
                                      int32_t max_value) const;

  void GetStreamConfigEntry(camera_metadata_ro_entry_t* entry) const;

  const camera_metadata_t* characteristics_;
};

}  // namespace camera3_test

#endif  // CAMERA_CAMERA3_TEST_CAMERA3_DEVICE_H_

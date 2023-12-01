// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CAMERA_CAMERA3_TEST_CAMERA3_DEVICE_IMPL_H_
#define CAMERA_CAMERA3_TEST_CAMERA3_DEVICE_IMPL_H_

#include <semaphore.h>

#include <deque>
#include <memory>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include <base/threading/thread_checker.h>

#include "camera3_test/camera3_device_connector.h"
#include "camera3_test/camera3_device_fixture.h"
#include "common/utils/common_types.h"

namespace camera3_test {

const uint32_t kInitialFrameNumber = 0;

// This class is thread-safe except the Flush function, which must be called
// after the Initialize function returns successfully.
class Camera3DeviceImpl : protected camera3_callback_ops {
 public:
  explicit Camera3DeviceImpl(int cam_id);

  Camera3DeviceImpl(const Camera3DeviceImpl&) = delete;
  Camera3DeviceImpl& operator=(const Camera3DeviceImpl&) = delete;

  int Initialize(Camera3Module* cam_module);

  void RegisterProcessCaptureResultCallback(
      Camera3Device::ProcessCaptureResultCallback cb);

  void RegisterNotifyCallback(Camera3Device::NotifyCallback cb);

  void RegisterResultMetadataOutputBufferCallback(
      Camera3Device::ProcessResultMetadataOutputBuffersCallback cb);

  void RegisterPartialMetadataCallback(
      Camera3Device::ProcessPartialMetadataCallback cb);

  bool IsTemplateSupported(int32_t type);

  void AddStream(int format,
                 int width,
                 int height,
                 int crop_rotate_scale_degrees,
                 camera3_stream_type_t type);

  const camera_metadata_t* ConstructDefaultRequestSettings(int type);

  int ConfigureStreams(std::vector<const camera3_stream_t*>* streams);

  int AllocateOutputStreamBuffers(
      std::vector<camera3_stream_buffer_t>* output_buffers);

  int AllocateOutputBuffersByStreams(
      const std::vector<const camera3_stream_t*>& streams,
      std::vector<camera3_stream_buffer_t>* output_buffers);

  int RegisterOutputBuffer(const camera3_stream_t& stream,
                           cros::ScopedBufferHandle unique_buffer);

  int ProcessCaptureRequest(camera3_capture_request_t* request);

  int WaitShutter(const struct timespec& timeout);

  int WaitCaptureResult(const struct timespec& timeout);

  int Flush();

  void Destroy();

  const Camera3Device::StaticInfo* GetStaticInfo() const;

 private:
  void InitializeOnThread(Camera3Module* cam_module, int* result);

  void RegisterProcessCaptureResultCallbackOnThread(
      Camera3Device::ProcessCaptureResultCallback cb);

  void RegisterNotifyCallbackOnThread(Camera3Device::NotifyCallback cb);

  void RegisterResultMetadataOutputBufferCallbackOnThread(
      Camera3Device::ProcessResultMetadataOutputBuffersCallback cb);

  void RegisterPartialMetadataCallbackOnThread(
      Camera3Device::ProcessPartialMetadataCallback cb);

  void IsTemplateSupportedOnThread(int32_t type, bool* result);

  void AddStreamOnThread(int format,
                         int width,
                         int height,
                         int crop_rotate_scale_degrees,
                         camera3_stream_type_t output);

  void ConstructDefaultRequestSettingsOnThread(
      int type, const camera_metadata_t** result);

  void ConfigureStreamsOnThread(std::vector<const camera3_stream_t*>* streams,
                                int* result);

  void AllocateOutputStreamBuffersOnThread(
      std::vector<camera3_stream_buffer_t>* output_buffers, int32_t* result);

  void AllocateOutputBuffersByStreamsOnThread(
      const std::vector<const camera3_stream_t*>* streams,
      std::vector<camera3_stream_buffer_t>* output_buffers,
      int32_t* result);

  void RegisterOutputBufferOnThread(const camera3_stream_t* stream,
                                    cros::ScopedBufferHandle unique_buffer,
                                    int32_t* result);

  void ProcessCaptureRequestOnThread(camera3_capture_request_t* request,
                                     int* result);

  void DestroyOnThread(int* result);

  // Static callback forwarding methods from HAL to instance
  static void ProcessCaptureResultForwarder(
      const camera3_callback_ops* cb, const camera3_capture_result_t* result);

  // Static callback forwarding methods from HAL to instance
  static void NotifyForwarder(const camera3_callback_ops* cb,
                              const camera3_notify_msg_t* msg);

  struct StreamBuffer : camera3_stream_buffer_t {
    explicit StreamBuffer(const camera3_stream_buffer_t& buffer);
    buffer_handle_t buffer_handle;
  };

  struct CaptureResult : camera3_capture_result_t {
    explicit CaptureResult(const camera3_capture_result_t& result);
    ScopedCameraMetadata metadata_result;
    std::vector<StreamBuffer> stream_buffers;
  };

  // Callback functions from HAL device
  void ProcessCaptureResult(const camera3_capture_result_t* result);

  void ProcessCaptureResultOnThread(std::unique_ptr<CaptureResult> result);

  // Callback functions from HAL device
  void Notify(const camera3_notify_msg_t* msg);

  void NotifyOnThread(camera3_notify_msg_t msg);

  // Get the buffers out of the given stream buffers |output_buffers|. The
  // buffers are return in the container |unique_buffers|, and the caller of
  // the function is expected to take the buffer ownership.
  int GetOutputStreamBufferHandles(
      const std::vector<StreamBuffer>& output_buffers,
      std::vector<cros::ScopedBufferHandle>* unique_buffers);

  // Whether or not partial result is used
  bool UsePartialResult() const;

  // Process and handle partial result of one callback. The |metadata_result|
  // field of |result| will be reset.
  void ProcessPartialResult(CaptureResult* result);

  const std::string GetThreadName(int cam_id);

  const int cam_id_;

  // This thread is needed because of the Chrome OS camera HAL adapter
  // assumption that all the camera3_device_ops functions, except dump, should
  // be called on the same thread. Each device is accessed through a different
  // thread.
  cros::CameraThread hal_thread_;

  THREAD_CHECKER(thread_checker_);

  bool initialized_;

  std::unique_ptr<DeviceConnector> dev_connector_;

  uint32_t device_api_version_;

  std::unique_ptr<Camera3Device::StaticInfo> static_info_;

  // Two bins of streams for swapping while configuring new streams
  std::vector<cros::internal::camera3_stream_aux_t> cam_stream_[2];

  // Index of active streams
  int cam_stream_idx_;

  Camera3TestGralloc* gralloc_;

  // Store allocated buffers with streams as the key
  std::unordered_map<const camera3_stream_t*,
                     std::vector<cros::ScopedBufferHandle>>
      stream_buffer_map_;

  uint32_t request_frame_number_;

  // Store created capture requests with frame number as the key
  std::unordered_map<uint32_t, camera3_capture_request_t> capture_request_map_;

  // Store the frame numbers of capture requests that HAL has finished
  // processing
  std::set<uint32_t> completed_request_set_;

  // Store the capture output buffers with streams as the key to verify that
  // buffers of the same stream are delivered in capture order
  std::unordered_map<camera3_stream_t*, std::deque<buffer_handle_t>>
      stream_output_buffer_map_;

  class CaptureResultInfo {
   public:
    CaptureResultInfo();

    // Determine whether or not the key is available
    bool IsMetadataKeyAvailable(int32_t key) const;

    // Find and get key value from partial metadata
    int32_t GetMetadataKeyValue(int32_t key) const;

    // Find and get key value in int64_t from partial metadata
    int64_t GetMetadataKeyValue64(int32_t key) const;

    // Merge partial metadata into one.
    ScopedCameraMetadata MergePartialMetadata();

    bool have_input_buffer_;

    uint32_t num_output_buffers_;

    bool have_result_metadata_;

    std::vector<ScopedCameraMetadata> partial_metadata_;

    std::vector<StreamBuffer> output_buffers_;

   private:
    bool GetMetadataKeyEntry(int32_t key,
                             camera_metadata_ro_entry_t* entry) const;

    THREAD_CHECKER(thread_checker_);
  };

  // Store capture result information with frame number as the key
  std::unordered_map<uint32_t, CaptureResultInfo> capture_result_info_map_;

  sem_t shutter_sem_;

  sem_t capture_result_sem_;

  Camera3Device::ProcessCaptureResultCallback process_capture_result_cb_;

  Camera3Device::NotifyCallback notify_cb_;

  Camera3Device::ProcessResultMetadataOutputBuffersCallback
      process_result_metadata_output_buffers_cb_;

  Camera3Device::ProcessPartialMetadataCallback process_partial_metadata_cb_;
};

}  // namespace camera3_test

#endif  // CAMERA_CAMERA3_TEST_CAMERA3_DEVICE_IMPL_H_

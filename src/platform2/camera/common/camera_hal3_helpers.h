/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_COMMON_CAMERA_HAL3_HELPERS_H_
#define CAMERA_COMMON_CAMERA_HAL3_HELPERS_H_

#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <cutils/native_handle.h>
#include <base/containers/span.h>
#include <base/synchronization/lock.h>
#include <camera/camera_metadata.h>
#include <hardware/camera3.h>

#include "cros-camera/camera_face_detection.h"
#include "cros-camera/common.h"
#include "cros-camera/common_types.h"
#include "cros-camera/export.h"

namespace perfetto {

// Forward declaring perfetto::EventContext instead of including the perfetto
// header file to avoid macro/variable definitions collisions between libchrome
// and perfetto.
class EventContext;

}  // namespace perfetto

namespace cros {

// Types of effects that can be applied to the camera stream.
enum StreamEffectType {
  kDefault = 0,
  kPortraitMode = 1,
};

// Generic base struct for stream effect. Used by StreamEffectMap.
struct StreamEffect {
  StreamEffectType type = StreamEffectType::kDefault;
};

struct PortraitModeStreamEffect : public StreamEffect {
  bool enable_rectiface = false;
};

// A mapper from a camera3_stream_t pointer to a vector of StreamEffect objects.
// This is used to pass the effects information that is applied to each stream.
using StreamEffectMap =
    std::map<const camera3_stream_t*,
             std::vector<std::unique_ptr<const StreamEffect>>>;

// Utility function to produce a debug string for the given camera3_stream_t
// |stream|.
inline std::string GetDebugString(const camera3_stream_t* stream) {
  return base::StringPrintf(
      "stream=%p, type=%d, size=%ux%u, format=%d, usage=%u, max_buffers=%u, "
      "rotation=%d, crop_rotate_scale_degrees=%d",
      stream, stream->stream_type, stream->width, stream->height,
      stream->format, stream->usage, stream->max_buffers, stream->rotation,
      stream->crop_rotate_scale_degrees);
}

inline bool HaveSameAspectRatio(const camera3_stream_t* s1,
                                const camera3_stream_t* s2) {
  return (s1->width * s2->height == s1->height * s2->width);
}

template <typename T>
inline Rect<float> NormalizeRect(const Rect<T>& rect, const Size& size) {
  return Rect<float>(
      static_cast<float>(rect.left) / static_cast<float>(size.width),
      static_cast<float>(rect.top) / static_cast<float>(size.height),
      static_cast<float>(rect.width) / static_cast<float>(size.width),
      static_cast<float>(rect.height) / static_cast<float>(size.height));
}

template <typename T>
inline Rect<T> ClampRect(const Rect<T>& rect, const Rect<T>& bound) {
  const T left = std::clamp(rect.left, bound.left, bound.right());
  const T top = std::clamp(rect.top, bound.top, bound.bottom());
  const T right = std::clamp(rect.right(), bound.left, bound.right());
  const T bottom = std::clamp(rect.bottom(), bound.top, bound.bottom());
  return Rect<T>(left, top, right - left + 1, bottom - top + 1);
}

// Returns the maximum centering crop window within |size| with the specified
// aspect ratio.
CROS_CAMERA_EXPORT Rect<uint32_t> GetCenteringFullCrop(Size size,
                                                       uint32_t aspect_ratio_x,
                                                       uint32_t aspect_ratio_y);

bool AddListItemToMetadataTag(android::CameraMetadata* metadata,
                              uint32_t tag,
                              int32_t item);

// Waits on |buffer.release_fence|, if valid, to be signalled with timeout
// |timeout_ms|. Returns true if the release fence is invalid (i.e. equals to
// -1), or if the fence is signalled within |timeout_ms|. Returns false
// otherwise.
//
// |buffer.release_fence| is closed and resets it to -1 on success. The function
// leaves |buffer.release_fence| untouched if the fence wait times out.
[[nodiscard]] bool CROS_CAMERA_EXPORT
WaitOnAndClearReleaseFence(camera3_stream_buffer_t& buffer, int timeout_ms);

// Extracts frame number from a notify message.
inline uint32_t GetFrameNumber(const camera3_notify_msg_t& msg) {
  switch (msg.type) {
    case CAMERA3_MSG_ERROR:
      return msg.message.error.frame_number;
    case CAMERA3_MSG_SHUTTER:
      return msg.message.shutter.frame_number;
    default:
      NOTREACHED();
      return 0u;
  }
}

// A container for passing metadata across different StreamManipulator instances
// to allow different feature implementations to communicate with one another.
struct FeatureMetadata {
  // |hdr_ratio| produced by GcamAeStreamManipulator and consumed by
  // HdrNetStreamManipulator for HDRnet output frame rendering.
  std::optional<float> hdr_ratio;

  // The face rectangles detected by the FaceDetectionStreamManipulator when
  // CrOS face detector is enabled. The coordinates of the rectangles are
  // normalized with respect to the active sensor array size. The face ROIs are
  // consumed by GcamAeStreamManipulator as input metadata.
  std::optional<std::vector<human_sensing::CrosFace>> faces;
};

// A helper class that wraps a camera3_stream_buffer_t object to facilitate
// event tracing and simplify data access.
//
// The class does not take ownership of any of the resources in the input
// camera3_stream_buffer_t object. Specifically, the owner of the raw buffer
// object is responsible for managing the acquire and release fence FDs, either
// by passing on the ownership to the camera client or camera HAL, or closing
// the fence FD before setting a new one.
class CROS_CAMERA_EXPORT Camera3StreamBuffer {
 public:
  // The flow direction of the buffer. A buffer is either an input buffer from
  // the upper layer, or an output buffer that needs to be filled by the lower
  // layer.
  enum class Direction {
    kInvalidDirection = -1,
    kInput = 0,
    kOutput = 1,
  };

  // The type of the buffer. A buffer should either be associated with a capture
  // request or a capture result.
  enum class Type {
    kInvalidType = -1,
    kRequest = 0,
    kResult = 1,
  };

  static constexpr camera3_stream_buffer_t kInvalidRawBuffer = {
      .stream = nullptr,
      .buffer = nullptr,
      .status = CAMERA3_BUFFER_STATUS_ERROR,
      .acquire_fence = -1,
      .release_fence = -1,
  };

  static Camera3StreamBuffer MakeRequestInput(
      const camera3_stream_buffer_t& stream_buffer);
  static Camera3StreamBuffer MakeRequestOutput(
      const camera3_stream_buffer_t& stream_buffer);
  static Camera3StreamBuffer MakeResultInput(
      const camera3_stream_buffer_t& stream_buffer);
  static Camera3StreamBuffer MakeResultOutput(
      const camera3_stream_buffer_t& stream_buffer);

  // Default constructor creates an invalid buffer.
  Camera3StreamBuffer() = default;
  ~Camera3StreamBuffer();

  Camera3StreamBuffer(Camera3StreamBuffer&& other);
  Camera3StreamBuffer& operator=(Camera3StreamBuffer&& other);

  Camera3StreamBuffer(const Camera3StreamBuffer& other) = delete;
  Camera3StreamBuffer& operator=(const Camera3StreamBuffer& other) = delete;

  // See the docstring of WaitOnAndClearReleaseFence above.
  [[nodiscard]] bool WaitOnAndClearReleaseFence(int timeout_ms) {
    return cros::WaitOnAndClearReleaseFence(raw_buffer_, timeout_ms);
  }

  // Starts and ends a trace slice that associates the buffer with
  // |frame_number|.
  void StartTracing(int frame_number);
  void EndTracing();

  // Used for creating a Perfetto flow to visualize the buffer lifecycle.
  uint64_t flow_id() const { return reinterpret_cast<uintptr_t>(*buffer()); }

  bool is_valid() const {
    return raw_buffer_.stream != nullptr && raw_buffer_.buffer != nullptr &&
           *raw_buffer_.buffer != nullptr;
  }

  const camera3_stream_t* stream() const { return raw_buffer_.stream; }
  const buffer_handle_t* buffer() const { return raw_buffer_.buffer; }
  int status() const { return raw_buffer_.status; }
  int acquire_fence() const { return raw_buffer_.acquire_fence; }
  int release_fence() const { return raw_buffer_.release_fence; }

  int take_release_fence() {
    int fence = raw_buffer_.release_fence;
    raw_buffer_.release_fence = -1;
    return fence;
  }

  const camera3_stream_buffer_t& raw_buffer() const { return raw_buffer_; }
  camera3_stream_buffer_t& mutable_raw_buffer() { return raw_buffer_; }

 protected:
  // LockAndFill is called only by the Camera3CaptureDescriptor to expose the
  // input and output buffers in raw capture requests/results. Since the raw
  // buffer states can be modified, we sync |container| back to |raw_buffer_| in
  // Unlock.
  friend class Camera3CaptureDescriptor;
  void LockAndFill(camera3_stream_buffer_t* container);
  void Unlock();

 private:
  Camera3StreamBuffer(const camera3_stream_buffer_t& stream_buffer,
                      Type type,
                      Direction dir);
  void Invalidate();

  camera3_stream_buffer_t raw_buffer_ = kInvalidRawBuffer;
  Type type_ = Type::kInvalidType;
  Direction dir_ = Direction::kInvalidDirection;
  camera3_stream_buffer_t* lock_container_ = nullptr;
  bool trace_started_ = false;
};

// A helper class to make it easy to modify camera3_stream_configuration_t.
//
// The class is not thread-safe. The user of this class needs to ensure that the
// method calls are serialized and also that the class instance remains valid
// when the data members are being referenced externally.
class CROS_CAMERA_EXPORT Camera3StreamConfiguration {
 public:
  // Default constructor creates an invalid instance.
  Camera3StreamConfiguration() = default;
  explicit Camera3StreamConfiguration(
      const camera3_stream_configuration_t& stream_list);
  ~Camera3StreamConfiguration() = default;

  Camera3StreamConfiguration(Camera3StreamConfiguration&& other) = default;
  Camera3StreamConfiguration& operator=(Camera3StreamConfiguration&& other) =
      default;
  Camera3StreamConfiguration(const Camera3StreamConfiguration& other) = delete;
  Camera3StreamConfiguration& operator=(
      const Camera3StreamConfiguration& other) = delete;

  // Gets the stream configuration in a span.
  base::span<camera3_stream_t* const> GetStreams() const;

  // Sets the stream configuration to |streams|.
  bool SetStreams(base::span<camera3_stream_t* const> streams);

  // Appends |stream| to the stream configuration.
  bool AppendStream(camera3_stream_t* stream);

  // Removes |stream| from the stream configuration.
  bool RemoveStream(const camera3_stream_t* stream);

  // Locks the internal data and get the camera3_stream_configuration_t that can
  // be consumed by the Android HAL3 API.
  camera3_stream_configuration_t* Lock();

  // Unlocks the instance for further modification.
  void Unlock();

  // Returns a JSON string describing the stream configurations.
  std::string ToJsonString() const;

  // Populates the given event context with the stream info debug annotation.
  void PopulateEventAnnotation(perfetto::EventContext& ctx) const;

  bool is_valid() const { return !streams_.empty(); }
  uint32_t num_streams() const { return streams_.size(); }
  uint32_t operation_mode() const { return operation_mode_; }

 private:
  bool IsLocked() const;

  std::vector<camera3_stream_t*> streams_;
  uint32_t operation_mode_ = 0;
  const camera_metadata_t* session_parameters_ = nullptr;

  std::optional<camera3_stream_configuration_t> raw_configuration_;
};

// A helper class to make it easy to modify camera3_capture_request_t and
// camera3_capture_result_t objects.
//
// The class is not thread-safe. The user of this class needs to ensure that the
// method calls are serialized and also that the class instance remains valid
// when the data members are being referenced externally.
class CROS_CAMERA_EXPORT Camera3CaptureDescriptor {
 public:
  enum class Type {
    kInvalidType = -1,
    kCaptureRequest,
    kCaptureResult,
  };

  // Default constructor creates an invalid instance.
  Camera3CaptureDescriptor() = default;

  explicit Camera3CaptureDescriptor(const camera3_capture_request_t& request);
  explicit Camera3CaptureDescriptor(const camera3_capture_result_t& result);

  ~Camera3CaptureDescriptor();

  Camera3CaptureDescriptor(Camera3CaptureDescriptor&& other);
  Camera3CaptureDescriptor& operator=(Camera3CaptureDescriptor&& other);
  Camera3CaptureDescriptor(const Camera3CaptureDescriptor& other) = delete;
  Camera3CaptureDescriptor& operator=(const Camera3CaptureDescriptor& other) =
      delete;

  // Metadata getter and setter. The templated methods only support the six data
  // types defined for Android camera_metadata_entry_t: uint8_t, int32_t, float,
  // double, int64_t, camera_metadata_rational_t.

  // Check the metadata exists with |tag|.
  bool HasMetadata(uint32_t tag) const;

  // Gets the metadata associated with |tag| as span. Returns empty span if
  // there's no metadata associated with |tag|.
  template <typename T>
  base::span<const T> GetMetadata(uint32_t tag) const;

  // Updates, and creates if not exist, the metadata associated with |tag| with
  // |values|. Returns true if the metadata is successfully updated; false
  // otherwise.
  template <typename T>
  bool UpdateMetadata(uint32_t tag, base::span<const T> values) {
    if (IsLocked()) {
      LOGF(ERROR) << "Cannot update metadata when locked";
      return false;
    }
    auto ret = metadata_.update(tag, values.data(), values.size());
    return ret == 0;
  }

  // Appends |metadata| to |metadata_|. Returns true if |metadata| is
  // successfully appended; false otherwise.
  bool AppendMetadata(const camera_metadata_t* metadata);

  // Deletes the metadata associated with |tag|. Returns true if the metadata is
  // successfully deleted; false otherwise.
  bool DeleteMetadata(uint32_t tag);

  // Sets the existing metadata by copying the contents from |metadata|.
  // Returns true if the metadata are set successfully; false otherwise.
  bool SetMetadata(const camera_metadata_t* metadata);

  // Getter and setter for the input buffer.
  const Camera3StreamBuffer* GetInputBuffer() const;
  std::optional<Camera3StreamBuffer> AcquireInputBuffer();
  void SetInputBuffer(Camera3StreamBuffer input_buffer);

  // Getter and setter for the output buffers.
  base::span<const Camera3StreamBuffer> GetOutputBuffers() const;
  base::span<Camera3StreamBuffer> GetMutableOutputBuffers();
  std::vector<Camera3StreamBuffer> AcquireOutputBuffers();
  void SetOutputBuffers(std::vector<Camera3StreamBuffer> output_buffers);
  void AppendOutputBuffer(Camera3StreamBuffer buffer);

  // Locks the internal data and get the raw camera3_capture_request_t /
  // camera3_capture_result_t that can be consumed by the Android HAL3 API.
  camera3_capture_request_t* LockForRequest();
  camera3_capture_result_t* LockForResult();
  camera3_capture_request_t* GetLockedRequest();
  camera3_capture_result_t* GetLockedResult();

  // Unlocks the descriptor for further modification.
  void Unlock();

  // Returns a JSON string describing the capture request / result.
  std::string ToJsonString() const;

  // Populates the given event context with the capture info debug annotation.
  void PopulateEventAnnotation(perfetto::EventContext& ctx) const;

  bool is_valid() const { return type_ != Type::kInvalidType; }
  uint32_t frame_number() const { return frame_number_; }
  bool has_metadata() const { return !metadata_.isEmpty(); }
  bool has_input_buffer() const { return input_buffer_.has_value(); }
  uint32_t num_output_buffers() const { return output_buffers_.size(); }
  uint32_t partial_result() const { return partial_result_; }

  FeatureMetadata& feature_metadata() { return feature_metadata_; }
  const FeatureMetadata& feature_metadata() const { return feature_metadata_; }

 protected:
  void Invalidate();
  bool IsLocked() const;

  Type type_ = Type::kInvalidType;

  // Flattened data for both kCaptureRequest and kCaptureResult.
  uint32_t frame_number_ = 0;
  android::CameraMetadata metadata_;
  std::optional<Camera3StreamBuffer> input_buffer_;
  std::vector<Camera3StreamBuffer> output_buffers_;

  // For kCaptureResult only.
  uint32_t partial_result_ = 0;

  // The physical camera info are not being active used at the moment, so we
  // just use these fields to keep track of the original values.
  uint32_t num_physcam_metadata_ = 0;
  const char** physcam_ids_ = nullptr;
  const camera_metadata_t** physcam_metadata_ = nullptr;

  FeatureMetadata feature_metadata_;

  union RawDescriptor {
    camera3_capture_request_t raw_request;
    camera3_capture_result_t raw_result;
  };
  std::vector<camera3_stream_buffer_t> raw_output_buffers_;
  std::optional<RawDescriptor> raw_descriptor_;
};

template <>
CROS_CAMERA_EXPORT base::span<const uint8_t>
Camera3CaptureDescriptor::GetMetadata(uint32_t tag) const;

template <>
CROS_CAMERA_EXPORT base::span<const int32_t>
Camera3CaptureDescriptor::GetMetadata(uint32_t tag) const;

template <>
CROS_CAMERA_EXPORT base::span<const float>
Camera3CaptureDescriptor::GetMetadata(uint32_t tag) const;

template <>
CROS_CAMERA_EXPORT base::span<const double>
Camera3CaptureDescriptor::GetMetadata(uint32_t tag) const;

template <>
CROS_CAMERA_EXPORT base::span<const int64_t>
Camera3CaptureDescriptor::GetMetadata(uint32_t tag) const;

template <>
CROS_CAMERA_EXPORT base::span<const camera_metadata_rational_t>
Camera3CaptureDescriptor::GetMetadata(uint32_t tag) const;

}  // namespace cros

#endif  // CAMERA_COMMON_CAMERA_HAL3_HELPERS_H_

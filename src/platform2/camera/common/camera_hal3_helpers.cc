/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "common/camera_hal3_helpers.h"

#include <algorithm>
#include <cstdint>
#include <functional>
#include <optional>
#include <utility>

#include <base/json/json_writer.h>
#include <base/notreached.h>
#include <base/values.h>
#include <hardware/camera3.h>
#include <sync/sync.h>

#include "common/camera_buffer_handle.h"
#include "common/common_tracing.h"
#include "cros-camera/tracing.h"

namespace cros {

namespace {

base::Value::Dict ToValueDict(const camera3_stream_t* stream) {
  if (!stream) {
    return base::Value::Dict();
  }
  base::Value::Dict s;
  s.Set("stream_type", stream->stream_type);
  s.Set("width", base::checked_cast<int>(stream->width));
  s.Set("height", base::checked_cast<int>(stream->height));
  s.Set("format", stream->format);
  s.Set("usage", base::checked_cast<int>(stream->usage));
  s.Set("max_buffers", base::checked_cast<int>(stream->max_buffers));
  s.Set("data_space", stream->data_space);
  s.Set("rotation", stream->rotation);
  if (stream->physical_camera_id) {
    s.Set("physical_camera_id", stream->physical_camera_id);
  }
  return s;
}

base::Value::Dict ToValueDict(const Camera3StreamBuffer& buffer) {
  base::Value::Dict b;
  b.Set("stream", ToValueDict(buffer.stream()));
  b.Set("status", buffer.status());
  b.Set("acquire_fence", buffer.acquire_fence());
  b.Set("release_fence", buffer.release_fence());
  return b;
}

perfetto::StaticString GetBufferDirectionStr(
    Camera3StreamBuffer::Direction dir) {
  switch (dir) {
    case Camera3StreamBuffer::Direction::kInput:
      return perfetto::StaticString("input");
    case Camera3StreamBuffer::Direction::kOutput:
      return perfetto::StaticString("output");
    case Camera3StreamBuffer::Direction::kInvalidDirection:
      return perfetto::StaticString("unknown");
  }
}

perfetto::StaticString GetBufferEventStr(Camera3StreamBuffer::Type type) {
  switch (type) {
    case Camera3StreamBuffer::Type::kRequest:
      return perfetto::StaticString("Request Buffer");
    case Camera3StreamBuffer::Type::kResult:
      return perfetto::StaticString("Result Buffer");
    case Camera3StreamBuffer::Type::kInvalidType:
      return perfetto::StaticString("Unknown Buffer");
  }
}

}  // namespace

Rect<uint32_t> GetCenteringFullCrop(Size size,
                                    uint32_t aspect_ratio_x,
                                    uint32_t aspect_ratio_y) {
  uint32_t crop_width = size.width;
  uint32_t crop_height = size.height;
  if (size.width * aspect_ratio_y >= size.height * aspect_ratio_x) {
    crop_width = size.height * aspect_ratio_x / aspect_ratio_y;
  } else {
    crop_height = size.width * aspect_ratio_y / aspect_ratio_x;
  }
  uint32_t dx = (size.width - crop_width) / 2;
  uint32_t dy = (size.height - crop_height) / 2;
  return Rect<uint32_t>(dx, dy, crop_width, crop_height);
}

bool AddListItemToMetadataTag(android::CameraMetadata* metadata,
                              uint32_t tag,
                              int32_t item) {
  camera_metadata_entry_t entry = metadata->find(tag);
  if (entry.count == 0) {
    const int32_t data[] = {item};
    return metadata->update(tag, data, 1) == 0;
  }
  const int32_t* begin = entry.data.i32;
  const int32_t* end = entry.data.i32 + entry.count;
  if (std::find(begin, end, item) != end) {
    return true;
  }
  std::vector<int32_t> data(begin, end);
  data.push_back(item);
  return metadata->update(tag, data.data(), data.size()) == 0;
}

bool WaitOnAndClearReleaseFence(camera3_stream_buffer_t& buffer,
                                int timeout_ms) {
  if (buffer.release_fence == -1) {
    return true;
  }
  if (sync_wait(buffer.release_fence, timeout_ms) != 0) {
    return false;
  }
  close(buffer.release_fence);
  buffer.release_fence = -1;
  return true;
}

//
// Camera3StreamBuffer implementations.
//

// static
Camera3StreamBuffer Camera3StreamBuffer::MakeRequestInput(
    const camera3_stream_buffer_t& stream_buffer) {
  return Camera3StreamBuffer(stream_buffer, Camera3StreamBuffer::Type::kRequest,
                             Camera3StreamBuffer::Direction::kInput);
}

// static
Camera3StreamBuffer Camera3StreamBuffer::MakeRequestOutput(
    const camera3_stream_buffer_t& stream_buffer) {
  return Camera3StreamBuffer(stream_buffer, Camera3StreamBuffer::Type::kRequest,
                             Camera3StreamBuffer::Direction::kOutput);
}

// static
Camera3StreamBuffer Camera3StreamBuffer::MakeResultInput(
    const camera3_stream_buffer_t& stream_buffer) {
  return Camera3StreamBuffer(stream_buffer, Camera3StreamBuffer::Type::kResult,
                             Camera3StreamBuffer::Direction::kInput);
}

// static
Camera3StreamBuffer Camera3StreamBuffer::MakeResultOutput(
    const camera3_stream_buffer_t& stream_buffer) {
  return Camera3StreamBuffer(stream_buffer, Camera3StreamBuffer::Type::kResult,
                             Camera3StreamBuffer::Direction::kOutput);
}

Camera3StreamBuffer::~Camera3StreamBuffer() {
  Invalidate();
}

Camera3StreamBuffer::Camera3StreamBuffer(Camera3StreamBuffer&& other) {
  *this = std::move(other);
}

Camera3StreamBuffer& Camera3StreamBuffer::operator=(
    Camera3StreamBuffer&& other) {
  if (this != &other) {
    Invalidate();
    type_ = other.type_;
    dir_ = other.dir_;
    raw_buffer_ = other.raw_buffer_;
    lock_container_ = other.lock_container_;
    trace_started_ = other.trace_started_;

    other.type_ = Type::kInvalidType;
    other.dir_ = Direction::kInvalidDirection;
    other.raw_buffer_ = kInvalidRawBuffer;
    other.lock_container_ = nullptr;
    other.trace_started_ = false;
  }
  return *this;
}

void Camera3StreamBuffer::StartTracing(int frame_number) {
  if (!is_valid() || trace_started_) {
    return;
  }
  TRACE_COMMON_EVENT("AttachBuffer", perfetto::Flow::ProcessScoped(flow_id()));
  TRACE_COMMON_BEGIN(
      GetBufferEventStr(type_),
      perfetto::Track(reinterpret_cast<uintptr_t>(*raw_buffer_.buffer)),
      "frame_number", frame_number, "direction", GetBufferDirectionStr(dir_),
      "stream", reinterpret_cast<uintptr_t>(raw_buffer_.stream), "width",
      raw_buffer_.stream->width, "height", raw_buffer_.stream->height, "format",
      raw_buffer_.stream->format);
  trace_started_ = true;
}

void Camera3StreamBuffer::EndTracing() {
  if (!is_valid() || !trace_started_) {
    return;
  }
  TRACE_COMMON_EVENT("DetachBuffer",
                     perfetto::TerminatingFlow::ProcessScoped(flow_id()));
  TRACE_COMMON_END(
      perfetto::Track(reinterpret_cast<uintptr_t>(*raw_buffer_.buffer)));
  trace_started_ = false;
}

void Camera3StreamBuffer::LockAndFill(camera3_stream_buffer_t* container) {
  CHECK_EQ(lock_container_, nullptr);
  CHECK(container);
  *container = raw_buffer_;
  lock_container_ = container;
}

void Camera3StreamBuffer::Unlock() {
  CHECK(lock_container_);
  raw_buffer_ = *lock_container_;
  lock_container_ = nullptr;
}

Camera3StreamBuffer::Camera3StreamBuffer(
    const camera3_stream_buffer_t& stream_buf, Type type, Direction dir)
    : raw_buffer_(stream_buf), type_(type), dir_(dir) {
  if (!is_valid()) {
    return;
  }

  // Some camera HAL may use their own storage to hold |buffer_handle_t*|s in
  // the capture results and it doesn't out-live the whole result callback
  // sequence. Fix them to our maintained storage so we can pass on the buffer
  // object safely.
  auto* handle = camera_buffer_handle_t::FromBufferHandle(*raw_buffer_.buffer);
  CHECK(handle);
  raw_buffer_.buffer = const_cast<buffer_handle_t*>(&handle->self);
}

void Camera3StreamBuffer::Invalidate() {
  EndTracing();
  raw_buffer_ = kInvalidRawBuffer;
  type_ = Type::kInvalidType;
  dir_ = Direction::kInvalidDirection;
}

//
// Camera3StreamConfiguration implementations.
//

Camera3StreamConfiguration::Camera3StreamConfiguration(
    const camera3_stream_configuration_t& stream_list)
    : streams_(stream_list.streams,
               stream_list.streams + stream_list.num_streams),
      operation_mode_(stream_list.operation_mode),
      session_parameters_(stream_list.session_parameters) {}

base::span<camera3_stream_t* const> Camera3StreamConfiguration::GetStreams()
    const {
  return {streams_.data(), streams_.size()};
}

bool Camera3StreamConfiguration::SetStreams(
    base::span<camera3_stream_t* const> streams) {
  if (IsLocked()) {
    LOGF(ERROR) << "Cannot set streams when locked";
    return false;
  }
  streams_.clear();
  streams_.resize(streams.size());
  std::copy(streams.begin(), streams.end(), streams_.begin());
  return true;
}

bool Camera3StreamConfiguration::AppendStream(camera3_stream_t* stream) {
  if (IsLocked()) {
    LOGF(ERROR) << "Cannot append streams when locked";
    return false;
  }
  streams_.push_back(stream);
  return true;
}

bool Camera3StreamConfiguration::RemoveStream(const camera3_stream_t* stream) {
  if (IsLocked()) {
    LOGF(ERROR) << "Cannot remove streams when locked";
    return false;
  }
  auto it = std::find(streams_.begin(), streams_.end(), stream);
  if (it == streams_.end()) {
    LOGF(ERROR) << "Cannot find the stream to remove";
    return false;
  }
  streams_.erase(it);
  return true;
}

camera3_stream_configuration_t* Camera3StreamConfiguration::Lock() {
  CHECK(!IsLocked());
  raw_configuration_ = camera3_stream_configuration_t{
      .num_streams = static_cast<uint32_t>(streams_.size()),
      .streams = streams_.data(),
      .operation_mode = operation_mode_,
      .session_parameters = session_parameters_};
  return &raw_configuration_.value();
}

std::string Camera3StreamConfiguration::ToJsonString() const {
  base::Value::List val;
  for (const auto* stream : GetStreams()) {
    val.Append(ToValueDict(stream));
  }
  std::string json_string;
  if (!base::JSONWriter::WriteWithOptions(
          val, base::JSONWriter::OPTIONS_PRETTY_PRINT, &json_string)) {
    LOGF(ERROR) << "Cannot convert stream configurations to JSON string";
    return std::string();
  }
  return json_string;
}

void Camera3StreamConfiguration::PopulateEventAnnotation(
    perfetto::EventContext& ctx) const {
  ctx.AddDebugAnnotation("stream_configurations", ToJsonString());
}

void Camera3StreamConfiguration::Unlock() {
  raw_configuration_.reset();
}

bool Camera3StreamConfiguration::IsLocked() const {
  return raw_configuration_.has_value();
}

//
// Camera3CaptureDescriptor implementations.
//

Camera3CaptureDescriptor::Camera3CaptureDescriptor(
    const camera3_capture_request_t& request)
    : type_(Type::kCaptureRequest),
      frame_number_(request.frame_number),
      num_physcam_metadata_(request.num_physcam_settings),
      physcam_ids_(request.physcam_id),
      physcam_metadata_(request.physcam_settings) {
  if (request.settings != nullptr) {
    metadata_.acquire(clone_camera_metadata(request.settings));
  }
  if (request.input_buffer) {
    SetInputBuffer(
        Camera3StreamBuffer::MakeRequestInput(*request.input_buffer));
  }
  if (request.num_output_buffers > 0) {
    output_buffers_.reserve(request.num_output_buffers);
    for (int i = 0; i < request.num_output_buffers; ++i) {
      AppendOutputBuffer(Camera3StreamBuffer::MakeRequestOutput(
          *(request.output_buffers + i)));
    }
  }
}

Camera3CaptureDescriptor::Camera3CaptureDescriptor(
    const camera3_capture_result_t& result)
    : type_(Type::kCaptureResult),
      frame_number_(result.frame_number),
      partial_result_(result.partial_result),
      num_physcam_metadata_(result.num_physcam_metadata),
      physcam_ids_(result.physcam_ids),
      physcam_metadata_(result.physcam_metadata) {
  if (result.result != nullptr) {
    metadata_.acquire(clone_camera_metadata(result.result));
  }
  if (result.input_buffer) {
    SetInputBuffer(Camera3StreamBuffer::MakeResultInput(*result.input_buffer));
  }
  if (result.num_output_buffers > 0) {
    output_buffers_.reserve(result.num_output_buffers);
    for (int i = 0; i < result.num_output_buffers; ++i) {
      AppendOutputBuffer(
          Camera3StreamBuffer::MakeResultOutput(*(result.output_buffers + i)));
    }
  }
}

Camera3CaptureDescriptor::~Camera3CaptureDescriptor() {
  Unlock();
  Invalidate();
}

Camera3CaptureDescriptor::Camera3CaptureDescriptor(
    Camera3CaptureDescriptor&& other) {
  *this = std::move(other);
}

Camera3CaptureDescriptor& Camera3CaptureDescriptor::operator=(
    Camera3CaptureDescriptor&& other) {
  if (this != &other) {
    Invalidate();

    type_ = other.type_;
    frame_number_ = other.frame_number_;

    // metadata_.isEmpty() doesn't differentiate a nullptr metadata from a
    // valid metadata with zero entry count. We want to move the latter while
    // avoid copying the former to avoid the log spams in metadata_.acquire().
    camera_metadata_t* m = other.metadata_.release();
    if (m) {
      metadata_.acquire(m);
    }

    input_buffer_ = std::move(other.input_buffer_);
    output_buffers_ = std::move(other.output_buffers_);
    partial_result_ = other.partial_result_;
    num_physcam_metadata_ = other.num_physcam_metadata_;
    physcam_ids_ = other.physcam_ids_;
    physcam_metadata_ = other.physcam_metadata_;
    feature_metadata_ = std::move(other.feature_metadata_);
    raw_descriptor_ = std::move(other.raw_descriptor_);

    other.Invalidate();
  }
  return *this;
}

template <>
base::span<const uint8_t> Camera3CaptureDescriptor::GetMetadata(
    uint32_t tag) const {
  camera_metadata_ro_entry_t entry = metadata_.find(tag);
  if (entry.count == 0) {
    return base::span<const uint8_t>();
  }
  return base::span<const uint8_t>(entry.data.u8, entry.count);
}

template <>
base::span<const int32_t> Camera3CaptureDescriptor::GetMetadata(
    uint32_t tag) const {
  camera_metadata_ro_entry_t entry = metadata_.find(tag);
  if (entry.count == 0) {
    return base::span<const int32_t>();
  }
  return base::span<const int32_t>(entry.data.i32, entry.count);
}

template <>
base::span<const float> Camera3CaptureDescriptor::GetMetadata(
    uint32_t tag) const {
  camera_metadata_ro_entry_t entry = metadata_.find(tag);
  if (entry.count == 0) {
    return base::span<const float>();
  }
  return base::span<const float>(entry.data.f, entry.count);
}

template <>
base::span<const double> Camera3CaptureDescriptor::GetMetadata(
    uint32_t tag) const {
  camera_metadata_ro_entry_t entry = metadata_.find(tag);
  if (entry.count == 0) {
    return base::span<const double>();
  }
  return base::span<const double>(entry.data.d, entry.count);
}

template <>
base::span<const int64_t> Camera3CaptureDescriptor::GetMetadata(
    uint32_t tag) const {
  camera_metadata_ro_entry_t entry = metadata_.find(tag);
  if (entry.count == 0) {
    return base::span<const int64_t>();
  }
  return base::span<const int64_t>(entry.data.i64, entry.count);
}

template <>
base::span<const camera_metadata_rational_t>
Camera3CaptureDescriptor::GetMetadata(uint32_t tag) const {
  camera_metadata_ro_entry_t entry = metadata_.find(tag);
  if (entry.count == 0) {
    return base::span<const camera_metadata_rational_t>();
  }
  return base::span<const camera_metadata_rational_t>(entry.data.r,
                                                      entry.count);
}

bool Camera3CaptureDescriptor::AppendMetadata(
    const camera_metadata_t* metadata) {
  if (IsLocked()) {
    LOGF(ERROR) << "Cannot update metadata when locked";
    return false;
  }
  auto ret = metadata_.append(metadata);
  return ret == 0;
}

bool Camera3CaptureDescriptor::DeleteMetadata(uint32_t tag) {
  if (IsLocked()) {
    LOGF(ERROR) << "Cannot delete metadata when locked";
    return false;
  }
  auto ret = metadata_.erase(tag);
  return ret == 0;
}

bool Camera3CaptureDescriptor::SetMetadata(const camera_metadata_t* metadata) {
  if (IsLocked()) {
    LOGF(ERROR) << "Cannot set metadata when locked";
    return false;
  }
  if (get_camera_metadata_entry_count(metadata) == 0) {
    LOGF(ERROR) << "The input metadata is empty";
    return false;
  }
  metadata_.acquire(clone_camera_metadata(metadata));
  return !metadata_.isEmpty();
}

bool Camera3CaptureDescriptor::HasMetadata(uint32_t tag) const {
  return metadata_.exists(tag);
}

const Camera3StreamBuffer* Camera3CaptureDescriptor::GetInputBuffer() const {
  if (input_buffer_) {
    return &input_buffer_.value();
  }
  return nullptr;
}

std::optional<Camera3StreamBuffer>
Camera3CaptureDescriptor::AcquireInputBuffer() {
  std::optional<Camera3StreamBuffer> ret = std::move(input_buffer_);
  input_buffer_.reset();
  return ret;
}

void Camera3CaptureDescriptor::SetInputBuffer(
    Camera3StreamBuffer input_buffer) {
  input_buffer.StartTracing(frame_number_);
  input_buffer_ = std::move(input_buffer);
}

base::span<const Camera3StreamBuffer>
Camera3CaptureDescriptor::GetOutputBuffers() const {
  return {output_buffers_.data(), output_buffers_.size()};
}

base::span<Camera3StreamBuffer>
Camera3CaptureDescriptor::GetMutableOutputBuffers() {
  return {output_buffers_.data(), output_buffers_.size()};
}

std::vector<Camera3StreamBuffer>
Camera3CaptureDescriptor::AcquireOutputBuffers() {
  return std::move(output_buffers_);
}

void Camera3CaptureDescriptor::SetOutputBuffers(
    std::vector<Camera3StreamBuffer> output_buffers) {
  for (auto& b : output_buffers) {
    b.StartTracing(frame_number_);
  }
  output_buffers_ = std::move(output_buffers);
}

void Camera3CaptureDescriptor::AppendOutputBuffer(Camera3StreamBuffer buffer) {
  buffer.StartTracing(frame_number_);
  output_buffers_.push_back(std::move(buffer));
}

camera3_capture_request* Camera3CaptureDescriptor::LockForRequest() {
  if (type_ != Type::kCaptureRequest) {
    LOGF(ERROR) << "Cannot lock for capture request";
    return nullptr;
  }
  CHECK(!IsLocked());
  raw_descriptor_ = RawDescriptor();
  raw_descriptor_->raw_request.frame_number = frame_number_;
  raw_descriptor_->raw_request.settings = metadata_.getAndLock();

  raw_descriptor_->raw_request.input_buffer =
      input_buffer_ ? &input_buffer_->mutable_raw_buffer() : nullptr;

  raw_descriptor_->raw_request.num_output_buffers = output_buffers_.size();
  raw_output_buffers_.resize(output_buffers_.size());
  for (int i = 0; i < output_buffers_.size(); ++i) {
    output_buffers_[i].LockAndFill(&raw_output_buffers_[i]);
  }
  raw_descriptor_->raw_request.output_buffers = raw_output_buffers_.data();

  raw_descriptor_->raw_request.num_physcam_settings = num_physcam_metadata_;
  raw_descriptor_->raw_request.physcam_id = physcam_ids_;
  raw_descriptor_->raw_request.physcam_settings = physcam_metadata_;

  return &raw_descriptor_->raw_request;
}

camera3_capture_result_t* Camera3CaptureDescriptor::LockForResult() {
  if (type_ != Type::kCaptureResult) {
    LOGF(ERROR) << "Cannot lock for capture result";
    return nullptr;
  }
  CHECK(!IsLocked());
  raw_descriptor_ = RawDescriptor();
  raw_descriptor_->raw_result.frame_number = frame_number_;
  raw_descriptor_->raw_result.result = metadata_.getAndLock();

  raw_descriptor_->raw_result.num_output_buffers = output_buffers_.size();
  raw_output_buffers_.resize(output_buffers_.size());
  for (int i = 0; i < output_buffers_.size(); ++i) {
    output_buffers_[i].LockAndFill(&raw_output_buffers_[i]);
  }
  raw_descriptor_->raw_result.output_buffers = raw_output_buffers_.data();

  raw_descriptor_->raw_result.input_buffer =
      input_buffer_ ? &input_buffer_->mutable_raw_buffer() : nullptr;

  raw_descriptor_->raw_result.partial_result = partial_result_;
  raw_descriptor_->raw_result.num_physcam_metadata = num_physcam_metadata_;
  raw_descriptor_->raw_result.physcam_ids = physcam_ids_;
  raw_descriptor_->raw_result.physcam_metadata = physcam_metadata_;

  return &raw_descriptor_->raw_result;
}

camera3_capture_request_t* Camera3CaptureDescriptor::GetLockedRequest() {
  if (type_ != Type::kCaptureRequest) {
    LOGF(ERROR) << "Cannot lock for capture request";
    return nullptr;
  }
  if (!IsLocked()) {
    return nullptr;
  }
  return &raw_descriptor_->raw_request;
}

camera3_capture_result_t* Camera3CaptureDescriptor::GetLockedResult() {
  if (type_ != Type::kCaptureResult) {
    LOGF(ERROR) << "Cannot lock for capture result";
    return nullptr;
  }
  if (!IsLocked()) {
    return nullptr;
  }
  return &raw_descriptor_->raw_result;
}

void Camera3CaptureDescriptor::Unlock() {
  if (!is_valid() || !IsLocked()) {
    return;
  }
  switch (type_) {
    case Type::kCaptureRequest:
      metadata_.unlock(raw_descriptor_->raw_request.settings);
      break;
    case Type::kCaptureResult:
      metadata_.unlock(raw_descriptor_->raw_result.result);
      break;
    case Type::kInvalidType:
      NOTREACHED() << "Cannot unlock invalid descriptor";
  }
  for (auto& b : output_buffers_) {
    b.Unlock();
  }
  raw_descriptor_.reset();
}

std::string Camera3CaptureDescriptor::ToJsonString() const {
  if (!is_valid()) {
    return std::string();
  }

  base::Value::Dict val;
  val.Set("capture_type",
          type_ == Type::kCaptureRequest ? "Request" : "Result");
  val.Set("frame_number", base::checked_cast<int>(frame_number_));
  if (input_buffer_) {
    val.Set("input_buffer", ToValueDict(input_buffer_.value()));
  }

  base::Value::List out_bufs;
  for (const auto& b : GetOutputBuffers()) {
    out_bufs.Append(ToValueDict(b));
  }
  val.Set("output_buffers", std::move(out_bufs));

  if (type_ == Type::kCaptureResult) {
    val.Set("partial_result", base::checked_cast<int>(partial_result_));
  }

  std::string json_string;
  if (!base::JSONWriter::WriteWithOptions(
          val, base::JSONWriter::OPTIONS_PRETTY_PRINT, &json_string)) {
    LOGF(ERROR) << "Cannot convert capture descriptor to JSON string";
    return std::string();
  }
  return json_string;
}

void Camera3CaptureDescriptor::PopulateEventAnnotation(
    perfetto::EventContext& ctx) const {
  if (!is_valid()) {
    return;
  }

  ctx.AddDebugAnnotation("capture_type",
                         type_ == Type::kCaptureRequest ? "Request" : "Result");
  ctx.AddDebugAnnotation("frame_number",
                         base::checked_cast<int>(frame_number_));

  std::string input_buffer;
  if (input_buffer_) {
    perfetto::Flow::ProcessScoped(input_buffer_->flow_id())(ctx);
    if (base::JSONWriter::WriteWithOptions(
            ToValueDict(input_buffer_.value()),
            base::JSONWriter::OPTIONS_PRETTY_PRINT, &input_buffer)) {
      ctx.AddDebugAnnotation("input_buffer", input_buffer);
    }
  }

  base::Value::List out_bufs;
  for (const auto& b : GetOutputBuffers()) {
    perfetto::Flow::ProcessScoped(b.flow_id())(ctx);
    out_bufs.Append(ToValueDict(b));
  }
  std::string output_buffers;
  if (base::JSONWriter::WriteWithOptions(
          out_bufs, base::JSONWriter::OPTIONS_PRETTY_PRINT, &output_buffers)) {
    ctx.AddDebugAnnotation("output_buffers", output_buffers);
  }

  if (type_ == Type::kCaptureResult) {
    ctx.AddDebugAnnotation("partial_result",
                           base::checked_cast<int>(partial_result_));
  }
}

void Camera3CaptureDescriptor::Invalidate() {
  type_ = Type::kInvalidType;
  frame_number_ = 0;
  metadata_.clear();
  input_buffer_.reset();
  output_buffers_.clear();
  partial_result_ = 0;
  num_physcam_metadata_ = 0;
  physcam_ids_ = nullptr;
  physcam_metadata_ = nullptr;
  feature_metadata_ = {};
  raw_descriptor_.reset();
}

bool Camera3CaptureDescriptor::IsLocked() const {
  return raw_descriptor_.has_value();
}

}  // namespace cros

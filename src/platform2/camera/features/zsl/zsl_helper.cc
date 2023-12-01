/*
 * Copyright 2019 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "features/zsl/zsl_helper.h"

#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <functional>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/check_op.h>
#include <base/functional/bind.h>
#include <base/numerics/safe_conversions.h>
#include <camera/camera_metadata.h>
#include <sync/sync.h>
#include <system/camera_metadata.h>

#include "common/camera_hal3_helpers.h"
#include "cros-camera/camera_metadata_utils.h"
#include "cros-camera/common.h"
#include "cros-camera/constants.h"
#include "cros-camera/utils/camera_config.h"

namespace cros {

namespace {

static constexpr int64_t kOverrideCurrentTimestampNotSet = -1;

bool IsInputStream(camera3_stream_t* stream) {
  return stream->stream_type == CAMERA3_STREAM_INPUT ||
         stream->stream_type == CAMERA3_STREAM_BIDIRECTIONAL;
}

bool IsOutputStream(camera3_stream_t* stream) {
  return stream->stream_type == CAMERA3_STREAM_OUTPUT ||
         stream->stream_type == CAMERA3_STREAM_BIDIRECTIONAL;
}

int64_t GetTimestamp(const android::CameraMetadata& android_metadata) {
  camera_metadata_ro_entry_t entry;
  if (android_metadata.exists(ANDROID_SENSOR_TIMESTAMP)) {
    entry = android_metadata.find(ANDROID_SENSOR_TIMESTAMP);
    return entry.data.i64[0];
  }
  LOGF(ERROR) << "Cannot find sensor timestamp in ZSL buffer";
  return static_cast<int64_t>(-1);
}

// Checks the static metadata of the camera device to see if we can attempt to
// enable our in-house ZSL solution for it. It checks whether or not the
// device already supports ZSL, and checks for private processing capability
// if not.
bool CanEnableZsl(const camera_metadata_t* metadata) {
  // Determine if it's possible for us to enable our in-house ZSL solution. Note
  // that we may end up not enabling it in situations where we cannot allocate
  // sufficient private buffers or the camera HAL client's stream configuration
  // wouldn't allow us to set up the streams we need.
  base::span<const uint8_t> available_caps = GetRoMetadataAsSpan<uint8_t>(
      metadata, ANDROID_REQUEST_AVAILABLE_CAPABILITIES);
  if (available_caps.empty()) {
    return false;
  }
  if (std::find(available_caps.begin(), available_caps.end(),
                ANDROID_REQUEST_AVAILABLE_CAPABILITIES_PRIVATE_REPROCESSING) ==
      available_caps.end()) {
    return false;
  }

  // See if the camera HAL already supports ZSL.
  base::span<const int32_t> req_keys = GetRoMetadataAsSpan<int32_t>(
      metadata, ANDROID_REQUEST_AVAILABLE_REQUEST_KEYS);
  if (req_keys.empty()) {
    return false;
  }
  if (std::find(req_keys.begin(), req_keys.end(), ANDROID_CONTROL_ENABLE_ZSL) !=
      req_keys.end()) {
    LOGF(INFO) << "Device supports vendor-provided ZSL";
    return false;
  }

  return true;
}

}  // namespace

ZslBuffer::ZslBuffer()
    : metadata_ready(false), buffer_ready(false), selected(false) {}
ZslBuffer::ZslBuffer(uint32_t frame_number, camera3_stream_buffer_t buffer)
    : frame_number(frame_number),
      buffer(std::move(buffer)),
      metadata_ready(false),
      buffer_ready(false),
      selected(false) {}

void ZslBuffer::AttachToRequest(Camera3CaptureDescriptor* capture_request) {
  capture_request->AppendOutputBuffer(
      Camera3StreamBuffer::MakeRequestOutput(buffer));
}

ZslBufferManager::ZslBufferManager()
    : initialized_(false), buffer_manager_(nullptr) {}

ZslBufferManager::~ZslBufferManager() {
  Reset();
}

bool ZslBufferManager::Initialize(size_t pool_size,
                                  const camera3_stream_t* output_stream) {
  DCHECK(buffer_pool_.empty());

  // |buffer_manager_| could be set by SetCameraBufferManagerForTesting().
  if (!buffer_manager_) {
    buffer_manager_ = CameraBufferManager::GetInstance();
  }

  bool success = true;
  output_stream_ = output_stream;
  {
    base::AutoLock l(buffer_pool_lock_);
    buffer_pool_.reserve(pool_size);
    for (size_t i = 0; i < pool_size; ++i) {
      uint32_t stride;
      buffer_handle_t buffer;
      if (buffer_manager_->Allocate(
              output_stream_->width, output_stream_->height,
              ZslHelper::kZslPixelFormat,
              GRALLOC_USAGE_HW_CAMERA_ZSL | GRALLOC_USAGE_SW_READ_OFTEN |
                  GRALLOC_USAGE_SW_WRITE_OFTEN,
              &buffer, &stride) != 0) {
        LOGF(ERROR) << "Failed to allocate buffer";
        success = false;
        break;
      }
      buffer_pool_.push_back(buffer);
      free_buffers_.push(&buffer_pool_.back());
      buffer_to_buffer_pointer_map_[buffer] = &buffer_pool_.back();
    }
  }

  if (!success) {
    Reset();
    return false;
  }
  initialized_ = true;
  return true;
}

buffer_handle_t* ZslBufferManager::GetBuffer() {
  base::AutoLock buffer_pool_lock(buffer_pool_lock_);
  if (!initialized_) {
    LOGF(ERROR) << "ZSL buffer manager has not been initialized";
    return nullptr;
  }
  if (free_buffers_.empty()) {
    LOGF(ERROR) << "No more buffer left in the pool. This shouldn't happen";
    return nullptr;
  }

  buffer_handle_t* buffer = free_buffers_.front();
  free_buffers_.pop();
  return buffer;
}

bool ZslBufferManager::ReleaseBuffer(buffer_handle_t buffer_to_release) {
  base::AutoLock buffer_pool_lock(buffer_pool_lock_);
  if (!initialized_) {
    LOGF(ERROR) << "ZSL buffer manager has not been initialized";
    return false;
  }
  auto it = buffer_to_buffer_pointer_map_.find(buffer_to_release);
  if (it == buffer_to_buffer_pointer_map_.end()) {
    LOGF(ERROR) << "The released buffer doesn't belong to ZSL buffer manager";
    return false;
  }
  free_buffers_.push(it->second);
  return true;
}

void ZslBufferManager::Reset() {
  initialized_ = false;
  base::AutoLock l(buffer_pool_lock_);
  for (auto& buffer : buffer_pool_) {
    buffer_manager_->Free(buffer);
  }
  buffer_pool_.clear();
  free_buffers_ = {};
  buffer_to_buffer_pointer_map_.clear();
}

void ZslBufferManager::SetCameraBufferManagerForTesting(
    CameraBufferManager* buffer_manager) {
  buffer_manager_ = buffer_manager;
}

ZslHelper::ZslHelper(const camera_metadata_t* static_info)
    : zsl_buffer_manager_(new ZslBufferManager),
      fence_sync_thread_("FenceSyncThread"),
      override_current_timestamp_for_testing_(kOverrideCurrentTimestampNotSet) {
  if (!IsCapabilitySupported(
          static_info,
          ANDROID_REQUEST_AVAILABLE_CAPABILITIES_PRIVATE_REPROCESSING)) {
    LOGF(INFO) << "Private reprocessing not supported, ZSL won't be enabled";
    return;
  }
  uint32_t bi_width, bi_height;
  if (!SelectZslStreamSize(static_info, &bi_width, &bi_height,
                           &bi_stream_min_frame_duration_)) {
    LOGF(ERROR) << "Failed to select stream sizes for ZSL.";
    return;
  }
  LOGF(INFO) << "Selected ZSL stream size = " << bi_width << "x" << bi_height;
  // Create ZSL streams
  bi_stream_ = std::make_unique<camera3_stream_t>();
  bi_stream_->stream_type = CAMERA3_STREAM_BIDIRECTIONAL;
  bi_stream_->width = bi_width;
  bi_stream_->height = bi_height;
  bi_stream_->format = kZslPixelFormat;

  if (!fence_sync_thread_.Start()) {
    LOGF(ERROR) << "Fence sync thread failed to start";
  }
  partial_result_count_ = [&]() {
    camera_metadata_ro_entry entry;
    if (find_camera_metadata_ro_entry(
            static_info, ANDROID_REQUEST_PARTIAL_RESULT_COUNT, &entry) != 0) {
      return 1;
    }
    return entry.data.i32[0];
  }();
  max_num_input_streams_ = [&]() {
    camera_metadata_ro_entry_t entry;
    if (find_camera_metadata_ro_entry(
            static_info, ANDROID_REQUEST_MAX_NUM_INPUT_STREAMS, &entry) != 0) {
      LOGF(ERROR) << "Failed to get maximum number of input streams.";
      return 0;
    }
    return entry.data.i32[0];
  }();
  timestamp_source_ = [&]() {
    camera_metadata_ro_entry_t entry;
    if (find_camera_metadata_ro_entry(
            static_info, ANDROID_SENSOR_INFO_TIMESTAMP_SOURCE, &entry) != 0) {
      LOGF(ERROR) << "Failed to get timestamp source. Assuming it's UNKNOWN.";
      return ANDROID_SENSOR_INFO_TIMESTAMP_SOURCE_UNKNOWN;
    }
    return static_cast<
        camera_metadata_enum_android_sensor_info_timestamp_source_t>(
        entry.data.u8[0]);
  }();

  auto camera_config =
      cros::CameraConfig::Create(cros::constants::kCrosCameraConfigPathString);
  // We're casting an int to int64_t here. Make sure the configured time doesn't
  // overflow (roughly 2.1s).
  zsl_lookback_ns_ = base::strict_cast<int64_t>(camera_config->GetInteger(
      cros::constants::kCrosZslLookback,
      base::checked_cast<int>(kZslDefaultLookbackNs)));
  LOGF(INFO) << "Configured ZSL lookback time = " << zsl_lookback_ns_;
}

ZslHelper::~ZslHelper() {
  fence_sync_thread_.Stop();
}

bool ZslHelper::AttachZslStream(Camera3StreamConfiguration* stream_config) {
  if (!CanEnableZsl(stream_config->GetStreams())) {
    return false;
  }

  stream_config->AppendStream(bi_stream_.get());

  if (VLOG_IS_ON(1)) {
    VLOGF(1) << "Attached ZSL streams. The list of streams after attaching:";
    for (const auto* s : stream_config->GetStreams()) {
      VLOGF(1) << ", type = " << s->stream_type << ", size = " << s->width
               << "x" << s->height << ", format = " << s->format;
    }
  }

  return true;
}

bool ZslHelper::Initialize(Camera3StreamConfiguration* stream_config) {
  auto GetStillCaptureMaxBuffers = [&]() {
    uint32_t max_buffers = 0;
    for (auto* stream : stream_config->GetStreams()) {
      if (!IsOutputStream(stream)) {
        continue;
      }
      // If our private usage flag is specified, we know only this stream
      // will be used for ZSL capture.
      if (stream->usage & cros::GRALLOC_USAGE_STILL_CAPTURE) {
        return stream->max_buffers;
      } else if (stream->format == HAL_PIXEL_FORMAT_BLOB) {
        max_buffers += stream->max_buffers;
      }
    }
    return max_buffers;
  };

  base::AutoLock ring_buffer_lock(ring_buffer_lock_);

  // First, clear all the buffers and states.
  ring_buffer_.clear();
  zsl_buffer_manager_->Reset();

  // Determine at most how many buffers would be selected for private
  // reprocessing simultaneously, and remove the ZSL stream we attached along
  // the way.
  bi_stream_max_buffers_ = 0;
  base::span<camera3_stream_t* const> streams = stream_config->GetStreams();
  std::vector<camera3_stream_t*> modified_streams;
  for (auto* s : streams) {
    if (s == bi_stream_.get()) {
      bi_stream_max_buffers_ = s->max_buffers;
    } else {
      modified_streams.push_back(s);
    }
  }
  stream_config->SetStreams(modified_streams);
  if (bi_stream_max_buffers_ == 0) {
    LOGF(ERROR) << "Failed to acquire max_buffers for the private stream";
    return false;
  }
  VLOGF(1) << "Max buffers for private stream = " << bi_stream_max_buffers_;

  // Determine at most how many still capture buffers would be in-flight.
  uint32_t still_max_buffers = GetStillCaptureMaxBuffers();
  if (still_max_buffers == 0) {
    LOGF(ERROR) << "Failed to acquire max_buffers for the still capture stream";
    return false;
  }
  VLOGF(1) << "Max buffers for still capture streams = " << still_max_buffers;

  // We look back at most
  // ceil(|zsl_lookback_ns_| / |bi_stream_min_frame_duration_| frames, and there
  // will be at most |bi_stream_max_buffers_| being processed. We also need to
  // have |still_max_buffers| additional buffers in the buffer pool.
  if (!zsl_buffer_manager_->Initialize(
          static_cast<size_t>(std::ceil(static_cast<double>(zsl_lookback_ns_) /
                                        bi_stream_min_frame_duration_)) +
              bi_stream_max_buffers_ + still_max_buffers,
          bi_stream_.get())) {
    LOGF(ERROR) << "Failed to initialize ZSL buffer manager";
    return false;
  }

  return true;
}

bool ZslHelper::CanEnableZsl(base::span<camera3_stream_t* const> streams) {
  size_t num_input_streams = 0;
  bool has_still_capture_output_stream = false;
  bool has_zsl_output_stream = false;
  for (auto* stream : streams) {
    if (IsInputStream(stream)) {
      num_input_streams++;
    }
    if (IsOutputStream(stream) &&
        (stream->format == HAL_PIXEL_FORMAT_BLOB ||
         (stream->usage & GRALLOC_USAGE_STILL_CAPTURE))) {
      has_still_capture_output_stream = true;
    }
    if (IsOutputStream(stream) &&
        (stream->usage & GRALLOC_USAGE_HW_CAMERA_ZSL) ==
            GRALLOC_USAGE_HW_CAMERA_ZSL) {
      has_zsl_output_stream = true;
    }
  }
  return num_input_streams < max_num_input_streams_  // Has room for an extra
                                                     // input stream for ZSL.
         && has_still_capture_output_stream  // Has a stream for still capture.
         && !has_zsl_output_stream;  // HAL doesn't support multiple raw output
                                     // streams.
}

bool ZslHelper::IsZslRequested(const Camera3CaptureDescriptor* request) {
  bool enable_zsl = [&]() {
    base::span<const uint8_t> entry =
        request->GetMetadata<uint8_t>(ANDROID_CONTROL_ENABLE_ZSL);
    if (!entry.empty()) {
      return entry[0] == ANDROID_CONTROL_ENABLE_ZSL_TRUE;
    }
    return false;
  }();
  if (!enable_zsl) {
    return false;
  }
  // We can only enable ZSL when capture intent is also still capture.
  base::span<const uint8_t> entry =
      request->GetMetadata<uint8_t>(ANDROID_CONTROL_CAPTURE_INTENT);
  if (!entry.empty()) {
    return entry[0] == ANDROID_CONTROL_CAPTURE_INTENT_STILL_CAPTURE ||
           entry[0] == ANDROID_CONTROL_CAPTURE_INTENT_ZERO_SHUTTER_LAG;
  }
  return false;
}

bool ZslHelper::IsTransformedZslBuffer(const Camera3StreamBuffer& buffer) {
  return buffer.stream() == bi_stream_.get();
}

void ZslHelper::TryReleaseBuffer() {
  ring_buffer_lock_.AssertAcquired();
  // Check if the oldest buffer is already too old to be selected. In which
  // case, we can remove it from our ring buffer. If the buffer is not selected,
  // we release it back to the buffer pool. If the buffer is selected, we
  // release it when it returns from ProcessZslCaptureResult.
  if (ring_buffer_.empty()) {
    return;
  }
  const ZslBuffer& oldest_buffer = ring_buffer_.back();
  if (oldest_buffer.selected) {
    ring_buffer_.pop_back();
    return;
  }

  if (!oldest_buffer.metadata_ready) {
    return;
  }
  auto timestamp = GetTimestamp(oldest_buffer.metadata);
  DCHECK_NE(timestamp, -1);
  if (GetCurrentTimestamp() - timestamp <= zsl_lookback_ns_) {
    // Buffer is too new that we should keep it. This will happen for the
    // initial buffers.
    return;
  }
  if (!zsl_buffer_manager_->ReleaseBuffer(*oldest_buffer.buffer.buffer)) {
    LOGF(ERROR) << "Unable to release the oldest buffer";
    return;
  }
  ring_buffer_.pop_back();
}

bool ZslHelper::ProcessZslCaptureRequest(Camera3CaptureDescriptor* request,
                                         SelectionStrategy strategy) {
  if (request->has_input_buffer()) {
    return false;
  }
  bool transformed = false;
  if (IsZslRequested(request)) {
    transformed = TransformRequest(request, strategy);
    if (!transformed) {
      LOGF(ERROR) << "Failed to find a suitable ZSL buffer";
    }
  } else {
    AttachRequest(request);
  }
  return transformed;
}

void ZslHelper::AttachRequest(Camera3CaptureDescriptor* request) {
  base::AutoLock l(ring_buffer_lock_);
  TryReleaseBuffer();
  auto* buffer = zsl_buffer_manager_->GetBuffer();
  if (buffer == nullptr) {
    LOGF(ERROR) << "Failed to acquire a ZSL buffer";
    return;
  }
  // Attach our ZSL output buffer.
  camera3_stream_buffer_t stream_buffer = {
      .stream = bi_stream_.get(),
      .buffer = buffer,
      .status = CAMERA3_BUFFER_STATUS_OK,
      .acquire_fence = -1,
      .release_fence = -1,
  };

  ZslBuffer zsl_buffer(request->frame_number(), stream_buffer);
  zsl_buffer.AttachToRequest(request);
  ring_buffer_.push_front(std::move(zsl_buffer));
}

bool ZslHelper::TransformRequest(Camera3CaptureDescriptor* request,
                                 SelectionStrategy strategy) {
  base::AutoLock l(ring_buffer_lock_);

  const int32_t jpeg_orientation = [&]() {
    base::span<const int32_t> entry =
        request->GetMetadata<int32_t>(ANDROID_JPEG_ORIENTATION);
    if (entry.empty()) {
      return 0;
    }
    return entry[0];
  }();
  const std::vector<int32_t> jpeg_thumbnail_size = [&]() {
    base::span<const int32_t> entry =
        request->GetMetadata<int32_t>(ANDROID_JPEG_THUMBNAIL_SIZE);
    if (entry.empty()) {
      LOGF(ERROR) << "Failed to find JPEG thumbnail size, defaulting to [0, 0]";
      return std::vector<int32_t>{0, 0};
    }
    return std::vector<int32_t>{entry[0], entry[1]};
  }();

  // Select the best buffer.
  ZslBufferIterator selected_buffer_it = SelectZslBuffer(strategy);
  if (selected_buffer_it == ring_buffer_.end()) {
    LOGF(WARNING) << "Unable to find a suitable ZSL buffer. Request will not "
                     "be transformed.";
    return false;
  }

  LOGF(INFO) << "Transforming request into ZSL reprocessing request";
  selected_buffer_it->buffer.stream = bi_stream_.get();
  selected_buffer_it->buffer.acquire_fence = -1;
  selected_buffer_it->buffer.acquire_fence = -1;
  request->SetInputBuffer(
      Camera3StreamBuffer::MakeRequestInput(selected_buffer_it->buffer));

  // The result metadata for the RAW buffers come from the preview frames. We
  // need to add JPEG orientation back so that the resulting JPEG is of the
  // correct orientation.
  if (selected_buffer_it->metadata.update(ANDROID_JPEG_ORIENTATION,
                                          &jpeg_orientation, 1) != 0) {
    LOGF(ERROR) << "Failed to update JPEG_ORIENTATION";
  }
  if (selected_buffer_it->metadata.update(ANDROID_JPEG_THUMBNAIL_SIZE,
                                          jpeg_thumbnail_size.data(),
                                          jpeg_thumbnail_size.size()) != 0) {
    LOGF(ERROR) << "Failed to update JPEG_THUMBNAIL_SIZE";
  }
  request->SetMetadata(selected_buffer_it->metadata.getAndLock());
  return true;
}

void ZslHelper::ProcessZslCaptureResult(Camera3CaptureDescriptor* result,
                                        bool* is_input_transformed) {
  for (auto& buffer : result->AcquireOutputBuffers()) {
    if (buffer.stream() == bi_stream_.get()) {
      WaitAttachedFrame(result->frame_number(),
                        base::ScopedFD(buffer.take_release_fence()));
    } else {
      result->AppendOutputBuffer(std::move(buffer));
    }
  }

  const Camera3StreamBuffer* input_buffer = result->GetInputBuffer();
  if (input_buffer && IsTransformedZslBuffer(*input_buffer)) {
    *is_input_transformed = true;
    ReleaseStreamBuffer(result->AcquireInputBuffer());
  } else {
    *is_input_transformed = false;
  }

  base::AutoLock ring_buffer_lock(ring_buffer_lock_);
  auto it = std::find_if(ring_buffer_.begin(), ring_buffer_.end(),
                         [&](const ZslBuffer& buffer) {
                           return buffer.frame_number == result->frame_number();
                         });
  if (it == ring_buffer_.end()) {
    return;
  }

  if (result->partial_result() != 0) {  // Result has metadata. Merge it.
    const camera3_capture_result_t* locked_result = result->LockForResult();
    if (locked_result->result) {
      it->metadata.append(locked_result->result);
    } else {
      LOGF(ERROR) << "No result metadata although partial_result = "
                  << result->partial_result();
    }
    result->Unlock();
    if (result->partial_result() == partial_result_count_) {
      it->metadata_ready = true;
    }
  }
}

void ZslHelper::OnNotifyError(const camera3_error_msg_t& error_msg) {
  if (error_msg.error_stream == bi_stream_.get()) {
    LOGFID(ERROR, error_msg.frame_number)
        << "Received error message: " << error_msg.error_code;
  }
}

void ZslHelper::WaitAttachedFrame(uint32_t frame_number,
                                  base::ScopedFD release_fence) {
  fence_sync_thread_.task_runner()->PostTask(
      FROM_HERE, base::BindOnce(&ZslHelper::WaitAttachedFrameOnFenceSyncThread,
                                base::Unretained(this), frame_number,
                                std::move(release_fence)));
}

void ZslHelper::WaitAttachedFrameOnFenceSyncThread(
    uint32_t frame_number, base::ScopedFD release_fence) {
  if (release_fence.is_valid() &&
      sync_wait(release_fence.get(), ZslHelper::kZslSyncWaitTimeoutMs)) {
    LOGF(WARNING) << "Failed to wait for release fence on attached ZSL buffer";
  } else {
    base::AutoLock ring_buffer_lock(ring_buffer_lock_);
    auto it = std::find_if(ring_buffer_.begin(), ring_buffer_.end(),
                           [&](const ZslBuffer& buffer) {
                             return buffer.frame_number == frame_number;
                           });
    if (it != ring_buffer_.end()) {
      it->buffer_ready = true;
    }
    return;
  }
  fence_sync_thread_.task_runner()->PostTask(
      FROM_HERE, base::BindOnce(&ZslHelper::WaitAttachedFrameOnFenceSyncThread,
                                base::Unretained(this), frame_number,
                                std::move(release_fence)));
}

void ZslHelper::ReleaseStreamBuffer(std::optional<Camera3StreamBuffer> buffer) {
  if (!buffer) {
    return;
  }
  fence_sync_thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&ZslHelper::ReleaseStreamBufferOnFenceSyncThread,
                     base::Unretained(this), std::move(buffer.value())));
}

void ZslHelper::ReleaseStreamBufferOnFenceSyncThread(
    Camera3StreamBuffer buffer) {
  if (!buffer.WaitOnAndClearReleaseFence(ZslHelper::kZslSyncWaitTimeoutMs)) {
    LOGF(WARNING) << "Failed to wait for release fence on ZSL input buffer";
  } else {
    if (!zsl_buffer_manager_->ReleaseBuffer(*buffer.buffer())) {
      LOGF(ERROR) << "Failed to release this stream buffer";
    }
    // The above error should only happen when the mapping in buffer manager
    // becomes invalid somwhow. It's not recoverable, so we don't retry here.
    return;
  }
  fence_sync_thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&ZslHelper::ReleaseStreamBufferOnFenceSyncThread,
                     base::Unretained(this), std::move(buffer)));
}

bool ZslHelper::IsCapabilitySupported(const camera_metadata_t* static_info,
                                      uint8_t capability) {
  camera_metadata_ro_entry_t entry;
  if (find_camera_metadata_ro_entry(
          static_info, ANDROID_REQUEST_AVAILABLE_CAPABILITIES, &entry) == 0) {
    return std::find(entry.data.u8, entry.data.u8 + entry.count, capability) !=
           entry.data.u8 + entry.count;
  }
  return false;
}

bool ZslHelper::SelectZslStreamSize(const camera_metadata_t* static_info,
                                    uint32_t* bi_width,
                                    uint32_t* bi_height,
                                    int64_t* min_frame_duration) {
  *bi_width = 0;
  *bi_height = 0;
  camera_metadata_ro_entry entry;
  if (find_camera_metadata_ro_entry(
          static_info, ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS,
          &entry) != 0) {
    LOGF(ERROR) << "Failed to find stream configurations map";
    return false;
  }
  VLOGF(1) << "Iterating stream configuration map for ZSL streams";
  for (size_t i = 0; i < entry.count; i += 4) {
    const int32_t& format = entry.data.i32[i + STREAM_CONFIG_FORMAT_INDEX];
    if (format != kZslPixelFormat)
      continue;
    const int32_t& width = entry.data.i32[i + STREAM_CONFIG_WIDTH_INDEX];
    const int32_t& height = entry.data.i32[i + STREAM_CONFIG_HEIGHT_INDEX];
    const int32_t& direction =
        entry.data.i32[i + STREAM_CONFIG_DIRECTION_INDEX];
    VLOGF(1) << "format = " << format << ", "
             << "width = " << width << ", "
             << "height = " << height << ", "
             << "direction = " << direction;
    if (direction == ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS_INPUT) {
      if (width * height > (*bi_width) * (*bi_height)) {
        *bi_width = width;
        *bi_height = height;
      }
    }
  }
  if (*bi_width == 0 || *bi_height == 0) {
    LOGF(ERROR) << "Failed to select ZSL stream size";
    return false;
  }

  *min_frame_duration = 0;
  if (find_camera_metadata_ro_entry(
          static_info, ANDROID_SCALER_AVAILABLE_MIN_FRAME_DURATIONS, &entry) !=
      0) {
    LOGF(ERROR) << "Failed to find the minimum frame durations";
    return false;
  }
  for (size_t i = 0; i < entry.count; i += 4) {
    const int64_t& format = entry.data.i64[i + FRAME_DURATION_FOMRAT_INDEX];
    const int64_t& width = entry.data.i64[i + FRAME_DURATION_WIDTH_INDEX];
    const int64_t& height = entry.data.i64[i + FRAME_DURATION_HEIGHT_INDEX];
    const int64_t& duration = entry.data.i64[i + FRAME_DURATION_DURATION_INDEX];
    if (format == kZslPixelFormat && width == *bi_width &&
        height == *bi_height) {
      *min_frame_duration = duration;
      break;
    }
  }
  if (*min_frame_duration == 0) {
    LOGF(ERROR) << "Failed to find the minimum frame duration for the selected "
                   "ZSL stream";
    return false;
  }

  return true;
}

ZslHelper::ZslBufferIterator ZslHelper::SelectZslBuffer(
    SelectionStrategy strategy) {
  ring_buffer_lock_.AssertAcquired();
  if (strategy == LAST_SUBMITTED) {
    for (auto it = ring_buffer_.begin(); it != ring_buffer_.end(); it++) {
      if (it->metadata_ready && it->buffer_ready && !it->selected) {
        it->selected = true;
        return it;
      }
    }
    LOGF(WARNING) << "Failed to find a unselected submitted ZSL buffer";
    return ring_buffer_.end();
  }

  // For CLOSEST or CLOSEST_3A strategies.
  int64_t cur_timestamp = GetCurrentTimestamp();
  LOGF(INFO) << "Current timestamp = " << cur_timestamp;
  ZslBufferIterator selected_buffer_it = ring_buffer_.end();
  int64_t min_diff = zsl_lookback_ns_;
  int64_t ideal_timestamp = cur_timestamp - zsl_lookback_ns_;
  for (auto it = ring_buffer_.begin(); it != ring_buffer_.end(); it++) {
    if (!it->metadata_ready || !it->buffer_ready || it->selected) {
      continue;
    }
    int64_t timestamp = GetTimestamp(it->metadata);
    bool satisfy_3a = strategy == CLOSEST ||
                      (strategy == CLOSEST_3A && Is3AConverged(it->metadata));
    int64_t diff = timestamp - ideal_timestamp;
    VLOGF(1) << "Candidate timestamp = " << timestamp
             << " (Satisfy 3A = " << satisfy_3a << ", "
             << "Difference from desired timestamp = " << diff << ")";
    if (diff > kZslLookbackLengthNs) {
      continue;
    } else if (diff < 0) {
      // We don't select buffers that are older than what is displayed.
      break;
    }
    if (satisfy_3a) {
      if (diff < min_diff) {
        min_diff = diff;
        selected_buffer_it = it;
      } else {
        // Not possible to find a better buffer
        break;
      }
    }
  }
  if (selected_buffer_it == ring_buffer_.end()) {
    LOGF(WARNING)
        << "Failed to a find suitable ZSL buffer with the given strategy";
    return selected_buffer_it;
  }
  LOGF(INFO) << "Timestamp of the selected buffer = "
             << GetTimestamp(selected_buffer_it->metadata);
  selected_buffer_it->selected = true;
  return selected_buffer_it;
}

int64_t ZslHelper::GetCurrentTimestamp() {
  if (override_current_timestamp_for_testing_ !=
      kOverrideCurrentTimestampNotSet) {
    return override_current_timestamp_for_testing_;
  }
  struct timespec t = {};
  clock_gettime(
      timestamp_source_ == ANDROID_SENSOR_INFO_TIMESTAMP_SOURCE_UNKNOWN
          ? CLOCK_MONOTONIC
          : CLOCK_BOOTTIME /* ANDROID_SENSOR_INFO_TIMESTAMP_SOURCE_REALTIME */,
      &t);
  return static_cast<int64_t>(t.tv_sec) * 1000000000LL + t.tv_nsec;
}

bool ZslHelper::Is3AConverged(const android::CameraMetadata& android_metadata) {
  auto GetState = [&](size_t tag) {
    camera_metadata_ro_entry_t entry;
    if (android_metadata.exists(tag)) {
      entry = android_metadata.find(tag);
      return entry.data.u8[0];
    }
    LOGF(ERROR) << "Cannot find the metadata for "
                << get_camera_metadata_tag_name(tag);
    return static_cast<uint8_t>(0);
  };
  uint8_t ae_mode = GetState(ANDROID_CONTROL_AE_MODE);
  uint8_t ae_state = GetState(ANDROID_CONTROL_AE_STATE);
  bool ae_converged = [&]() {
    if (ae_mode != ANDROID_CONTROL_AE_MODE_OFF) {
      if (ae_state != ANDROID_CONTROL_AE_STATE_CONVERGED &&
          ae_state != ANDROID_CONTROL_AE_STATE_FLASH_REQUIRED &&
          ae_state != ANDROID_CONTROL_AE_STATE_LOCKED) {
        return false;
      }
    }
    return true;
  }();
  if (!ae_converged) {
    return false;
  }
  uint8_t af_mode = GetState(ANDROID_CONTROL_AF_MODE);
  uint8_t af_state = GetState(ANDROID_CONTROL_AF_STATE);
  bool af_converged = [&]() {
    if (af_mode != ANDROID_CONTROL_AF_MODE_OFF) {
      if (af_state != ANDROID_CONTROL_AF_STATE_PASSIVE_FOCUSED &&
          af_state != ANDROID_CONTROL_AF_STATE_FOCUSED_LOCKED) {
        return false;
      }
    }
    return true;
  }();
  if (!af_converged) {
    return false;
  }
  uint8_t awb_mode = GetState(ANDROID_CONTROL_AWB_MODE);
  uint8_t awb_state = GetState(ANDROID_CONTROL_AWB_STATE);
  bool awb_converged = [&]() {
    if (awb_mode != ANDROID_CONTROL_AWB_MODE_OFF) {
      if (awb_state != ANDROID_CONTROL_AWB_STATE_CONVERGED &&
          awb_state != ANDROID_CONTROL_AWB_STATE_LOCKED) {
        return false;
      }
    }
    return true;
  }();
  // We won't reach here if neither AE nor AF is converged.
  return awb_converged;
}

void ZslHelper::SetZslBufferManagerForTesting(
    std::unique_ptr<ZslBufferManager> zsl_buffer_manager) {
  zsl_buffer_manager_ = std::move(zsl_buffer_manager);
}

void ZslHelper::OverrideCurrentTimestampForTesting(int64_t timestamp) {
  override_current_timestamp_for_testing_ = timestamp;
}

bool AddVendorTags(VendorTagManager& vendor_tag_manager) {
  if (!vendor_tag_manager.Add(kCrosZslVendorTagCanAttempt,
                              kCrosZslVendorTagSectionName,
                              kCrosZslVendorTagCanAttemptName, TYPE_BYTE)) {
    LOGF(ERROR)
        << "Failed to add the vendor tag for CrOS ZSL attemptable indicator";
    return false;
  }
  return true;
}

bool TryAddEnableZslKey(android::CameraMetadata* metadata) {
  const camera_metadata_t* locked_metadata = metadata->getAndLock();
  if (!CanEnableZsl(locked_metadata)) {
    metadata->unlock(locked_metadata);
    return false;
  }
  metadata->unlock(locked_metadata);

  auto entry = metadata->find(ANDROID_REQUEST_AVAILABLE_REQUEST_KEYS);
  std::vector<int32_t> new_request_keys(entry.data.i32,
                                        entry.data.i32 + entry.count);
  new_request_keys.push_back(ANDROID_CONTROL_ENABLE_ZSL);
  if (metadata->update(ANDROID_REQUEST_AVAILABLE_REQUEST_KEYS,
                       new_request_keys.data(), new_request_keys.size()) != 0) {
    LOGF(ERROR) << "Failed to add ANDROID_CONTROL_ENABLE_ZSL to metadata";
    return false;
  }
  LOGF(INFO) << "Added ANDROID_CONTROL_ENABLE_ZSL to static metadata";
  return true;
}

}  // namespace cros

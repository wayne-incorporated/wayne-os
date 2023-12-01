/*
 * Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "features/auto_framing/tests/auto_framing_test_fixture.h"

#include <sync/sync.h>

#include <utility>

#include "common/camera_hal3_helpers.h"
#include "features/auto_framing/auto_framing_stream_manipulator.h"

namespace cros::tests {

namespace {

Rect<uint32_t> ToAbsoluteCrop(const Size& size, const Rect<float>& crop) {
  return Rect<uint32_t>(
      static_cast<uint32_t>(static_cast<float>(size.width) * crop.left),
      static_cast<uint32_t>(static_cast<float>(size.height) * crop.top),
      static_cast<uint32_t>(static_cast<float>(size.width) * crop.width),
      static_cast<uint32_t>(static_cast<float>(size.height) * crop.height));
}

bool IsAspectRatioMatched(const Rect<float>& crop,
                          uint32_t src_width,
                          uint32_t src_height,
                          uint32_t dst_width,
                          uint32_t dst_height) {
  return std::abs((static_cast<float>(src_width) * crop.width) /
                      (static_cast<float>(src_height) * crop.height) -
                  static_cast<float>(dst_width) /
                      static_cast<float>(dst_height)) < 2e-2f;
}

bool AreSameRects(const Rect<float>& r1,
                  const Rect<float>& r2,
                  float threshold) {
  return std::abs(r1.left - r2.left) <= threshold &&
         std::abs(r1.top - r2.top) <= threshold &&
         std::abs(r1.right() - r2.right()) <= threshold &&
         std::abs(r1.bottom() - r2.bottom()) <= threshold;
}

bool IsFullCrop(const Rect<float>& rect) {
  constexpr float kThreshold = 1e-3f;
  return rect.width >= 1.0 - kThreshold || rect.height >= 1.0 - kThreshold;
}

bool PrepareStaticMetadata(android::CameraMetadata* static_info,
                           const Size& full_yuv_size,
                           const Size& full_blob_size,
                           const Size& client_yuv_size,
                           const Size& client_blob_size,
                           float frame_rate) {
  const int32_t full_yuv_width =
      base::checked_cast<int32_t>(full_yuv_size.width);
  const int32_t full_yuv_height =
      base::checked_cast<int32_t>(full_yuv_size.height);
  const int32_t full_blob_width =
      base::checked_cast<int32_t>(full_blob_size.width);
  const int32_t full_blob_height =
      base::checked_cast<int32_t>(full_blob_size.height);
  const int32_t client_yuv_width =
      base::checked_cast<int32_t>(client_yuv_size.width);
  const int32_t client_yuv_height =
      base::checked_cast<int32_t>(client_yuv_size.height);
  const int32_t client_blob_width =
      base::checked_cast<int32_t>(client_blob_size.width);
  const int32_t client_blob_height =
      base::checked_cast<int32_t>(client_blob_size.height);
  const int64_t frame_duration_ns = static_cast<int32_t>(1e9f / frame_rate);
  constexpr int64_t k1FpsFrameDurationNs = 1'000'000'000LL;

  const int32_t partial_result_count = 1;
  const int32_t active_array_size[] = {0, 0, full_blob_width, full_blob_height};
  const int32_t available_stream_configurations[] = {
      HAL_PIXEL_FORMAT_YCbCr_420_888,
      full_yuv_width,
      full_yuv_height,
      ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS_OUTPUT,
      HAL_PIXEL_FORMAT_YCbCr_420_888,
      client_yuv_width,
      client_yuv_height,
      ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS_OUTPUT,
      HAL_PIXEL_FORMAT_YCbCr_420_888,
      full_blob_width,
      full_blob_height,
      ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS_OUTPUT,
      HAL_PIXEL_FORMAT_YCbCr_420_888,
      client_blob_width,
      client_blob_height,
      ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS_OUTPUT,
      HAL_PIXEL_FORMAT_BLOB,
      full_blob_width,
      full_blob_height,
      ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS_OUTPUT,
      HAL_PIXEL_FORMAT_BLOB,
      client_blob_width,
      client_blob_height,
      ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS_OUTPUT,
  };
  const int64_t available_min_frame_durations[] = {
      HAL_PIXEL_FORMAT_YCbCr_420_888,
      full_yuv_width,
      full_yuv_height,
      frame_duration_ns,
      HAL_PIXEL_FORMAT_YCbCr_420_888,
      client_yuv_width,
      client_yuv_height,
      frame_duration_ns,
      HAL_PIXEL_FORMAT_YCbCr_420_888,
      full_blob_width,
      full_blob_height,
      k1FpsFrameDurationNs,
      HAL_PIXEL_FORMAT_YCbCr_420_888,
      client_blob_width,
      client_blob_height,
      k1FpsFrameDurationNs,
      HAL_PIXEL_FORMAT_BLOB,
      full_blob_width,
      full_blob_height,
      k1FpsFrameDurationNs,
      HAL_PIXEL_FORMAT_BLOB,
      client_blob_width,
      client_blob_height,
      k1FpsFrameDurationNs,
  };

  if (static_info->update(ANDROID_REQUEST_PARTIAL_RESULT_COUNT,
                          &partial_result_count, 1) != 0) {
    LOGF(ERROR) << "Failed to update ANDROID_REQUEST_PARTIAL_RESULT_COUNT";
    return false;
  }
  if (static_info->update(ANDROID_SENSOR_INFO_ACTIVE_ARRAY_SIZE,
                          active_array_size,
                          std::size(active_array_size)) != 0) {
    LOGF(ERROR) << "Failed to update ANDROID_SENSOR_INFO_ACTIVE_ARRAY_SIZE";
    return false;
  }
  if (static_info->update(ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS,
                          available_stream_configurations,
                          std::size(available_stream_configurations)) != 0) {
    LOGF(ERROR)
        << "Failed to update ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS";
    return false;
  }
  if (static_info->update(ANDROID_SCALER_AVAILABLE_MIN_FRAME_DURATIONS,
                          available_min_frame_durations,
                          std::size(available_min_frame_durations)) != 0) {
    LOGF(ERROR)
        << "Failed to update ANDROID_SCALER_AVAILABLE_MIN_FRAME_DURATIONS";
    return false;
  }
  return true;
}

bool PrepareResultMetadata(android::CameraMetadata* result_metadata,
                           int64_t sensor_timestamp,
                           const Rect<int32_t>& face_rect) {
  if (result_metadata->update(ANDROID_SENSOR_TIMESTAMP, &sensor_timestamp, 1) !=
      0) {
    LOGF(ERROR) << "Failed to update ANDROID_SENSOR_TIMESTAMP";
    return false;
  }
  const int32_t face_rectangles[] = {face_rect.left, face_rect.top,
                                     face_rect.right(), face_rect.bottom()};
  if (result_metadata->update(ANDROID_STATISTICS_FACE_RECTANGLES,
                              face_rectangles,
                              std::size(face_rectangles)) != 0) {
    LOGF(ERROR) << "Failed to update ANDROID_STATISTICS_FACE_RECTANGLES";
    return false;
  }
  return true;
}

}  // namespace

bool AutoFramingTestFixture::LoadTestImage(const base::FilePath& path) {
  test_image_one_face_ = TestImage::Create(path);
  if (!test_image_one_face_) {
    LOGF(ERROR) << "Failed to load test image from " << path;
    return false;
  }
  if (test_image_one_face_->face_rectangles().size() != 1) {
    LOGF(ERROR) << "Expected there's one face in the test image (metadata)";
    test_image_one_face_.reset();
    return false;
  }
  return true;
}

bool AutoFramingTestFixture::SetUp(
    const Size& full_yuv_size,
    const Size& full_blob_size,
    const Size& client_yuv_size,
    const Size& client_blob_size,
    float frame_rate,
    std::vector<TestStreamConfig> test_stream_configs,
    const AutoFramingStreamManipulator::Options& options,
    std::unique_ptr<StillCaptureProcessor> still_capture_processor) {
  if (full_yuv_size.width > full_blob_size.width ||
      full_yuv_size.height > full_blob_size.height ||
      client_yuv_size.width > full_yuv_size.width ||
      client_yuv_size.height > full_yuv_size.height ||
      client_blob_size.width > full_blob_size.width ||
      client_blob_size.height > full_blob_size.height ||
      !IsAspectRatioMatched(Rect<float>(0.0f, 0.0f, 1.0f, 1.0f),
                            full_yuv_size.width, full_yuv_size.height,
                            full_blob_size.width, full_blob_size.height)) {
    LOGF(ERROR) << "Invalid size combinations";
    return false;
  }

  active_array_size_ = full_blob_size;
  if (!PrepareStaticMetadata(&static_info_, full_yuv_size, full_blob_size,
                             client_yuv_size, client_blob_size, frame_rate)) {
    return false;
  }

  if (!gpu_resources_.Initialize()) {
    LOGF(ERROR) << "Failed to initialize GPU resources";
    return false;
  }

  auto_framing_stream_manipulator_ =
      std::make_unique<AutoFramingStreamManipulator>(
          &runtime_options_, &gpu_resources_, base::FilePath(),
          std::move(still_capture_processor), options);

  const camera_metadata_t* locked_static_info = static_info_.getAndLock();
  if (!locked_static_info) {
    LOGF(ERROR) << "Failed to lock static info";
    return false;
  }
  auto result_callback = base::BindRepeating(
      [](base::WaitableEvent* event, Camera3CaptureDescriptor result) {
        for (auto& b : result.GetMutableOutputBuffers()) {
          constexpr int kSyncWaitTimeoutMs = 300;
          if (!b.WaitOnAndClearReleaseFence(kSyncWaitTimeoutMs)) {
            LOGF(WARNING) << "Failed to wait on release fence";
          }
          if (b.stream()->format == HAL_PIXEL_FORMAT_BLOB) {
            DCHECK(!event->IsSignaled());
            event->Signal();
          }
        }
      },
      &still_capture_result_received_);
  if (!auto_framing_stream_manipulator_->Initialize(
          locked_static_info, StreamManipulator::Callbacks{
                                  .result_callback = std::move(result_callback),
                                  .notify_callback = base::DoNothing()})) {
    LOGF(ERROR) << "Failed to initialize AutoFramingStreamManipulator";
    return false;
  }
  if (static_info_.unlock(locked_static_info) != 0) {
    LOGF(ERROR) << "Failed to unlock static info";
    return false;
  }

  client_yuv_stream_ = camera3_stream_t{
      .stream_type = CAMERA3_STREAM_OUTPUT,
      .width = client_yuv_size.width,
      .height = client_yuv_size.height,
      .format = HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED,
      .usage = 0,
  };
  client_blob_stream_ = camera3_stream_t{
      .stream_type = CAMERA3_STREAM_OUTPUT,
      .width = client_blob_size.width,
      .height = client_blob_size.height,
      .format = HAL_PIXEL_FORMAT_BLOB,
      .usage = 0,
  };
  client_streams_.push_back(&client_yuv_stream_);
  client_streams_.push_back(&client_blob_stream_);
  Camera3StreamConfiguration stream_config(camera3_stream_configuration_t{
      .num_streams = static_cast<uint32_t>(client_streams_.size()),
      .streams = client_streams_.data(),
      .operation_mode = CAMERA3_STREAM_CONFIGURATION_NORMAL_MODE,
  });
  StreamEffectMap stream_effects_map;
  LOGF(INFO) << "Configued streams:";
  for (camera3_stream_t* s : stream_config.GetStreams()) {
    LOGF(INFO) << "  " << GetDebugString(s);
  }

  if (!auto_framing_stream_manipulator_->ConfigureStreams(
          &stream_config, &stream_effects_map)) {
    LOGF(ERROR) << "Failed to pre-configure streams";
    return false;
  }
  for (camera3_stream_t* s : stream_config.GetStreams()) {
    s->max_buffers = 1;
    modified_stream_buffers_[s] = std::vector<ScopedBufferHandle>{};
  }
  LOGF(INFO) << "Modified streams:";
  for (camera3_stream_t* s : stream_config.GetStreams()) {
    LOGF(INFO) << "  " << GetDebugString(s);
  }

  if (!auto_framing_stream_manipulator_->OnConfiguredStreams(&stream_config)) {
    LOGF(ERROR) << "Failed to post-configure streams";
    return false;
  }

  test_stream_configs_ = std::move(test_stream_configs);
  for (auto& [stream, buffers] : modified_stream_buffers_) {
    if (stream->format == HAL_PIXEL_FORMAT_BLOB) {
      // Allocate dummy BLOB frames.
      for (size_t i = 0; i < test_stream_configs_.size(); ++i) {
        buffers.push_back(CameraBufferManager::AllocateScopedBuffer(
            stream->width, stream->height, stream->format, stream->usage));
        if (!buffers.back()) {
          LOGF(ERROR) << "Failed to allocate BLOB buffer";
          return false;
        }
      }
    } else {
      // Create YUV frames with contents.
      for (auto& cfg : test_stream_configs_) {
        buffers.push_back(CreateTestFrameWithFace(
            stream->width, stream->height, stream->format, stream->usage,
            ToAbsoluteCrop(Size(stream->width, stream->height),
                           cfg.face_rect)));
        if (!buffers.back()) {
          LOGF(ERROR) << "Failed to create YUV frame with face rect: "
                      << cfg.face_rect.ToString();
          return false;
        }
      }
    }
  }

  client_yuv_buffer_ = CameraBufferManager::AllocateScopedBuffer(
      client_yuv_stream_.width, client_yuv_stream_.height,
      client_yuv_stream_.format, client_yuv_stream_.usage);
  if (!client_yuv_buffer_) {
    LOGF(ERROR) << "Failed to allocate YUV buffer";
    return false;
  }
  client_blob_buffer_ = CameraBufferManager::AllocateScopedBuffer(
      client_blob_stream_.width, client_blob_stream_.height,
      client_blob_stream_.format, client_blob_stream_.usage);
  if (!client_blob_buffer_) {
    LOGF(ERROR) << "Failed to allocate BLOB buffer";
    return false;
  }

  return true;
}

bool AutoFramingTestFixture::ProcessFrame(int64_t sensor_timestamp,
                                          bool is_enabled,
                                          bool has_yuv,
                                          bool has_blob,
                                          FramingResult* framing_result) {
  runtime_options_.SetAutoFramingState(
      is_enabled ? mojom::CameraAutoFramingState::ON_SINGLE
                 : mojom::CameraAutoFramingState::OFF);
  ++frame_number_;
  std::vector<camera3_stream_t*> requested_streams;
  if (!ProcessCaptureRequest(has_yuv, has_blob, &requested_streams)) {
    return false;
  }
  if (!ProcessCaptureResult(has_blob, requested_streams, sensor_timestamp,
                            framing_result)) {
    return false;
  }
  return true;
}

ScopedBufferHandle AutoFramingTestFixture::CreateTestFrameWithFace(
    uint32_t width,
    uint32_t height,
    uint32_t format,
    uint32_t usage,
    const Rect<uint32_t>& face_rect) {
  if (!test_image_one_face_) {
    LOGF(ERROR) << "Test image is not loaded";
    return nullptr;
  }
  const Rect<float> src_rect = NormalizeRect(
      test_image_one_face_->face_rectangles()[0], test_image_one_face_->size());
  const Rect<float> dst_rect = NormalizeRect(face_rect, Size(width, height));
  const float scale_x = src_rect.width / dst_rect.width;
  const float scale_y = src_rect.height / dst_rect.height;
  const float offset_x = src_rect.left - dst_rect.left * scale_x;
  const float offset_y = src_rect.top - dst_rect.top * scale_y;
  if (scale_x > 1.0f || scale_y > 1.0f || offset_x < 0.0f || offset_y < 0.0f ||
      offset_x + scale_x > 1.0f || offset_y + scale_y > 1.0f) {
    LOGF(ERROR) << "Failed to create test frame with face at "
                << face_rect.ToString();
    return nullptr;
  }
  const Rect<uint32_t> crop(
      static_cast<uint32_t>(static_cast<float>(test_image_one_face_->width()) *
                            offset_x),
      static_cast<uint32_t>(static_cast<float>(test_image_one_face_->height()) *
                            offset_y),
      static_cast<uint32_t>(static_cast<float>(test_image_one_face_->width()) *
                            scale_x),
      static_cast<uint32_t>(static_cast<float>(test_image_one_face_->height()) *
                            scale_y));
  ScopedBufferHandle buffer =
      CameraBufferManager::AllocateScopedBuffer(width, height, format, usage);
  if (!buffer) {
    LOGF(ERROR) << "Failed to allocate buffer";
    return nullptr;
  }
  if (!WriteTestImageToBuffer(*test_image_one_face_, *buffer, crop)) {
    LOGF(ERROR) << "Failed to write test image to buffer";
    return nullptr;
  }
  return buffer;
}

bool AutoFramingTestFixture::ProcessCaptureRequest(
    bool has_yuv,
    bool has_blob,
    std::vector<camera3_stream_t*>* requested_streams) {
  std::vector<camera3_stream_buffer_t> buffers;
  if (has_yuv) {
    buffers.push_back(camera3_stream_buffer_t{
        .stream = &client_yuv_stream_,
        .buffer = client_yuv_buffer_.get(),
        .status = CAMERA3_BUFFER_STATUS_OK,
        .acquire_fence = -1,
        .release_fence = -1,
    });
  }
  if (has_blob) {
    buffers.push_back(camera3_stream_buffer_t{
        .stream = &client_blob_stream_,
        .buffer = client_blob_buffer_.get(),
        .status = CAMERA3_BUFFER_STATUS_OK,
        .acquire_fence = -1,
        .release_fence = -1,
    });
    still_capture_result_received_.Reset();
  }
  Camera3CaptureDescriptor request(camera3_capture_request_t{
      .frame_number = frame_number_,
      .settings = nullptr,
      .num_output_buffers = static_cast<uint32_t>(buffers.size()),
      .output_buffers = buffers.data(),
  });
  if (!auto_framing_stream_manipulator_->ProcessCaptureRequest(&request)) {
    LOGF(ERROR) << "Failed to process capture request";
    return false;
  }

  for (auto& b : request.AcquireOutputBuffers()) {
    requested_streams->push_back(b.mutable_raw_buffer().stream);
  }

  return true;
}

bool AutoFramingTestFixture::ProcessCaptureResult(
    bool has_blob,
    base::span<camera3_stream_t*> requested_streams,
    int64_t sensor_timestamp,
    FramingResult* framing_result) {
  const size_t frame_index = GetFrameIndex(sensor_timestamp);
  if (!PrepareResultMetadata(
          &result_metadata_, sensor_timestamp,
          test_stream_configs_[frame_index].face_rect.AsRect<int32_t>())) {
    return false;
  }

  const camera_metadata_t* locked_result_metadata =
      result_metadata_.getAndLock();
  if (!locked_result_metadata) {
    LOGF(ERROR) << "Failed to lock result metadata";
    return false;
  }
  std::vector<camera3_stream_buffer_t> buffers;
  for (auto* s : requested_streams) {
    buffers.push_back(camera3_stream_buffer_t{
        .stream = s,
        // HACK: Replace the buffer by our pre-filled one.
        .buffer = modified_stream_buffers_[s][frame_index].get(),
        .status = CAMERA3_BUFFER_STATUS_OK,
        .acquire_fence = -1,
        .release_fence = -1,
    });
  }
  Camera3CaptureDescriptor result(camera3_capture_result_t{
      .frame_number = frame_number_,
      .result = locked_result_metadata,
      .num_output_buffers = static_cast<uint32_t>(buffers.size()),
      .output_buffers = buffers.data(),
      .partial_result = 1,
  });
  if (!auto_framing_stream_manipulator_->ProcessCaptureResult(
          std::move(result))) {
    LOGF(ERROR) << "Failed to process capture result";
    return false;
  }
  if (result_metadata_.unlock(locked_result_metadata) != 0) {
    LOGF(ERROR) << "Failed to unlock result metadata";
    return false;
  }

  if (has_blob) {
    constexpr base::TimeDelta kMaxShutterLag = base::Seconds(1);
    if (!still_capture_result_received_.TimedWait(kMaxShutterLag)) {
      LOGF(ERROR) << "Still capture result is not received";
      return false;
    }
  }

  if (!IsAspectRatioMatched(
          auto_framing_stream_manipulator_->active_crop_region(),
          active_array_size_.width, active_array_size_.height,
          client_blob_stream_.width, client_blob_stream_.height)) {
    LOGF(ERROR)
        << "Crop window aspect ratio doesn't match the output: "
        << auto_framing_stream_manipulator_->active_crop_region().ToString();
    return false;
  }
  if (framing_result != nullptr) {
    *framing_result = FramingResult{
        .is_face_detected =
            AreSameRects(auto_framing_stream_manipulator_->region_of_interest(),
                         test_stream_configs_[frame_index].face_rect,
                         /*threshold=*/0.05f),
        .is_crop_window_moving =
            last_crop_window_.has_value()
                ? !AreSameRects(
                      *last_crop_window_,
                      auto_framing_stream_manipulator_->active_crop_region(),
                      /*threshold=*/1e-5f)
                : false,
        .is_crop_window_full =
            IsFullCrop(auto_framing_stream_manipulator_->active_crop_region()),
    };
  }
  last_crop_window_ = auto_framing_stream_manipulator_->active_crop_region();

  return true;
}

size_t AutoFramingTestFixture::GetFrameIndex(int64_t sensor_timestamp) const {
  CHECK_GT(test_stream_configs_.size(), 0u);
  for (size_t i = 0; i < test_stream_configs_.size(); ++i) {
    if (sensor_timestamp <= test_stream_configs_[i].duration.InNanoseconds()) {
      return i;
    }
    sensor_timestamp -= test_stream_configs_[i].duration.InNanoseconds();
  }
  return test_stream_configs_.size() - 1;
}

}  // namespace cros::tests

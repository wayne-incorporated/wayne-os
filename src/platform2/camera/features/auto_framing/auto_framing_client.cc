/*
 * Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "features/auto_framing/auto_framing_client.h"

#include <hardware/gralloc.h>
#include <libyuv.h>

#include <algorithm>
#include <limits>
#include <numeric>
#include <optional>
#include <string>
#include <utility>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/timer/elapsed_timer.h>

#include "base/time/time.h"
#include "common/camera_hal3_helpers.h"
#include "cros-camera/common.h"

namespace cros {

namespace {

// The internal detector model input dimensions.  It saves an internal copy when
// the detector input buffer matches this size and is continuous.
constexpr uint32_t kDetectorInputWidth = 569;
constexpr uint32_t kDetectorInputHeight = 320;

constexpr char kAutoFramingGraphConfigOverridePath[] =
    "/run/camera/auto_framing_subgraph.pbtxt";

bool AreSameRects(const Rect<float>& r1, const Rect<float>& r2) {
  constexpr float kThreshold = std::numeric_limits<float>::epsilon();
  return std::abs(r1.left - r2.left) <= kThreshold &&
         std::abs(r1.top - r2.top) <= kThreshold &&
         std::abs(r1.right() - r2.right()) <= kThreshold &&
         std::abs(r1.bottom() - r2.bottom()) <= kThreshold;
}

}  // namespace

bool AutoFramingClient::SetUp(const Options& options) {
  base::AutoLock lock(lock_);

  image_size_ = options.input_size;

  AutoFramingCrOS::Options auto_framing_options = {
      .frame_rate = options.frame_rate,
      .image_width = base::checked_cast<int>(options.input_size.width),
      .image_height = base::checked_cast<int>(options.input_size.height),
      .detector_input_format = AutoFramingCrOS::ImageFormat::kGRAY8,
      .detector_input_width = base::checked_cast<int>(kDetectorInputWidth),
      .detector_input_height = base::checked_cast<int>(kDetectorInputHeight),
      .target_aspect_ratio_x =
          base::checked_cast<int>(options.target_aspect_ratio_x),
      .target_aspect_ratio_y =
          base::checked_cast<int>(options.target_aspect_ratio_y),
  };
  std::string graph_config;
  std::string* graph_config_ptr = nullptr;
  if (base::ReadFileToString(
          base::FilePath(kAutoFramingGraphConfigOverridePath), &graph_config)) {
    graph_config_ptr = &graph_config;
  }
  auto_framing_ = AutoFramingCrOS::Create();
  if (!auto_framing_ || !auto_framing_->Initialize(auto_framing_options, this,
                                                   graph_config_ptr)) {
    LOGF(ERROR) << "Failed to initialize auto-framing engine";
    auto_framing_ = nullptr;
    ++metrics_.errors[AutoFramingError::kPipelineInitializationError];
    return false;
  }

  detector_input_buffer_.resize(kDetectorInputWidth * kDetectorInputHeight);

  region_of_interest_ = std::nullopt;
  full_crop_ =
      GetCenteringFullCrop(options.input_size, options.target_aspect_ratio_x,
                           options.target_aspect_ratio_y)
          .AsRect<int>();
  full_crop_normalized_ =
      NormalizeRect(full_crop_.AsRect<uint32_t>(), image_size_);

  constexpr float kMaxDetectionInterval = std::numeric_limits<float>::max();
  min_detection_interval_ = base::Seconds(options.detection_rate > 0.0f
                                              ? 1.0f / options.detection_rate
                                              : kMaxDetectionInterval);

  return true;
}

bool AutoFramingClient::ProcessFrame(int64_t timestamp,
                                     buffer_handle_t buffer) {
  base::AutoLock lock(lock_);
  DCHECK_NE(auto_framing_, nullptr);

  VLOGF(2) << "Notify frame @" << timestamp;
  if (!auto_framing_->NotifyFrame(timestamp)) {
    LOGF(ERROR) << "Failed to notify frame @" << timestamp;
    ++metrics_.errors[AutoFramingError::kPipelineInputError];
    return false;
  }

  // Skip detecting this frame if there's an inflight detection or limited by
  // the detection rate.
  if (!buffer || detector_input_buffer_timestamp_.has_value() ||
      (detection_timer_ &&
       detection_timer_->Elapsed() < min_detection_interval_)) {
    return true;
  }
  detection_timer_ = base::ElapsedTimer();

  ScopedMapping mapping(buffer);
  libyuv::ScalePlane(
      mapping.plane(0).addr, mapping.plane(0).stride, mapping.width(),
      mapping.height(), detector_input_buffer_.data(), kDetectorInputWidth,
      kDetectorInputWidth, kDetectorInputHeight, libyuv::kFilterNone);

  VLOGF(2) << "Process frame @" << timestamp;
  detector_input_buffer_timestamp_ = timestamp;
  if (!auto_framing_->ProcessFrame(timestamp, detector_input_buffer_.data(),
                                   kDetectorInputWidth)) {
    LOGF(ERROR) << "Failed to detect frame @" << timestamp;
    detector_input_buffer_timestamp_ = std::nullopt;
    ++metrics_.errors[AutoFramingError::kPipelineInputError];
    return false;
  }

  return true;
}

bool AutoFramingClient::ResetCropWindow(int64_t timestamp) {
  base::AutoLock lock(lock_);
  DCHECK_NE(auto_framing_, nullptr);
  VLOGF(1) << "Reset crop window @" << timestamp;
  if (!auto_framing_->SetTargetCropWindow(timestamp, full_crop_.left,
                                          full_crop_.top, full_crop_.right(),
                                          full_crop_.bottom())) {
    LOGF(ERROR) << "Failed to reset crop window @" << timestamp;
    ++metrics_.errors[AutoFramingError::kPipelineInputError];
    return false;
  }
  return true;
}

std::optional<Rect<float>> AutoFramingClient::TakeNewRegionOfInterest() {
  base::AutoLock lock(lock_);
  std::optional<Rect<float>> roi;
  roi.swap(region_of_interest_);
  return roi;
}

Rect<float> AutoFramingClient::GetCropWindow(int64_t timestamp) {
  constexpr base::TimeDelta kCropCalculationTimeout = base::Milliseconds(100);

  base::AutoLock lock(lock_);
  base::ElapsedTimer timer;
  while (crop_windows_.find(timestamp) == crop_windows_.end()) {
    base::TimeDelta elapsed_time = timer.Elapsed();
    if (elapsed_time >= kCropCalculationTimeout) {
      LOGF(WARNING) << "Calculating crop window timed out; using the last";
      ++metrics_.errors[AutoFramingError::kPipelineOutputError];
      return crop_windows_.empty() ? full_crop_normalized_
                                   : crop_windows_.rbegin()->second;
    }
    crop_window_received_cv_.TimedWait(kCropCalculationTimeout - elapsed_time);
  }
  const Rect<float> crop_window = crop_windows_.at(timestamp);
  crop_windows_.erase(timestamp);
  return crop_window;
}

void AutoFramingClient::ResetDetectionTimer() {
  base::AutoLock lock(lock_);
  detection_timer_ = std::nullopt;
}

void AutoFramingClient::TearDown() {
  base::AutoLock lock(lock_);

  auto_framing_.reset();

  detector_input_buffer_timestamp_ = std::nullopt;
  detector_input_buffer_.clear();
}

void AutoFramingClient::OnFrameProcessed(int64_t timestamp) {
  VLOGF(2) << "Release frame @" << timestamp;

  base::AutoLock lock(lock_);
  DCHECK(detector_input_buffer_timestamp_.has_value());
  DCHECK_EQ(*detector_input_buffer_timestamp_, timestamp);
  detector_input_buffer_timestamp_ = std::nullopt;
}

void AutoFramingClient::OnNewRegionOfInterest(
    int64_t timestamp, int x_min, int y_min, int x_max, int y_max) {
  VLOGF(2) << "ROI @" << timestamp << ": " << x_min << "," << y_min << ","
           << x_max << "," << y_max;

  base::AutoLock lock(lock_);
  region_of_interest_ = NormalizeRect(
      Rect<int>(x_min, y_min, x_max - x_min + 1, y_max - y_min + 1)
          .AsRect<uint32_t>(),
      image_size_);
  ++metrics_.num_detections;
  if (x_min != 0 || y_min != 0 || x_max != image_size_.width - 1 ||
      y_max != image_size_.height - 1) {
    ++metrics_.num_detection_hits;
  }
  metrics_.accumulated_detection_latency += detection_timer_->Elapsed();
}

void AutoFramingClient::OnNewCropWindow(
    int64_t timestamp, int x_min, int y_min, int x_max, int y_max) {
  VLOGF(2) << "Crop window @" << timestamp << ": " << x_min << "," << y_min
           << "," << x_max << "," << y_max;

  base::AutoLock lock(lock_);
  const Rect<float> crop_window = NormalizeRect(
      Rect<int>(x_min, y_min, x_max - x_min + 1, y_max - y_min + 1)
          .AsRect<uint32_t>(),
      image_size_);
  crop_windows_[timestamp] = crop_window;

  // Sample zoom ratio when the crop window is stabilized for some time.
  constexpr base::TimeDelta kCropWindowStabilizationPeriod = base::Seconds(1);
  if (!last_crop_window_.has_value() ||
      !AreSameRects(crop_window, *last_crop_window_)) {
    sample_crop_window_timer_ = base::ElapsedTimer();
  } else if (sample_crop_window_timer_.Elapsed() >=
             kCropWindowStabilizationPeriod) {
    const float zoom_ratio =
        1.0f / std::max(crop_window.width, crop_window.height);
    if (zoom_ratio > 1.01f) {
      ++metrics_
            .zoom_ratio_tenths_histogram[static_cast<int>(zoom_ratio * 10.0f)];
    }
    sample_crop_window_timer_ = base::ElapsedTimer();
  }
  last_crop_window_ = crop_window;

  crop_window_received_cv_.Signal();
}

}  // namespace cros

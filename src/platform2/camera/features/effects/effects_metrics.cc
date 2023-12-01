/*
 * Copyright 2023 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "features/effects/effects_metrics.h"

#include <algorithm>
#include <limits>
#include <numeric>
#include <utility>

namespace {
cros::CameraEffect CameraEffectFromConfig(cros::EffectsConfig config) {
  if (config.blur_enabled && config.relight_enabled) {
    return cros::CameraEffect::kBlurAndRelight;
  } else if (config.blur_enabled) {
    return cros::CameraEffect::kBlur;
  } else if (config.relight_enabled) {
    return cros::CameraEffect::kRelight;
  }
  return cros::CameraEffect::kNone;
}

}  // namespace

namespace cros {

EffectsMetricsData::EffectsMetricsData() {
  // Initialize the min/max stream sizes to uint_max/zero so that
  // `RecordStreamSize` can update the values as new streams are added.
  stream_sizes_.fill({std::numeric_limits<size_t>::max(), 0ul});
}

void EffectsMetricsData::RecordSelectedEffect(const EffectsConfig& config) {
  if (config.HasEnabledEffects()) {
    selected_effects_.insert(CameraEffectFromConfig(config));
  }
}

void EffectsMetricsData::RecordFrameProcessingLatency(
    const EffectsConfig& config,
    CameraEffectStreamType stream_type,
    const base::TimeDelta& latency) {
  size_t effect_idx = static_cast<size_t>(CameraEffectFromConfig(config));
  size_t stream_idx = static_cast<size_t>(stream_type);
  processing_times_[effect_idx][stream_idx].push_back(latency);
}

void EffectsMetricsData::RecordFrameProcessingInterval(
    const EffectsConfig& config,
    CameraEffectStreamType stream_type,
    const base::TimeDelta& interval) {
  size_t effect_idx = static_cast<size_t>(CameraEffectFromConfig(config));
  size_t stream_idx = static_cast<size_t>(stream_type);
  frame_intervals_[effect_idx][stream_idx].push_back(interval);
}

void EffectsMetricsData::RecordRequestedFrameRate(int fps) {
  max_requested_fps_ = std::max(max_requested_fps_, fps);
}

void EffectsMetricsData::RecordStreamSize(CameraEffectStreamType stream_type,
                                          size_t size) {
  size_t idx = static_cast<size_t>(stream_type);
  stream_sizes_[idx].first = std::min(stream_sizes_[idx].first, size);
  stream_sizes_[idx].second = std::max(stream_sizes_[idx].second, size);
}

void EffectsMetricsData::RecordNumConcurrentStreams(
    size_t num_concurrent_streams) {
  max_num_concurrent_streams_ =
      std::max(max_num_concurrent_streams_, num_concurrent_streams);
}

void EffectsMetricsData::RecordNumConcurrentProcessedStreams(
    size_t num_concurrent_processed_streams) {
  max_num_concurrent_processed_streams_ = std::max(
      max_num_concurrent_processed_streams_, num_concurrent_processed_streams);
}

void EffectsMetricsData::RecordStillShotTaken() {
  num_still_shots_taken_++;
}

void EffectsMetricsData::RecordError(CameraEffectError error) {
  // Only record the first error that occurs per session.
  if (error_ != CameraEffectError::kNoError) {
    error_ = error;
  }
}

bool EffectsMetricsData::EffectSelected(CameraEffect effect) const {
  return selected_effects_.contains(effect);
}

base::TimeDelta EffectsMetricsData::AverageFrameProcessingLatency(
    CameraEffect effect, CameraEffectStreamType stream_type) const {
  const auto& latencies = processing_times_[static_cast<size_t>(effect)]
                                           [static_cast<size_t>(stream_type)];
  if (latencies.size() > 0) {
    return std::reduce(latencies.begin(), latencies.end()) / latencies.size();
  }
  return base::TimeDelta();
}

base::TimeDelta EffectsMetricsData::AverageFrameProcessingInterval(
    CameraEffect effect, CameraEffectStreamType stream_type) const {
  const auto& intervals = frame_intervals_[static_cast<size_t>(effect)]
                                          [static_cast<size_t>(stream_type)];
  if (intervals.size() > 0) {
    return std::reduce(intervals.begin(), intervals.end()) / intervals.size();
  }
  return base::TimeDelta();
}

EffectsMetricsUploader::EffectsMetricsUploader(
    scoped_refptr<base::SequencedTaskRunner> task_runner)
    : metrics_helper_(CameraMetrics::New()),
      last_upload_time_(base::TimeTicks::Now()),
      task_runner_(task_runner) {}

base::TimeDelta EffectsMetricsUploader::TimeSinceLastUpload() {
  base::AutoLock lock(lock_);
  return base::TimeTicks::Now() - last_upload_time_;
}

void EffectsMetricsUploader::UploadMetricsData(EffectsMetricsData metrics) {
  base::AutoLock lock(lock_);
  last_upload_time_ = base::TimeTicks::Now();

  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&EffectsMetricsUploader::UploadMetricsDataOnThread,
                     base::Unretained(this), std::move(metrics)));
}

void EffectsMetricsUploader::UploadMetricsDataOnThread(
    EffectsMetricsData metrics) {
  if (metrics.max_requested_fps_) {
    metrics_helper_->SendEffectsRequestedFrameRate(metrics.max_requested_fps_);
  }
  if (metrics.max_num_concurrent_streams_) {
    metrics_helper_->SendEffectsNumConcurrentStreams(
        metrics.max_num_concurrent_streams_);
    metrics_helper_->SendEffectsNumConcurrentProcessedStreams(
        metrics.max_num_concurrent_processed_streams_);
  }
  metrics_helper_->SendEffectsError(metrics.error_);
  metrics_helper_->SendEffectsNumStillShotsTaken(
      metrics.num_still_shots_taken_);

  // Post per-effect metrics
  for (int i = 0; i <= static_cast<int>(CameraEffect::kMaxValue); i++) {
    CameraEffect effect = static_cast<CameraEffect>(i);
    if (metrics.EffectSelected(effect)) {
      metrics_helper_->SendEffectsSelectedEffect(effect);
    }
    for (int j = 0; j <= static_cast<int>(CameraEffectStreamType::kMaxValue);
         j++) {
      CameraEffectStreamType stream_type =
          static_cast<CameraEffectStreamType>(j);

      auto avg_latency =
          metrics.AverageFrameProcessingLatency(effect, stream_type);
      if (avg_latency != base::TimeDelta()) {
        metrics_helper_->SendEffectsAvgProcessingLatency(effect, stream_type,
                                                         avg_latency);
      }

      auto avg_interval =
          metrics.AverageFrameProcessingInterval(effect, stream_type);
      if (avg_interval != base::TimeDelta()) {
        metrics_helper_->SendEffectsAvgProcessedFrameInterval(
            effect, stream_type, avg_interval);
      }
    }
  }

  for (int i = 0; i <= static_cast<int>(CameraEffectStreamType::kMaxValue);
       i++) {
    CameraEffectStreamType stream_type = static_cast<CameraEffectStreamType>(i);
    auto [min, max] = metrics.stream_sizes_[i];
    if (max) {
      metrics_helper_->SendEffectsMinStreamSize(stream_type, min);
      metrics_helper_->SendEffectsMaxStreamSize(stream_type, max);
    }
  }
}

}  // namespace cros

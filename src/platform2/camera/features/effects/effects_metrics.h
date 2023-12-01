/*
 * Copyright 2023 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_FEATURES_EFFECTS_EFFECTS_METRICS_H_
#define CAMERA_FEATURES_EFFECTS_EFFECTS_METRICS_H_

#include <memory>
#include <utility>
#include <vector>

#include <base/containers/flat_set.h>
#include <base/task/thread_pool.h>
#include <base/time/time.h>

#include "cros-camera/camera_metrics.h"
#include "cros-camera/camera_thread.h"
#include "ml_core/effects_pipeline.h"

namespace cros {

// EffectsMetricsData should be used to collect and aggregate metrics for the
// EffecsStreamManipulator. It is not thread safe, and should only be used from
// the same sequence. The intention is that the client should use the interfaces
// to record metric samples, and then std::move() the instance into the upload
// method of EffectsMetricsUploader and then create a new one.
class EffectsMetricsData {
 public:
  EffectsMetricsData();
  void RecordSelectedEffect(const EffectsConfig& config);
  void RecordFrameProcessingLatency(const EffectsConfig& config,
                                    CameraEffectStreamType stream_type,
                                    const base::TimeDelta& latency);
  void RecordFrameProcessingInterval(const EffectsConfig& config,
                                     CameraEffectStreamType stream_type,
                                     const base::TimeDelta& interval);
  void RecordRequestedFrameRate(int fps);
  void RecordStreamSize(CameraEffectStreamType stream_type, size_t size);
  void RecordNumConcurrentStreams(size_t num_concurrent_streams);
  void RecordNumConcurrentProcessedStreams(
      size_t num_concurrent_processed_streams);
  void RecordStillShotTaken();
  void RecordError(CameraEffectError error);

  bool EffectSelected(CameraEffect effect) const;
  base::TimeDelta AverageFrameProcessingLatency(
      CameraEffect effect, CameraEffectStreamType stream_type) const;
  base::TimeDelta AverageFrameProcessingInterval(
      CameraEffect effect, CameraEffectStreamType stream_type) const;

 private:
  friend class EffectsMetricsUploader;
  int max_requested_fps_ = 0;
  size_t max_num_concurrent_streams_ = 0u;
  size_t max_num_concurrent_processed_streams_ = 0u;
  size_t num_still_shots_taken_ = 0;
  CameraEffectError error_ = CameraEffectError::kNoError;
  base::flat_set<CameraEffect> selected_effects_;
  // A vector of time durations for each effect and stream type combination.
  using DurationVectorArray = std::array<
      std::array<std::vector<base::TimeDelta>,
                 static_cast<size_t>(CameraEffectStreamType::kMaxValue) + 1>,
      static_cast<size_t>(CameraEffect::kMaxValue) + 1>;
  DurationVectorArray processing_times_;
  DurationVectorArray frame_intervals_;
  std::array<std::pair<size_t /*min*/, size_t /*max*/>,
             static_cast<size_t>(CameraEffect::kMaxValue) + 1>
      stream_sizes_;
};

// EffectsMetricsUploader will upload an instance of EffectsMetricsData to
// UMA. It is thread-safe. The UploadMetricsData call will
// consume an EffectsMetricsData instance and post it asynchronously via the
// task_runner provided on construction.
class EffectsMetricsUploader {
 public:
  explicit EffectsMetricsUploader(
      scoped_refptr<base::SequencedTaskRunner> task_runner);

  base::TimeDelta TimeSinceLastUpload();
  void UploadMetricsData(EffectsMetricsData metrics);

 private:
  base::Lock lock_;

  void UploadMetricsDataOnThread(EffectsMetricsData metrics);

  std::unique_ptr<CameraMetrics> metrics_helper_;
  base::TimeTicks last_upload_time_ GUARDED_BY(lock_);
  scoped_refptr<base::SequencedTaskRunner> task_runner_;
};

}  // namespace cros

#endif  // CAMERA_FEATURES_EFFECTS_EFFECTS_METRICS_H_

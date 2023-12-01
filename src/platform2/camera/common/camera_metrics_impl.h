/*
 * Copyright 2019 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_COMMON_CAMERA_METRICS_IMPL_H_
#define CAMERA_COMMON_CAMERA_METRICS_IMPL_H_

#include <memory>

#include <base/time/time.h>
#include <base/process/process_metrics.h>
#include <cros-camera/camera_metrics.h>
#include <metrics/metrics_library.h>

namespace cros {

// Implementation of Camera Metrics.
class CameraMetricsImpl : public CameraMetrics {
 public:
  CameraMetricsImpl();
  ~CameraMetricsImpl() override;

  void SetMetricsLibraryForTesting(
      std::unique_ptr<MetricsLibraryInterface> metrics_lib);

  void SendJpegProcessLatency(JpegProcessType process_type,
                              JpegProcessMethod process_layer,
                              base::TimeDelta latency) override;
  void SendJpegResolution(JpegProcessType process_type,
                          JpegProcessMethod process_layer,
                          int width,
                          int height) override;
  void SendConfigureStreamResolution(int width,
                                     int height,
                                     int format) override;
  void SendConfigureStreamsLatency(base::TimeDelta latency) override;
  void SendOpenDeviceClientType(int client_type) override;
  void SendOpenDeviceLatency(base::TimeDelta latency) override;
  void SendError(int error_code) override;
  void SendCameraFacing(int facing) override;
  void SendSessionDuration(base::TimeDelta duration) override;
  void SendFaceAeFunction(FaceAeFunction function) override;
  void SendFaceAeMaxDetectedFaces(int number) override;

  void SendHdrnetStreamConfiguration(HdrnetStreamConfiguration config) override;
  void SendHdrnetMaxStreamSize(HdrnetStreamType stream_type, int size) override;
  void SendHdrnetNumConcurrentStreams(int num_streams) override;
  void SendHdrnetMaxOutputBuffersRendered(int num_buffers) override;
  void SendHdrnetError(HdrnetError error) override;
  void SendHdrnetNumStillShotsTaken(int num_shots) override;
  void SendHdrnetAvgLatency(HdrnetProcessingType processing_type,
                            int latency_us) override;

  void SendGcamAeAvgConvergenceLatency(int latency_us) override;
  void SendGcamAeAvgHdrRatio(int hdr_ratio) override;
  void SendGcamAeAvgTet(int tet) override;

  void SendAutoFramingEnabledTimePercentage(int percentage) override;
  void SendAutoFramingEnabledCount(int count) override;
  void SendAutoFramingDetectionHitPercentage(int percentage) override;
  void SendAutoFramingAvgDetectionLatency(base::TimeDelta latency) override;
  void SendAutoFramingMedianZoomRatio(int zoom_ratio_tenths) override;
  void SendAutoFramingError(AutoFramingError error) override;

  void SendEffectsSelectedEffect(CameraEffect effect) override;
  void SendEffectsAvgProcessingLatency(CameraEffect effect,
                                       CameraEffectStreamType stream_type,
                                       base::TimeDelta latency) override;
  void SendEffectsAvgProcessedFrameInterval(CameraEffect effect,
                                            CameraEffectStreamType stream_type,
                                            base::TimeDelta interval) override;
  void SendEffectsRequestedFrameRate(int fps) override;
  void SendEffectsMinStreamSize(CameraEffectStreamType stream_type,
                                int size) override;
  void SendEffectsMaxStreamSize(CameraEffectStreamType stream_type,
                                int size) override;
  void SendEffectsNumConcurrentStreams(int num_streams) override;
  void SendEffectsNumConcurrentProcessedStreams(int num_streams) override;
  void SendEffectsError(CameraEffectError error) override;
  void SendEffectsNumStillShotsTaken(int num_shots) override;

 private:
  std::unique_ptr<MetricsLibraryInterface> metrics_lib_;
};

}  // namespace cros

#endif  // CAMERA_COMMON_CAMERA_METRICS_IMPL_H_

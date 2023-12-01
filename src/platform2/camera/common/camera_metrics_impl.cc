/*
 * Copyright 2019 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "common/camera_metrics_impl.h"

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/system/sys_info.h>
#include <hardware/camera3.h>
#include <system/graphics.h>

#include "camera/mojo/cros_camera_service.mojom.h"
#include "cros-camera/common.h"

namespace cros {

namespace {

constexpr char kCameraJpegProcessLatency[] =
    "ChromeOS.Camera.Jpeg.Latency.%s.%s";
constexpr base::TimeDelta kMinLatency = base::Microseconds(1);
constexpr base::TimeDelta kMaxLatency = base::Seconds(1);
constexpr int kBucketLatency = 100;

constexpr char kCameraJpegResolution[] =
    "ChromeOS.Camera.Jpeg.Resolution.%s.%s";
constexpr int kMinResolutionInPixels = 1;
constexpr int kMaxResolutionInPixels = 15000000;  // 15 MegaPixels.
constexpr int kBucketResolutionInPixels = 50;

constexpr char kCameraConfigureStreamsLatency[] =
    "ChromeOS.Camera.ConfigureStreamsLatency";

constexpr char kCameraConfigureStreamsResolution[] =
    "ChromeOS.Camera.ConfigureStreams.Output.Resolution.%s";

constexpr char kCameraOpenDeviceClientType[] =
    "ChromeOS.Camera.OpenDeviceClientType";
constexpr char kNumClientTypes =
    static_cast<int32_t>(mojom::CameraClientType::kMaxValue) + 1;

constexpr char kCameraOpenDeviceLatency[] = "ChromeOS.Camera.OpenDeviceLatency";

constexpr char kCameraErrorType[] = "ChromeOS.Camera.ErrorType";

constexpr char kCameraFacing[] = "ChromeOS.Camera.Facing";
// Includes CAMERA_FACING_BACK, CAMERA_FACING_FRONT and CAMERA_FACING_EXTERNAL.
constexpr int kNumCameraFacings = 3;

constexpr char kCameraSessionDuration[] = "ChromeOS.Camera.SessionDuration";
constexpr base::TimeDelta kMinCameraSessionDuration = base::Seconds(1);
constexpr base::TimeDelta kMaxCameraSessionDuration = base::Days(1);
constexpr int kBucketCameraSessionDuration = 100;

constexpr char kCameraFaceAeFunction[] =
    "ChromeOS.Camera.FaceAutoExposure.FunctionStatus";
// max number of faces detected times in a camera session
constexpr char kCameraFaceAeMaxDetectedFaces[] =
    "ChromeOS.Camera.FaceAutoExposure.MaxNumDetectedFaces";
constexpr int kMaxNumFaces = 10;

// *** HDRnet metrics ***

constexpr char kHdrnetStreamTypeYuv[] = "YUV";
constexpr char kHdrnetStreamTypeBlob[] = "BLOB";

constexpr char kHdrnetProcessingTypePreprocessing[] = "Preprocessing";
constexpr char kHdrnetProcessingTypeRgbPipeline[] = "RgbPipeline";
constexpr char kHdrnetProcessingTypePostprocessing[] = "Postprocessing";

constexpr char kCameraHdrnetStreamConfiguration[] =
    "ChromeOS.Camera.HDRnet.StreamConfiguration";

constexpr char kCameraHdrnetMaxStreamSize[] =
    "ChromeOS.Camera.HDRnet.MaxStreamSize.%s";
constexpr char kCameraHdrnetNumConcurrentStreams[] =
    "ChromeOS.Camera.HDRnet.NumConcurrentStreams";
constexpr int kMinNumConcurrentHdrnetStreams = 1;
constexpr int kMaxNumConcurrentHdrnetStreams = 4;
constexpr int kNumConcurrentCameraStreamsBuckets = 4;

constexpr char kCameraHdrnetMaxOutputBuffersRendered[] =
    "ChromeOS.Camera.HDRnet.MaxOutputBuffersRendered";
constexpr int kMinNumOutputBuffers = 1;
constexpr int kMaxNumOutputBuffers = 4;
constexpr int kNumOutputBuffersBuckets = 4;

constexpr char kCameraHdrnetError[] = "ChromeOS.Camera.HDRnet.Error";

constexpr char kCameraHdrnetNumStillShotsTaken[] =
    "ChromeOS.Camera.HDRnet.NumStillShotsTaken";
constexpr int kMinNumShotsTaken = 0;
constexpr int kMaxNumShotsTaken = 1000;
constexpr int kNumShotsTakenBuckets = 10;

constexpr char kCameraHdrnetAvgLatency[] =
    "ChromeOS.Camera.HDRnet.AverageLatency.%s";
constexpr int kMinHdrnetLatencyUs = 1;
constexpr int kMaxHdrnetLatencyUs = 50000;
constexpr int kHdrnetLatencyBuckets = 50;

// *** Gcam AE metrics ***

constexpr char kCameraGcamAeAvgConvergenceLatency[] =
    "ChromeOS.Camera.GcamAutoExposure.AverageConvergenceLatency";
constexpr int kMinConvergenceLatencyFrames = 1;
constexpr int kMaxConvergenceLatencyFrames = 3000;
constexpr int kConvergenceLatencyBuckets = 50;

constexpr char kCameraGcamAeAvgHdrRatio[] =
    "ChromeOS.Camera.GcamAutoExposure.AverageHdrRatio";
constexpr int kMinHdrRatio = 1;
constexpr int kMaxHdrRatio = 30;
constexpr int kHdrRatioBuckets = 15;

constexpr char kCameraGcamAeAvgTet[] =
    "ChromeOS.Camera.GcamAutoExposure.AverageTet";
constexpr int kMinTet = 1;
constexpr int kMaxTet = 10000;
constexpr int kTetBuckets = 50;

// *** Auto-framing metrics ***

constexpr char kCameraAutoFramingEnabledTime[] =
    "ChromeOS.Camera.AutoFraming.EnabledTime";

constexpr char kCameraAutoFramingEnabledCount[] =
    "ChromeOS.Camera.AutoFraming.EnabledCount";
constexpr int kMaxEnabledCount = 10;

constexpr char kCameraAutoFramingDetectionHitRate[] =
    "ChromeOS.Camera.AutoFraming.DetectionHitRate";

constexpr char kCameraAutoFramingAvgDetectionLatency[] =
    "ChromeOS.Camera.AutoFraming.AverageDetectionLatency";
constexpr int kMinDetectionLatencyUs = 0;
constexpr int kMaxDetectionLatencyUs = 1'000'000;
constexpr int kDetectionLatencyBuckets = 30;

constexpr char kCameraAutoFramingMedianZoomRatio[] =
    "ChromeOS.Camera.AutoFraming.MedianZoomRatio";
constexpr int kMinZoomRatioTenths = 10;
constexpr int kMaxZoomRatioTenths = 40;
constexpr int kZoomRatioBuckets = 30;

constexpr char kCameraAutoFramingError[] = "ChromeOS.Camera.AutoFraming.Error";

// *** Effects metrics ***
constexpr char kCameraEffectUnknown[] = "Unknown";
constexpr char kCameraEffectNone[] = "None";
constexpr char kCameraEffectBlur[] = "Blur";
constexpr char kCameraEffectRelight[] = "Relight";
constexpr char kCameraEffectBlurAndRelight[] = "BlurAndRelight";
constexpr char kCameraEffectStreamTypeUnknown[] = "Unknown";
constexpr char kCameraEffectStreamTypeYuv[] = "YUV";
constexpr char kCameraEffectStreamTypeBlob[] = "BLOB";

constexpr char kCameraEffectSelected[] =
    "ChromeOS.Camera.Effects.SelectedEffect";
constexpr char kCameraEffectsRequestedFrameRate[] =
    "ChromeOS.Camera.Effects.RequestedFrameRate";
constexpr int kMinEffectsFrameRate = 1;
constexpr int kMaxEffectsFrameRate = 60;
constexpr int kEffectsFrameRateBuckets = 60;

constexpr char kCameraEffectsMinStreamSize[] =
    "ChromeOS.Camera.Effects.%s.MinStreamSize";
constexpr char kCameraEffectsMaxStreamSize[] =
    "ChromeOS.Camera.Effects.%s.MaxStreamSize";
constexpr char kCameraEffectsNumConcurrentStreams[] =
    "ChromeOS.Camera.Effects.NumConcurrentStreams";
constexpr int kMinNumConcurrentEffectStreams = 1;
constexpr int kMaxNumConcurrentEffectStreams = 4;
constexpr char kCameraEffectsNumConcurrentProcessedStreams[] =
    "ChromeOS.Camera.Effects.NumConcurrentProcessedStreams";
constexpr char kCameraEffectsError[] = "ChromeOS.Camera.Effects.Error";
constexpr char kCameraEffectsNumStillShotsTaken[] =
    "ChromeOS.Camera.Effects.NumStillShotsTaken";

constexpr char kCameraEffectAvgProcessingLatency[] =
    "ChromeOS.Camera.Effects.%s.%s.AvgProcessingLatency";
// 0ms -> 250ms
constexpr int kMinEffectsProcessingLatencyUs = 0;
constexpr int kMaxEffectsProcessingLatencyUs = 250'000;
constexpr int kEffectsProcessingLatencyBuckets = 100;

constexpr char kCameraEffectAvgProcessedFrameInterval[] =
    "ChromeOS.Camera.Effects.%s.%s.AvgProcessedFrameInterval";
// 0ms -> 250ms
constexpr int kMinEffectsFrameIntervalUs = 0;
constexpr int kMaxEffectsFrameIntervalUs = 250'000;
constexpr int kEffectsFrameIntervalBuckets = 100;

const char* CameraEffectToString(CameraEffect effect) {
  switch (effect) {
    case CameraEffect::kNone:
      return kCameraEffectNone;
    case CameraEffect::kBlur:
      return kCameraEffectBlur;
    case CameraEffect::kRelight:
      return kCameraEffectRelight;
    case CameraEffect::kBlurAndRelight:
      return kCameraEffectBlurAndRelight;
    default:
      break;
  }
  return kCameraEffectUnknown;
}

const char* CameraEffectStreamTypeToString(CameraEffectStreamType stream_type) {
  switch (stream_type) {
    case CameraEffectStreamType::kYuv:
      return kCameraEffectStreamTypeYuv;
    case CameraEffectStreamType::kBlob:
      return kCameraEffectStreamTypeBlob;
    default:
      break;
  }
  return kCameraEffectStreamTypeUnknown;
}

}  // namespace

// static
std::unique_ptr<CameraMetrics> CameraMetrics::New() {
  return std::make_unique<CameraMetricsImpl>();
}

CameraMetricsImpl::CameraMetricsImpl()
    : metrics_lib_(std::make_unique<MetricsLibrary>()) {}

CameraMetricsImpl::~CameraMetricsImpl() = default;

void CameraMetricsImpl::SetMetricsLibraryForTesting(
    std::unique_ptr<MetricsLibraryInterface> metrics_lib) {
  metrics_lib_ = std::move(metrics_lib);
}

void CameraMetricsImpl::SendJpegProcessLatency(JpegProcessType process_type,
                                               JpegProcessMethod process_layer,
                                               base::TimeDelta latency) {
  std::string action_name = base::StringPrintf(
      kCameraJpegProcessLatency,
      (process_layer == JpegProcessMethod::kHardware ? "Hardware" : "Software"),
      (process_type == JpegProcessType::kDecode ? "Decode" : "Encode"));
  metrics_lib_->SendToUMA(action_name, latency.InMicroseconds(),
                          kMinLatency.InMicroseconds(),
                          kMaxLatency.InMicroseconds(), kBucketLatency);
}

void CameraMetricsImpl::SendJpegResolution(JpegProcessType process_type,
                                           JpegProcessMethod process_layer,
                                           int width,
                                           int height) {
  std::string action_name = base::StringPrintf(
      kCameraJpegResolution,
      (process_layer == JpegProcessMethod::kHardware ? "Hardware" : "Software"),
      (process_type == JpegProcessType::kDecode ? "Decode" : "Encode"));
  metrics_lib_->SendToUMA(action_name, width * height, kMinResolutionInPixels,
                          kMaxResolutionInPixels, kBucketResolutionInPixels);
}

void CameraMetricsImpl::SendConfigureStreamsLatency(base::TimeDelta latency) {
  metrics_lib_->SendToUMA(kCameraConfigureStreamsLatency,
                          latency.InMicroseconds(),
                          kMinLatency.InMicroseconds(),
                          kMaxLatency.InMicroseconds(), kBucketLatency);
}

void CameraMetricsImpl::SendConfigureStreamResolution(int width,
                                                      int height,
                                                      int format) {
  std::string format_str;
  switch (format) {
    case HAL_PIXEL_FORMAT_RGBA_8888:
      format_str = "RGBA_8888";
      break;
    case HAL_PIXEL_FORMAT_RGBX_8888:
      format_str = "RGBX_8888";
      break;
    case HAL_PIXEL_FORMAT_BGRA_8888:
      format_str = "BGRA_8888";
      break;
    case HAL_PIXEL_FORMAT_YCrCb_420_SP:
      format_str = "YCrCb_420_SP";
      break;
    case HAL_PIXEL_FORMAT_YCbCr_422_I:
      format_str = "YCbCr_422_I";
      break;
    case HAL_PIXEL_FORMAT_BLOB:
      format_str = "BLOB";
      break;
    case HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED:
      format_str = "IMPLEMENTATION_DEFINED";
      break;
    case HAL_PIXEL_FORMAT_YCbCr_420_888:
      format_str = "YCbCr_420_888";
      break;
    case HAL_PIXEL_FORMAT_YV12:
      format_str = "YV12";
      break;
  }
  std::string action_name =
      base::StringPrintf(kCameraConfigureStreamsResolution, format_str.c_str());
  metrics_lib_->SendToUMA(action_name, width * height, kMinResolutionInPixels,
                          kMaxResolutionInPixels, kBucketResolutionInPixels);
}

void CameraMetricsImpl::SendOpenDeviceClientType(int client_type) {
  metrics_lib_->SendEnumToUMA(kCameraOpenDeviceClientType, client_type,
                              kNumClientTypes);
}

void CameraMetricsImpl::SendOpenDeviceLatency(base::TimeDelta latency) {
  metrics_lib_->SendToUMA(kCameraOpenDeviceLatency, latency.InMicroseconds(),
                          kMinLatency.InMicroseconds(),
                          kMaxLatency.InMicroseconds(), kBucketLatency);
}

void CameraMetricsImpl::SendError(int error_code) {
  metrics_lib_->SendEnumToUMA(kCameraErrorType, error_code,
                              CAMERA3_MSG_NUM_ERRORS);
}

void CameraMetricsImpl::SendCameraFacing(int facing) {
  metrics_lib_->SendEnumToUMA(kCameraFacing, facing, kNumCameraFacings);
}

void CameraMetricsImpl::SendSessionDuration(base::TimeDelta duration) {
  metrics_lib_->SendToUMA(kCameraSessionDuration, duration.InSeconds(),
                          kMinCameraSessionDuration.InSeconds(),
                          kMaxCameraSessionDuration.InSeconds(),
                          kBucketCameraSessionDuration);
}

void CameraMetricsImpl::SendFaceAeFunction(FaceAeFunction function) {
  metrics_lib_->SendEnumToUMA(kCameraFaceAeFunction, function);
}

void CameraMetricsImpl::SendFaceAeMaxDetectedFaces(int number) {
  if (number > kMaxNumFaces) {
    number = kMaxNumFaces;
  }
  metrics_lib_->SendEnumToUMA(kCameraFaceAeMaxDetectedFaces, number,
                              kMaxNumFaces + 1);
}

void CameraMetricsImpl::SendHdrnetStreamConfiguration(
    HdrnetStreamConfiguration config) {
  metrics_lib_->SendEnumToUMA(kCameraHdrnetStreamConfiguration, config);
}

void CameraMetricsImpl::SendHdrnetMaxStreamSize(HdrnetStreamType stream_type,
                                                int size) {
  std::string type_str;
  switch (stream_type) {
    case HdrnetStreamType::kYuv:
      type_str = kHdrnetStreamTypeYuv;
      break;

    case HdrnetStreamType::kBlob:
      type_str = kHdrnetStreamTypeBlob;
      break;
  }
  std::string key =
      base::StringPrintf(kCameraHdrnetMaxStreamSize, type_str.c_str());
  metrics_lib_->SendToUMA(key, size, kMinResolutionInPixels,
                          kMaxResolutionInPixels, kBucketResolutionInPixels);
}

void CameraMetricsImpl::SendHdrnetNumConcurrentStreams(int num_streams) {
  metrics_lib_->SendToUMA(kCameraHdrnetNumConcurrentStreams, num_streams,
                          kMinNumConcurrentHdrnetStreams,
                          kMaxNumConcurrentHdrnetStreams,
                          kNumConcurrentCameraStreamsBuckets);
}

void CameraMetricsImpl::SendHdrnetMaxOutputBuffersRendered(int num_buffers) {
  metrics_lib_->SendToUMA(kCameraHdrnetMaxOutputBuffersRendered, num_buffers,
                          kMinNumOutputBuffers, kMaxNumOutputBuffers,
                          kNumOutputBuffersBuckets);
}

void CameraMetricsImpl::SendHdrnetError(HdrnetError error) {
  metrics_lib_->SendEnumToUMA(kCameraHdrnetError, error);
}

void CameraMetricsImpl::SendHdrnetNumStillShotsTaken(int num_shots) {
  metrics_lib_->SendToUMA(kCameraHdrnetNumStillShotsTaken, num_shots,
                          kMinNumShotsTaken, kMaxNumShotsTaken,
                          kNumShotsTakenBuckets);
}

void CameraMetricsImpl::SendHdrnetAvgLatency(
    HdrnetProcessingType processing_type, int latency_us) {
  std::string type_str;
  switch (processing_type) {
    case HdrnetProcessingType::kPreprocessing:
      type_str = kHdrnetProcessingTypePreprocessing;
      break;

    case HdrnetProcessingType::kRgbPipeline:
      type_str = kHdrnetProcessingTypeRgbPipeline;
      break;

    case HdrnetProcessingType::kPostprocessing:
      type_str = kHdrnetProcessingTypePostprocessing;
      break;
  }
  std::string key =
      base::StringPrintf(kCameraHdrnetAvgLatency, type_str.c_str());
  metrics_lib_->SendToUMA(key, latency_us, kMinHdrnetLatencyUs,
                          kMaxHdrnetLatencyUs, kHdrnetLatencyBuckets);
}

void CameraMetricsImpl::SendGcamAeAvgConvergenceLatency(int latency_frames) {
  metrics_lib_->SendToUMA(kCameraGcamAeAvgConvergenceLatency, latency_frames,
                          kMinConvergenceLatencyFrames,
                          kMaxConvergenceLatencyFrames,
                          kConvergenceLatencyBuckets);
}

void CameraMetricsImpl::SendGcamAeAvgHdrRatio(int hdr_ratio) {
  metrics_lib_->SendToUMA(kCameraGcamAeAvgHdrRatio, hdr_ratio, kMinHdrRatio,
                          kMaxHdrRatio, kHdrRatioBuckets);
}

void CameraMetricsImpl::SendGcamAeAvgTet(int tet) {
  metrics_lib_->SendToUMA(kCameraGcamAeAvgTet, tet, kMinTet, kMaxTet,
                          kTetBuckets);
}

void CameraMetricsImpl::SendAutoFramingEnabledTimePercentage(int percentage) {
  metrics_lib_->SendPercentageToUMA(kCameraAutoFramingEnabledTime, percentage);
}

void CameraMetricsImpl::SendAutoFramingEnabledCount(int count) {
  metrics_lib_->SendLinearToUMA(kCameraAutoFramingEnabledCount, count,
                                kMaxEnabledCount);
}

void CameraMetricsImpl::SendAutoFramingDetectionHitPercentage(int percentage) {
  metrics_lib_->SendPercentageToUMA(kCameraAutoFramingDetectionHitRate,
                                    percentage);
}

void CameraMetricsImpl::SendAutoFramingAvgDetectionLatency(
    base::TimeDelta latency) {
  metrics_lib_->SendToUMA(kCameraAutoFramingAvgDetectionLatency,
                          latency.InMicroseconds(), kMinDetectionLatencyUs,
                          kMaxDetectionLatencyUs, kDetectionLatencyBuckets);
}

void CameraMetricsImpl::SendAutoFramingMedianZoomRatio(int zoom_ratio_tenths) {
  metrics_lib_->SendToUMA(kCameraAutoFramingMedianZoomRatio, zoom_ratio_tenths,
                          kMinZoomRatioTenths, kMaxZoomRatioTenths,
                          kZoomRatioBuckets);
}

void CameraMetricsImpl::SendAutoFramingError(AutoFramingError error) {
  metrics_lib_->SendEnumToUMA(kCameraAutoFramingError, error);
}

void CameraMetricsImpl::SendEffectsSelectedEffect(CameraEffect effect) {
  metrics_lib_->SendEnumToUMA(kCameraEffectSelected, effect);
}

void CameraMetricsImpl::SendEffectsAvgProcessingLatency(
    CameraEffect effect,
    CameraEffectStreamType stream_type,
    base::TimeDelta latency) {
  auto metric_name = base::StringPrintf(
      kCameraEffectAvgProcessingLatency, CameraEffectToString(effect),
      CameraEffectStreamTypeToString(stream_type));
  metrics_lib_->SendToUMA(
      metric_name, latency.InMicroseconds(), kMinEffectsProcessingLatencyUs,
      kMaxEffectsProcessingLatencyUs, kEffectsProcessingLatencyBuckets);
}

void CameraMetricsImpl::SendEffectsAvgProcessedFrameInterval(
    CameraEffect effect,
    CameraEffectStreamType stream_type,
    base::TimeDelta interval) {
  auto metric_name = base::StringPrintf(
      kCameraEffectAvgProcessedFrameInterval, CameraEffectToString(effect),
      CameraEffectStreamTypeToString(stream_type));
  metrics_lib_->SendToUMA(
      metric_name, interval.InMicroseconds(), kMinEffectsFrameIntervalUs,
      kMaxEffectsFrameIntervalUs, kEffectsFrameIntervalBuckets);
}

void CameraMetricsImpl::SendEffectsRequestedFrameRate(int fps) {
  metrics_lib_->SendToUMA(kCameraEffectsRequestedFrameRate, fps,
                          kMinEffectsFrameRate, kMaxEffectsFrameRate,
                          kEffectsFrameRateBuckets);
}

void CameraMetricsImpl::SendEffectsMinStreamSize(
    CameraEffectStreamType stream_type, int size) {
  std::string key = base::StringPrintf(
      kCameraEffectsMinStreamSize, CameraEffectStreamTypeToString(stream_type));
  metrics_lib_->SendToUMA(key, size, kMinResolutionInPixels,
                          kMaxResolutionInPixels, kBucketResolutionInPixels);
}

void CameraMetricsImpl::SendEffectsMaxStreamSize(
    CameraEffectStreamType stream_type, int size) {
  std::string key = base::StringPrintf(
      kCameraEffectsMaxStreamSize, CameraEffectStreamTypeToString(stream_type));
  metrics_lib_->SendToUMA(key, size, kMinResolutionInPixels,
                          kMaxResolutionInPixels, kBucketResolutionInPixels);
}

void CameraMetricsImpl::SendEffectsNumConcurrentStreams(int num_streams) {
  metrics_lib_->SendToUMA(kCameraEffectsNumConcurrentStreams, num_streams,
                          kMinNumConcurrentEffectStreams,
                          kMaxNumConcurrentEffectStreams,
                          kNumConcurrentCameraStreamsBuckets);
}

void CameraMetricsImpl::SendEffectsNumConcurrentProcessedStreams(
    int num_streams) {
  metrics_lib_->SendToUMA(kCameraEffectsNumConcurrentProcessedStreams,
                          num_streams, kMinNumConcurrentEffectStreams,
                          kMaxNumConcurrentEffectStreams,
                          kNumConcurrentCameraStreamsBuckets);
}

void CameraMetricsImpl::SendEffectsError(CameraEffectError error) {
  metrics_lib_->SendEnumToUMA(kCameraEffectsError, error);
}

void CameraMetricsImpl::SendEffectsNumStillShotsTaken(int num_shots) {
  metrics_lib_->SendToUMA(kCameraEffectsNumStillShotsTaken, num_shots,
                          kMinNumShotsTaken, kMaxNumShotsTaken,
                          kNumShotsTakenBuckets);
}

}  // namespace cros

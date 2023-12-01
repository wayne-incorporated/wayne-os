// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "iioservice/daemon/sensor_metrics.h"

#include <algorithm>
#include <memory>
#include <string>
#include <utility>

#include <base/logging.h>
#include <base/stl_util.h>
#include <base/strings/stringprintf.h>
#include <base/strings/string_util.h>
#include <libmems/common_types.h>

#include "iioservice/include/common.h"

namespace iioservice {

namespace {

constexpr base::TimeDelta kMetricsHourlyTimeOnlineSamplePeriod = base::Hours(1);

constexpr int kFrequencyThresholds[] = {0, 10, 50, 100};

// UMA metric names:

// Device Type and Location
constexpr char kSensorUsage[] = "ChromeOS.IioService.SensorUsage.%iHz";

constexpr char kSensorObserver[] = "ChromeOS.IioService.SensorObserver";
constexpr char kSensorObserverOpen[] = "ChromeOS.IioService.SensorObserverOpen";
constexpr char kSensorClientConcurrent[] =
    "ChromeOS.IioService.SensorClientConcurrent";

// UMA histogram ranges:
constexpr int kSensorUsageEnumMax =
    (static_cast<int>(cros::mojom::DeviceType::kMaxValue) + 1) *
    static_cast<int>(SensorMetrics::Location::kMax);

constexpr int kSensorObserverMax = 20;
constexpr int kSensorObserverBuckets = 21;

constexpr int kSensorObserverOpenMax = 100;
constexpr int kSensorObserverOpenBuckets = 50;

constexpr int kSensorClientConcurrentMax = 10;
constexpr int kSensorClientConcurrentBuckets = 11;

bool SensorTypeSupported(cros::mojom::DeviceType type) {
  return type != cros::mojom::DeviceType::NONE &&
         type <= cros::mojom::DeviceType::kMaxValue;
}

SensorMetrics* g_sensor_metrics = nullptr;
}  // namespace

// static
void SensorMetrics::Initialize() {
  if (g_sensor_metrics) {
    LOGF(WARNING) << "SensorMetrics was already initialized";
    return;
  }
  SetInstance(new SensorMetrics(std::make_unique<MetricsLibrary>()));
}

// static
void SensorMetrics::Shutdown() {
  if (!g_sensor_metrics) {
    LOGF(WARNING) << "SensorMetrics::Shutdown() called with null metrics";
    return;
  }
  delete g_sensor_metrics;
  SetInstance(nullptr);
}

// static
SensorMetrics* SensorMetrics::GetInstance() {
  return g_sensor_metrics;
}

SensorMetrics::~SensorMetrics() {
  summarize_timer_.Stop();
}

void SensorMetrics::SetConfigForDevice(
    int iio_device_id,
    const std::vector<cros::mojom::DeviceType>& types,
    const std::string& location) {
  if (device_configs_.find(iio_device_id) != device_configs_.end()) {
    LOGF(WARNING) << "DeviceConfig already set for device with id: "
                  << iio_device_id;
    return;
  }

  auto& config = device_configs_[iio_device_id];
  config.types = types;
  config.location = FilterLocationString(std::string(base::TrimString(
      location, base::StringPiece("\0\n", 2), base::TRIM_TRAILING)));
}

void SensorMetrics::SendSensorUsage(int iio_device_id, double frequency) {
  DCHECK_GE(frequency, 0.0);
  auto it = device_configs_.find(iio_device_id);
  if (it == device_configs_.end())
    return;

  it->second.frequency = frequency;
  it->second.max_frequency = std::max(it->second.max_frequency, frequency);
}

void SensorMetrics::SendSensorObserverOpened() {
  ++enable_sensor_observer_counter_;
  ++sensor_observer_counter_;
  max_sensor_observer_counter_ =
      std::max(max_sensor_observer_counter_, sensor_observer_counter_);
}

void SensorMetrics::SendSensorObserverClosed() {
  DCHECK_GT(sensor_observer_counter_, 0);
  --sensor_observer_counter_;
}

void SensorMetrics::SendSensorClientConnected() {
  ++sensor_client_counter_;
  max_sensor_client_counter_ =
      std::max(max_sensor_client_counter_, sensor_client_counter_);
}

void SensorMetrics::SendSensorClientDisconnected() {
  DCHECK_GT(sensor_client_counter_, 0);
  --sensor_client_counter_;
}

// static
void SensorMetrics::SetInstance(SensorMetrics* sensor_metrics) {
  g_sensor_metrics = sensor_metrics;
}

SensorMetrics::SensorMetrics(
    std::unique_ptr<MetricsLibraryInterface> metrics_lib)
    : metrics_lib_(std::move(metrics_lib)) {
  summarize_timer_.Start(FROM_HERE, kMetricsHourlyTimeOnlineSamplePeriod,
                         base::BindRepeating(&SensorMetrics::SummarizeTime,
                                             base::Unretained(this)));
}

SensorMetrics::Location SensorMetrics::FilterLocationString(
    std::string location) {
  if (location == cros::mojom::kLocationBase)
    return Location::kBase;

  if (location == cros::mojom::kLocationLid)
    return Location::kLid;

  if (location == cros::mojom::kLocationCamera)
    return Location::kCamera;

  return Location::kOthers;
}

void SensorMetrics::SummarizeTime() {
  for (auto& device_config : device_configs_) {
    auto& config = device_config.second;

    for (auto type : config.types) {
      if (!SensorTypeSupported(type))
        continue;

      int device_enum =
          (static_cast<int>(type) - 1) * static_cast<int>(Location::kMax) +
          static_cast<int>(config.location);

      for (int freq_threshold : kFrequencyThresholds) {
        if (config.max_frequency < freq_threshold)
          continue;

        std::string action_name =
            base::StringPrintf(kSensorUsage, freq_threshold);
        metrics_lib_->SendEnumToUMA(action_name, device_enum,
                                    kSensorUsageEnumMax);
      }
    }

    config.max_frequency = config.frequency;
  }

  metrics_lib_->SendToUMA(kSensorObserver, max_sensor_observer_counter_, 1,
                          kSensorObserverMax, kSensorObserverBuckets);
  max_sensor_observer_counter_ = sensor_observer_counter_;

  metrics_lib_->SendToUMA(kSensorObserverOpen, enable_sensor_observer_counter_,
                          1, kSensorObserverOpenMax,
                          kSensorObserverOpenBuckets);

  metrics_lib_->SendToUMA(kSensorClientConcurrent, max_sensor_client_counter_,
                          1, kSensorClientConcurrentMax,
                          kSensorClientConcurrentBuckets);
  max_sensor_client_counter_ = sensor_client_counter_;
}

}  // namespace iioservice

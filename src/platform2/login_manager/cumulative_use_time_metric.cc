// Copyright 2016 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/cumulative_use_time_metric.h"

#include <limits>
#include <utility>

#include <base/bind.h>
#include <base/check.h>
#include <base/files/file_util.h>
#include <base/hash/hash.h>
#include <base/json/json_reader.h>
#include <base/json/json_writer.h>
#include <base/values.h>
#include <metrics/metrics_library.h>

namespace login_manager {

namespace {

// Time interval between cumulative use time metric updates.
const int kMetricsUpdateIntervalSeconds = 5 * 60;

// Used to calculate max size of accumulated seconds per UMA upload, which is
// needed to define histogram parameters.
const int kSecondsInADay = 24 * 60 * 60;

// Constants used for the UMA metric representing the accumulated usage time:
const int kAccumulatedActiveTimeBucketCount = 50;
const int kAccumulatedActiveTimeMin = 1;
// Set to expected max time sent to UMA - usage values are sent only if it is
// detected that day index (amount of time in days since base::Time::UnixEpoch)
// has changed at the time metric value is updated. So max elapsed time since
// last update is seconds in a day + metric update interval.
const int kAccumulatedActiveTimeMax =
    kSecondsInADay + kMetricsUpdateIntervalSeconds;

// This should be enough for writing JSON file containing information about
// usage time metric (can be increased if needed).
const size_t kMetricFileSizeLimit = 1024;

// File extension that should be used for the file backing cumulative use time
// metric.
const char kMetricFileExtension[] = "json";

// Keys for for usage metric parameters in the JSON saved in the metrics file.
const char kOsVersionHashKey[] = "os_version_hash";
const char kStartDayKey[] = "start_day";
const char kElapsedMillisecondsKey[] = "elapsed_milliseconds";

}  // namespace

class CumulativeUseTimeMetric::AccumulatedActiveTime {
 public:
  explicit AccumulatedActiveTime(const base::FilePath& metrics_file);
  AccumulatedActiveTime(const AccumulatedActiveTime&) = delete;
  AccumulatedActiveTime& operator=(const AccumulatedActiveTime&) = delete;

  base::FilePath metrics_file() const { return metrics_file_; }

  base::TimeDelta accumulated_time() const { return accumulated_time_; }

  int start_day() const { return start_day_; }

  // Loads previously persisted metric info from disk and checks if the loaded
  // OS version hash matches |os_version_hash|. If the OS version hashes don't
  // match, resets the accumulated time value and sets the new OS version hash.
  void Init(int os_version_hash);

  // Increases current accumulated usage time by |time|.
  void AddTime(const base::TimeDelta& time);

  // Sets accumulated usage time to |remaining_time|. Sets usage start day to
  // |day|.
  void Reset(const base::TimeDelta& remaining_time, int day);

 private:
  // Methods used to sync usage time parameters to file system.
  bool ReadMetricsFile();
  bool WriteMetricsFile();

  // File path of the file to which current metric info is saved in order to
  // persist metric value across reboots.
  const base::FilePath metrics_file_;

  // Hash of the OS version on which current usage time was accumulated.
  int os_version_hash_{0};

  // Current accumulated usage time.
  base::TimeDelta accumulated_time_;

  // ID of the day on which accumulating current usage time started.
  // The day id is the number of 24-hour periods that passed from
  // Time::UnixEpoch() (though, this class does not directly depend on this).
  int start_day_{0};
};

CumulativeUseTimeMetric::AccumulatedActiveTime::AccumulatedActiveTime(
    const base::FilePath& metrics_file)
    : metrics_file_(metrics_file) {}

void CumulativeUseTimeMetric::AccumulatedActiveTime::Init(int os_version_hash) {
  // Read persisted metric data and then compare read OS version hash to
  // |os_version_hash|. If the hashes do not match (or metric file could not be
  // read), accumulated usage time should be reset - the goal of this is to
  // avoid usage time from before version update to be reported as part of the
  // current version usage.
  if (ReadMetricsFile() && os_version_hash == os_version_hash_)
    return;

  os_version_hash_ = os_version_hash;

  // Note that these have to be reset even if reading metric file failed (as
  // some data might have been partially read).
  Reset(base::TimeDelta(), 0);
}

void CumulativeUseTimeMetric::AccumulatedActiveTime::AddTime(
    const base::TimeDelta& time) {
  if (time.is_zero())
    return;

  accumulated_time_ += time;
  WriteMetricsFile();
}

void CumulativeUseTimeMetric::AccumulatedActiveTime::Reset(
    const base::TimeDelta& remaining_time, int day) {
  accumulated_time_ = remaining_time;
  start_day_ = day;
  WriteMetricsFile();
}

bool CumulativeUseTimeMetric::AccumulatedActiveTime::ReadMetricsFile() {
  std::string data_json;
  if (!base::ReadFileToStringWithMaxSize(metrics_file_, &data_json,
                                         kMetricFileSizeLimit)) {
    return false;
  }

  auto data = base::JSONReader::Read(data_json, base::JSON_PARSE_RFC);
  if (!data) {
    LOG(ERROR) << "Contents of " << metrics_file_.value() << " invalid JSON";
    return false;
  }

  if (!data->is_dict()) {
    LOG(ERROR) << "Content of " << metrics_file_.value() << " not a dictionary";
    return false;
  }

  auto os_version_hash = data->FindIntKey(kOsVersionHashKey);
  if (!os_version_hash) {
    LOG(ERROR) << "OS version hash missing in " << metrics_file_.value();
    return false;
  }

  auto start_day = data->FindIntKey(kStartDayKey);
  if (!start_day) {
    LOG(ERROR) << "Start day missing in " << metrics_file_.value();
    return false;
  }

  auto elapsed_milliseconds = data->FindIntKey(kElapsedMillisecondsKey);
  if (!elapsed_milliseconds) {
    LOG(ERROR) << "Elapsed milliseconds missing in " << metrics_file_.value();
    return false;
  }

  os_version_hash_ = *os_version_hash;
  start_day_ = *start_day;
  accumulated_time_ = base::TimeDelta::FromMilliseconds(*elapsed_milliseconds);
  return true;
}

bool CumulativeUseTimeMetric::AccumulatedActiveTime::WriteMetricsFile() {
  base::Value data(base::Value::Type::DICTIONARY);
  data.SetIntKey(kOsVersionHashKey, os_version_hash_);
  data.SetIntKey(kStartDayKey, start_day_);
  int64_t elapsed_milliseconds = accumulated_time_.InMilliseconds();
  if (elapsed_milliseconds < 0 ||
      elapsed_milliseconds > std::numeric_limits<int>::max()) {
    LOG(ERROR) << "Elapsed milliseconds not in int bounds: "
               << elapsed_milliseconds;
    // Something is wrong here. Reset the stored amount.
    accumulated_time_ = base::TimeDelta();
    elapsed_milliseconds = 0;
  }
  data.SetIntKey(kElapsedMillisecondsKey,
                 static_cast<int>(elapsed_milliseconds));

  std::string data_json;
  if (!base::JSONWriter::Write(data, &data_json)) {
    LOG(ERROR) << "Failed to create JSON string for " << data;
    return false;
  }

  int data_size = data_json.size();
  if (base::WriteFile(metrics_file_, data_json.data(), data_size) !=
      data_size) {
    LOG(ERROR) << "Failed to write metric data to " << metrics_file_.value();
    return false;
  }

  return true;
}

CumulativeUseTimeMetric::CumulativeUseTimeMetric(
    const std::string& metric_name,
    MetricsLibraryInterface* metrics_lib,
    const base::FilePath& metrics_files_dir,
    std::unique_ptr<base::Clock> time_clock,
    std::unique_ptr<base::TickClock> time_tick_clock)
    : metrics_lib_(metrics_lib),
      metric_name_(metric_name),
      accumulated_active_time_(
          new AccumulatedActiveTime(metrics_files_dir.AppendASCII(metric_name_)
                                        .AddExtension(kMetricFileExtension))),
      time_clock_(std::move(time_clock)),
      time_tick_clock_(std::move(time_tick_clock)) {}

CumulativeUseTimeMetric::~CumulativeUseTimeMetric() {}

void CumulativeUseTimeMetric::Init(const std::string& os_version_string) {
  accumulated_active_time_->Init(
      static_cast<int>(base::Hash(os_version_string)));

  // Test if there is any persisted accumulated data that should be sent to UMA.
  IncreaseActiveTimeAndSendUmaIfNeeded(base::TimeDelta());

  initialized_ = true;
}

void CumulativeUseTimeMetric::Start() {
  CHECK(initialized_);

  last_update_time_ = time_tick_clock_->NowTicks();
  IncreaseActiveTimeAndSendUmaIfNeeded(base::TimeDelta());

  // Timer will be stopped when this goes out of scope, so Unretained is safe.
  update_stats_timer_.Start(
      FROM_HERE, base::TimeDelta::FromSeconds(kMetricsUpdateIntervalSeconds),
      base::Bind(&CumulativeUseTimeMetric::UpdateStats,
                 base::Unretained(this)));
}

void CumulativeUseTimeMetric::Stop() {
  CHECK(initialized_);
  if (!last_update_time_.is_null())
    UpdateStats();

  update_stats_timer_.Stop();
  last_update_time_ = base::TimeTicks();
}

base::TimeDelta CumulativeUseTimeMetric::GetMetricsUpdateCycle() const {
  return base::TimeDelta::FromSeconds(kMetricsUpdateIntervalSeconds);
}

base::TimeDelta CumulativeUseTimeMetric::GetMetricsUploadCycle() const {
  return base::TimeDelta::FromSeconds(kSecondsInADay);
}

base::FilePath CumulativeUseTimeMetric::GetMetricsFileForTest() const {
  return accumulated_active_time_->metrics_file();
}

void CumulativeUseTimeMetric::UpdateStats() {
  base::TimeTicks now = time_tick_clock_->NowTicks();
  const base::TimeDelta elapsed_time = now - last_update_time_;
  last_update_time_ = now;

  IncreaseActiveTimeAndSendUmaIfNeeded(elapsed_time);
}

void CumulativeUseTimeMetric::IncreaseActiveTimeAndSendUmaIfNeeded(
    const base::TimeDelta& additional_time) {
  const int day = (time_clock_->Now() - base::Time::UnixEpoch()).InDays();
  // If not enough time has passed since the metric was last sent, just update
  // the time.
  if (accumulated_active_time_->start_day() == day) {
    accumulated_active_time_->AddTime(additional_time);
    return;
  }

  // If metric has not previously been set, do it now, and make sure initial
  // update is not sent to UMA.
  if (accumulated_active_time_->start_day() == 0 &&
      accumulated_active_time_->accumulated_time().is_zero()) {
    accumulated_active_time_->Reset(additional_time, day);
    return;
  }

  base::TimeDelta accumulated_time =
      accumulated_active_time_->accumulated_time() + additional_time;
  int seconds_to_send = accumulated_time.InSeconds();

  // Avoid sending 0 values to UMA.
  if (seconds_to_send != 0) {
    metrics_lib_->SendToUMA(
        metric_name_, seconds_to_send, kAccumulatedActiveTimeMin,
        kAccumulatedActiveTimeMax, kAccumulatedActiveTimeBucketCount);
  }

  // Keep any data unreported due to rounding time to seconds, and set the time
  // accumulation start day to the new value.
  accumulated_active_time_->Reset(
      accumulated_time - base::TimeDelta::FromSeconds(seconds_to_send), day);
}

}  // namespace login_manager

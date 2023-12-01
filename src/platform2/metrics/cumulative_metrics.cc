// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "metrics/cumulative_metrics.h"

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/functional/bind.h>
#include <base/hash/hash.h>
#include <base/logging.h>
#include <base/strings/string_util.h>
#include <base/system/sys_info.h>
#include <memory>
#include <utility>

using base::FilePath;
using base::Time;

namespace chromeos_metrics {
namespace {

constexpr char kValidNameCharacters[] =
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789_.";

}  // namespace

CumulativeMetrics::CumulativeMetrics(const FilePath& backing_dir,
                                     const std::vector<std::string>& names,
                                     base::TimeDelta update_period,
                                     Callback update_callback,
                                     base::TimeDelta accumulation_period,
                                     Callback cycle_end_callback)
    : backing_dir_(backing_dir),
      update_period_(update_period),
      accumulation_period_(accumulation_period) {
  int64_t new_version_hash = 0;

  PersistentInteger persistent_version_hash(backing_dir.Append("version.hash"));
  update_callback_ = std::move(update_callback);
  cycle_end_callback_ = std::move(cycle_end_callback);

  cycle_start_.reset(new PersistentInteger(backing_dir.Append("cycle.start")));
  last_update_time_ = base::TimeTicks::Now();

  // Associate |names| with accumulated values (which may already exist from
  // previous sessions).
  for (const auto& name : names) {
    CHECK(base::ContainsOnlyChars(name, kValidNameCharacters))
        << "bad cumulative metrics name \"" << name << "\"";
    values_.emplace(
        name, std::make_unique<PersistentInteger>(backing_dir.Append(name)));
  }

  // Check version hash.  This only needs to happen at init time because we
  // assume that the OS version cannot be bumped without restarting the daemon.
  std::string version;
  if (base::SysInfo::GetLsbReleaseValue("CHROMEOS_RELEASE_VERSION", &version)) {
    new_version_hash = base::Hash(version);
  } else {
    LOG(ERROR) << "cannot find CHROMEOS_RELEASE_VERSION";
  }

  // Check if current cycle has expired.
  bool new_cycle_has_started = ProcessCycleEnd();

  // On a version change that's not at the end of a cycle, discard the
  // currently accumulating quantities, because the samples would be incorrect.
  // Then start a new cycle.
  int64_t old_version_hash = persistent_version_hash.Get();

  if (old_version_hash != new_version_hash) {
    persistent_version_hash.Set(new_version_hash);
    if (!new_cycle_has_started) {
      // OS version has changed.  Reset accumulators.
      for (const auto& kv : values_) {
        kv.second->GetAndClear();
      }
      // Reset start time.
      base::TimeDelta wall_time = Time::Now() - Time::UnixEpoch();
      cycle_start_->Set(wall_time.InMicroseconds());
    }
  }

  timer_.Start(FROM_HERE, update_period_, this, &CumulativeMetrics::Update);
}

bool CumulativeMetrics::ProcessCycleEnd() {
  base::TimeDelta wall_time = Time::Now() - Time::UnixEpoch();
  base::TimeDelta cycle_start = base::Microseconds(cycle_start_->Get());
  if (wall_time - cycle_start >= accumulation_period_) {
    cycle_start_->Set(wall_time.InMicroseconds());
    return true;
  }
  return false;
}

base::TimeDelta CumulativeMetrics::ActiveTimeSinceLastUpdate() const {
  return base::TimeTicks::Now() - last_update_time_;
}

void CumulativeMetrics::Update() {
  update_callback_.Run(this);

  if (ProcessCycleEnd()) {
    cycle_end_callback_.Run(this);
    for (const auto& kv : values_) {
      kv.second->GetAndClear();
    }
  }

  last_update_time_ = base::TimeTicks::Now();
}

void CumulativeMetrics::PanicFromBadName(const char* action,
                                         const std::string& name) const {
  LOG(FATAL) << "cannot execute action \"" << action << "\": unknown name \""
             << name << "\"";
}

PersistentInteger* CumulativeMetrics::Find(const std::string& name) const {
  const auto iter = values_.find(name);
  if (iter == values_.end())
    return nullptr;
  return iter->second.get();
}

int64_t CumulativeMetrics::Get(const std::string& name) const {
  PersistentInteger* pip = Find(name);
  if (pip != nullptr)
    return pip->Get();
  PanicFromBadName("GET", name);
  return 0;
}

void CumulativeMetrics::Set(const std::string& name, int64_t value) {
  PersistentInteger* pip = Find(name);
  if (pip != nullptr) {
    pip->Set(value);
  } else {
    PanicFromBadName("SET", name);
  }
}

void CumulativeMetrics::Add(const std::string& name, int64_t value) {
  PersistentInteger* pip = Find(name);
  if (pip != nullptr) {
    pip->Add(value);
  } else {
    PanicFromBadName("ADD", name);
  }
}

void CumulativeMetrics::Max(const std::string& name, int64_t value) {
  PersistentInteger* pip = Find(name);
  if (pip != nullptr) {
    pip->Max(value);
  } else {
    PanicFromBadName("MAX", name);
  }
}

int64_t CumulativeMetrics::GetAndClear(const std::string& name) {
  PersistentInteger* pip = Find(name);
  if (pip != nullptr)
    return pip->GetAndClear();
  PanicFromBadName("GETANDCLEAR", name);
  return 0;
}

}  // namespace chromeos_metrics

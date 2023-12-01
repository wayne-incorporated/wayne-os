// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/common/prefs.h"

#include <memory>
#include <set>
#include <utility>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/location.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <base/time/time.h>
#include <cros_config/cros_config.h>

#include "power_manager/common/cros_config_prefs_source.h"
#include "power_manager/common/cros_ec_prefs_source.h"
#include "power_manager/common/file_prefs_store.h"
#include "power_manager/common/prefs_observer.h"

namespace power_manager {

namespace {

// Default directories where read/write and read-only preference files are
// stored.
constexpr char kReadWritePrefsDir[] = "/var/lib/power_manager";
constexpr char kReadOnlyPrefsDir[] = "/usr/share/power_manager";

// Subdirectory within the read-only prefs dir where board-specific prefs are
// stored.
constexpr char kBoardSpecificPrefsSubdir[] = "board_specific";

// Minimum time between batches of prefs being written to disk, in
// milliseconds.
constexpr base::TimeDelta kDefaultWriteInterval = base::Seconds(1);

}  // namespace

Prefs::TestApi::TestApi(Prefs* prefs) : prefs_(prefs) {}

bool Prefs::TestApi::TriggerWriteTimeout() {
  if (!prefs_->write_prefs_timer_.IsRunning())
    return false;

  prefs_->write_prefs_timer_.Stop();
  prefs_->WritePrefs();
  return true;
}

Prefs::Prefs() : write_interval_(kDefaultWriteInterval) {}

Prefs::~Prefs() {
  if (write_prefs_timer_.IsRunning())
    WritePrefs();
}

// static
std::unique_ptr<PrefsStoreInterface> Prefs::GetDefaultStore() {
  return std::make_unique<FilePrefsStore>(base::FilePath(kReadWritePrefsDir));
}

// static
PrefsSourceInterfaceVector Prefs::GetDefaultSources() {
  PrefsSourceInterfaceVector sources;

  const base::FilePath read_only_path(kReadOnlyPrefsDir);

  if (CrosEcPrefsSource::IsSupported())
    sources.emplace_back(new CrosEcPrefsSource);

  sources.emplace_back(
      new CrosConfigPrefsSource(std::make_unique<brillo::CrosConfig>()));

  sources.emplace_back(
      new FilePrefsStore(read_only_path.Append(kBoardSpecificPrefsSubdir)));
  sources.emplace_back(new FilePrefsStore(read_only_path));
  return sources;
}

bool Prefs::Init(std::unique_ptr<PrefsStoreInterface> pref_store,
                 PrefsSourceInterfaceVector pref_sources) {
  pref_store_ = std::move(pref_store);
  pref_sources_ = std::move(pref_sources);
  return pref_store_->Watch(
      base::BindRepeating(&Prefs::HandlePrefChanged, base::Unretained(this)));
}

void Prefs::AddObserver(PrefsObserver* observer) {
  DCHECK(observer);
  observers_.AddObserver(observer);
}

void Prefs::RemoveObserver(PrefsObserver* observer) {
  DCHECK(observer);
  observers_.RemoveObserver(observer);
}

void Prefs::HandlePrefChanged(const std::string& name) {
  // Resist the temptation to erase |name| from |prefs_to_write_| here, as
  // it would cause a race:
  // 1. SetInt64() is called and pref is written to disk.
  // 2. SetInt64() is called and and the new value is queued.
  // 3. HandleFileChanged() is called regarding the initial write.
  for (PrefsObserver& observer : observers_)
    observer.OnPrefChanged(name);
}

void Prefs::GetPrefResults(const std::string& name,
                           bool read_all,
                           std::vector<PrefReadResult>* results) {
  CHECK(results);
  results->clear();

  PrefReadResult result;

  // If there's a queued value that'll be written to the store soon,
  // use it instead of reading from disk.
  bool in_store;
  if (prefs_to_write_.count(name)) {
    base::TrimWhitespaceASCII(prefs_to_write_[name], base::TRIM_TRAILING,
                              &result.value);
    in_store = true;
  } else {
    in_store = pref_store_->ReadPrefString(name, &result.value);
  }
  if (in_store) {
    result.source_desc = pref_store_->GetDescription();
    results->push_back(result);
    if (!read_all) {
      return;
    }
  }

  for (const auto& source : pref_sources_) {
    if (source->ReadPrefString(name, &result.value)) {
      result.source_desc = source->GetDescription();
      results->push_back(result);
      if (!read_all) {
        return;
      }
    }
  }
}

bool Prefs::GetString(const std::string& name, std::string* buf) {
  DCHECK(buf);
  std::vector<PrefReadResult> results;
  GetPrefResults(name, false, &results);
  if (results.empty())
    return false;
  *buf = results[0].value;
  return true;
}

bool Prefs::GetInt64(const std::string& name, int64_t* value) {
  DCHECK(value);
  std::vector<PrefReadResult> results;
  GetPrefResults(name, true, &results);

  for (const auto& result : results) {
    if (base::StringToInt64(result.value, value))
      return true;
    else
      LOG(ERROR) << "Unable to parse int64_t from " << result.source_desc;
  }
  return false;
}

bool Prefs::GetDouble(const std::string& name, double* value) {
  DCHECK(value);
  std::vector<PrefReadResult> results;
  GetPrefResults(name, true, &results);

  for (const auto& result : results) {
    if (base::StringToDouble(result.value, value))
      return true;
    else
      LOG(ERROR) << "Unable to parse double from " << result.source_desc;
  }
  return false;
}

bool Prefs::GetBool(const std::string& name, bool* value) {
  int64_t int_value = 0;
  if (!GetInt64(name, &int_value))
    return false;
  *value = int_value != 0;
  return true;
}

void Prefs::SetString(const std::string& name, const std::string& value) {
  prefs_to_write_[name] = value;
  ScheduleWrite();
}

void Prefs::SetInt64(const std::string& name, int64_t value) {
  prefs_to_write_[name] = base::NumberToString(value);
  ScheduleWrite();
}

void Prefs::SetDouble(const std::string& name, double value) {
  prefs_to_write_[name] = base::NumberToString(value);
  ScheduleWrite();
}

void Prefs::SetBool(const std::string& name, bool value) {
  SetInt64(name, static_cast<int64_t>(value));
}

bool Prefs::GetExternalString(const std::string& path,
                              const std::string& name,
                              std::string* value) {
  DCHECK(value);
  for (const auto& source : pref_sources_) {
    if (source->ReadExternalString(path, name, value))
      return true;
  }
  return false;
}

void Prefs::ScheduleWrite() {
  base::TimeDelta time_since_last_write =
      base::TimeTicks::Now() - last_write_time_;
  if (last_write_time_.is_null() || time_since_last_write >= write_interval_) {
    WritePrefs();
  } else if (!write_prefs_timer_.IsRunning()) {
    write_prefs_timer_.Start(FROM_HERE, write_interval_ - time_since_last_write,
                             this, &Prefs::WritePrefs);
  }
}

void Prefs::WritePrefs() {
  for (const auto& pref_pair : prefs_to_write_) {
    if (!pref_store_->WritePrefString(pref_pair.first, pref_pair.second)) {
      PLOG(ERROR) << "Failed to write to " << pref_store_->GetDescription();
    }
  }
  prefs_to_write_.clear();
  last_write_time_ = base::TimeTicks::Now();
}

}  // namespace power_manager

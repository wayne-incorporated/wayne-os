// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "usb_bouncer/entry_manager.h"

#include <algorithm>
#include <cstdint>
#include <unordered_set>
#include <vector>

#include <base/files/file_enumerator.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <base/time/time.h>
#include <metrics/metrics_library.h>
#include <re2/re2.h>

#include "usb_bouncer/util.h"

using base::TimeDelta;

namespace usb_bouncer {

namespace {

constexpr TimeDelta kModeSwitchThreshold = base::Milliseconds(1000);

constexpr TimeDelta kCleanupThreshold = base::Days(365 / 4);

constexpr char kDevpathRoot[] = "sys/devices";

}  // namespace

EntryManager* EntryManager::GetInstance(
    DevpathToRuleCallback rule_from_devpath) {
  static EntryManager instance("/", GetUserDBDir(), IsLockscreenShown(),
                               IsGuestSession(), rule_from_devpath);
  if (!instance.global_db_.Valid()) {
    LOG(ERROR) << "Failed to open global DB.";
    return nullptr;
  }
  return &instance;
}

bool EntryManager::CreateDefaultGlobalDB() {
  base::FilePath db_path = base::FilePath("/").Append(kDefaultGlobalDir);
  return OpenStateFile(db_path.DirName(), db_path.BaseName().value(),
                       kDefaultDbName, false)
      .is_valid();
}

EntryManager::EntryManager()
    : EntryManager("/",
                   GetUserDBDir(),
                   IsLockscreenShown(),
                   IsGuestSession(),
                   GetRuleFromDevPath) {}

EntryManager::EntryManager(const std::string& root_dir,
                           const base::FilePath& user_db_dir,
                           bool user_db_read_only,
                           bool is_guest_session,
                           DevpathToRuleCallback rule_from_devpath)
    : user_db_read_only_(user_db_read_only),
      is_guest_session_(is_guest_session),
      root_dir_(root_dir),
      rule_from_devpath_(rule_from_devpath),
      global_db_(root_dir_.Append(kDefaultGlobalDir)) {
  if (!user_db_dir.empty()) {
    user_db_ = RuleDBStorage(user_db_dir);
    // In the case of the user_db being created from scratch replace it with the
    // global db which represents the current state of the system.
    if (global_db_.Valid() && user_db_.Valid() &&
        user_db_.Get().entries_size() == 0) {
      user_db_.Get() = global_db_.Get();
    }
  }
}

EntryManager::~EntryManager() {}

bool EntryManager::GarbageCollect() {
  size_t num_removed = GarbageCollectInternal(false);

  if (num_removed == 0)
    return true;

  return PersistChanges();
}

std::string EntryManager::GenerateRules() const {
  // The currently connected devices are allow-listed without filtering.
  std::unordered_set<std::string> rules =
      UniqueRules(global_db_.Get().entries());

  // Include user specific allow-listing rules.
  if (user_db_.Valid()) {
    for (const auto& rule : UniqueRules(user_db_.Get().entries())) {
      if (IncludeRuleAtLockscreen(rule)) {
        rules.insert(rule);
      }
    }
  }

  // Include user specific allow-list rules first so that they take precedence
  // over any block-list rules.
  std::string result = "";
  for (const auto& rule : rules) {
    result.append(rule);
    result.append("\n");
  }

  // Include base set of rules in sorted order.
  std::vector<base::FilePath> rules_d_files;
  base::FileEnumerator file_enumerator(root_dir_.Append(kUsbguardPolicyDir),
                                       false, base::FileEnumerator::FILES);
  base::FilePath next_path;
  while (!(next_path = file_enumerator.Next()).empty()) {
    if (base::EndsWith(next_path.value(), ".conf",
                       base::CompareCase::INSENSITIVE_ASCII)) {
      rules_d_files.push_back(next_path);
    }
  }
  std::sort(rules_d_files.begin(), rules_d_files.end());

  for (const auto& rules_d_file : rules_d_files) {
    std::string contents;
    if (base::ReadFileToString(rules_d_file, &contents)) {
      result.append(contents);
      if (contents.back() != '\n') {
        result.append("\n");
      }
    }
  }
  return result;
}

bool EntryManager::HandleUdev(UdevAction action, const std::string& devpath) {
  if (!ValidateDevPath(devpath)) {
    LOG(ERROR) << "Failed to validate devpath \"" << devpath << "\".";
    return false;
  }

  std::string global_key = Hash(devpath);
  EntryMap* global_map = global_db_.Get().mutable_entries();
  auto global_devpaths = global_db_.Get().mutable_devpaths();

  switch (action) {
    case UdevAction::kAdd: {
      std::string rule = rule_from_devpath_(devpath);
      if (rule.empty() || !ValidateRule(rule)) {
        LOG(ERROR) << "Unable convert devpath to USBGuard allow-list rule.";
        return false;
      }

      RuleEntry& entry = (*global_map)[global_key];
      UpdateTimestamp(entry.mutable_last_used());

      // Handle the case an already connected device has an add event.
      if (!entry.rules().empty()) {
        return PersistChanges();
      }

      // Prepend any mode changes for the same device.
      GarbageCollectInternal(true /*global_only*/);
      const EntryMap& trash = global_db_.Get().trash();
      auto itr = trash.find(global_key);
      if (itr != trash.end()) {
        for (const auto& previous_mode : itr->second.rules()) {
          if (rule != previous_mode) {
            *entry.mutable_rules()->Add() = previous_mode;
          }
        }
      }

      *entry.mutable_rules()->Add() = rule;
      if (user_db_.Valid()) {
        const std::string user_key = Hash(entry.rules());
        const EntryMap& user_entries = user_db_.Get().entries();
        const UMADeviceRecognized new_entry =
            user_entries.find(user_key) == user_entries.end()
                ? UMADeviceRecognized::kUnrecognized
                : UMADeviceRecognized::kRecognized;
        const UMAEventTiming timing = user_db_read_only_
                                          ? UMAEventTiming::kLocked
                                          : UMAEventTiming::kLoggedIn;

        ReportMetrics(devpath, rule, new_entry, timing);

        if (!user_db_read_only_) {
          (*user_db_.Get().mutable_entries())[user_key] = entry;
        }
      }

      (*global_devpaths)[global_key] = devpath;
      return PersistChanges();
    }
    case UdevAction::kRemove: {
      auto itr_devpath = global_devpaths->find(global_key);
      if (itr_devpath != global_devpaths->end()) {
        global_devpaths->erase(itr_devpath);
      }

      // We only remove entries from the global db here because it represents
      // allow-list rules for the current state of the system. These entries
      // cannot be generated on-the-fly because of mode switching devices, and
      // are not removed from the user db because the user db represents devices
      // that have been used some time by a user that should be trusted.
      auto itr = global_map->find(global_key);
      if (itr != global_map->end()) {
        (*global_db_.Get().mutable_trash())[global_key].Swap(&itr->second);
        global_map->erase(itr);
        return PersistChanges();
      }
      return true;
    }
  }
  LOG(ERROR) << "Unrecognized action.";
  return false;
}

bool EntryManager::HandleUserLogin() {
  if (is_guest_session_) {
    // Ignore guest sessions.
    return true;
  }

  if (!user_db_.Valid()) {
    LOG(ERROR) << "Unable to access user db.";
    return false;
  }

  EntryMap* user_entries = user_db_.Get().mutable_entries();

  for (const auto& entry : global_db_.Get().entries()) {
    if (!entry.second.rules().empty()) {
      const std::string user_key = Hash(entry.second.rules());
      const UMADeviceRecognized new_entry =
          user_entries->find(user_key) == user_entries->end()
              ? UMADeviceRecognized::kUnrecognized
              : UMADeviceRecognized::kRecognized;

      const auto& global_key = entry.first;
      const auto& devpaths = global_db_.Get().devpaths();

      const std::string devpath = devpaths.find(global_key) != devpaths.end()
                                      ? devpaths.find(global_key)->second
                                      : std::string();

      for (const auto& rule : entry.second.rules()) {
        ReportMetrics(devpath, rule, new_entry, UMAEventTiming::kLoggedOut);
      }

      (*user_entries)[user_key] = entry.second;
    }
  }
  return PersistChanges();
}

size_t EntryManager::GarbageCollectInternal(bool global_only) {
  size_t num_removed = RemoveEntriesOlderThan(kModeSwitchThreshold,
                                              global_db_.Get().mutable_trash());

  if (!global_only) {
    if (user_db_.Valid()) {
      num_removed += RemoveEntriesOlderThan(kCleanupThreshold,
                                            user_db_.Get().mutable_entries());
    } else {
      LOG(WARNING) << "Unable to access user db.";
    }
  }

  return num_removed;
}

bool EntryManager::ValidateDevPath(const std::string& devpath) {
  if (devpath.empty()) {
    return false;
  }

  base::FilePath normalized_devpath =
      root_dir_.Append("sys").Append(StripLeadingPathSeparators(devpath));

  if (normalized_devpath.ReferencesParent()) {
    LOG(ERROR) << "The path \"" << normalized_devpath.value()
               << "\" has a parent reference.";
    return false;
  }

  if (!root_dir_.Append(kDevpathRoot).IsParent(normalized_devpath)) {
    LOG(ERROR) << "Failed \"" << normalized_devpath.value()
               << "\" is not a devpath.";
    return false;
  }
  return true;
}

bool EntryManager::PersistChanges() {
  bool success = true;
  if (!global_db_.Persist()) {
    LOG(ERROR) << "Failed to writeback global DB.";
    success = false;
  }
  if (user_db_.Valid() && !user_db_.Persist()) {
    LOG(ERROR) << "Failed to writeback user DB.";
    success = false;
  }
  return success;
}

void EntryManager::ReportMetrics(const std::string& devpath,
                                 const std::string& rule,
                                 UMADeviceRecognized new_entry,
                                 UMAEventTiming timing) {
  LOG(INFO) << "Reporting metrics for " << devpath;

  UMALogDeviceAttached(&metrics_, rule, new_entry, timing);

  // Device metrics not supported for empty devpath
  if (devpath.empty())
    return;

  base::FilePath normalized_devpath =
      root_dir_.Append("sys").Append(StripLeadingPathSeparators(devpath));

  // Report further metrics only for external USB devices. We cannot distinguish
  // external devices on Flex, so exclude it from reporting further metrics.
  if (IsFlexBoard() || !IsExternalDevice(normalized_devpath))
    return;

  UMALogExternalDeviceAttached(&metrics_, rule, new_entry, timing,
                               GetPortType(normalized_devpath),
                               GetDeviceSpeed(normalized_devpath));

  StructuredMetricsExternalDeviceAttached(
      GetVendorId(normalized_devpath), GetVendorName(normalized_devpath),
      GetProductId(normalized_devpath), GetProductName(normalized_devpath),
      GetDeviceClass(normalized_devpath),
      GetInterfaceClass(normalized_devpath));
}

}  // namespace usb_bouncer

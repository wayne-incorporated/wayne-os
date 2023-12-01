// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/gsc_collector_base.h"

#include <string>
#include <vector>

#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <brillo/strings/string_utils.h>

#include "crash-reporter/constants.h"
#include "crash-reporter/paths.h"

using base::FilePath;

namespace {

// "0x0A" is the event ID for crashes in the GSC flash log.
// event::Entry::Crash defined in src/platform/ti50/common/libs/event/src/lib.rs
const char kGSCToolFlogCrashEventMarker[] = ": 0a";
constexpr char kGscExecName[] = "google_security_chip";
const char kSignatureKey[] = "sig";

// Reserve 0xFFFFFFFF as an invalid crash ID.
// Assuming a GSC can crash at most 1/second, it will take 136.2 years to hit
// this value, so this is likely a safe limit.
constexpr uint32_t kInvalidCrashLogID = 0xFFFFFFFF;

}  // namespace

GscCollectorBase::GscCollectorBase()
    : CrashCollector("gsc"),
      crash_detected_(false),
      latest_crash_id_(kInvalidCrashLogID),
      prev_crash_id_(kInvalidCrashLogID) {}

// Return |true| if we successfully read the crash ID, |false| otherwise.
GscCollectorBase::Status GscCollectorBase::GetCrashId(
    const std::string& flog_line, uint32_t* crash_id) {
  // The FLOG line should look like:
  //    Mar 20 23 15:13:11 : 0a 01 00 00 00
  //    ^^^^^^^^^^^^^^^^^^   ^^ ^^^^^^^^^^^
  //    |                    |  |
  //    |                    |  - Little-Endian Crash Number (ID)
  //    |                    - Crash Identifier
  //    - Date/Time Crash Occurred
  // Split the line by the identifier, meaning the second piece is the crash
  // number.
  std::vector<std::string> event_strings = brillo::string_utils::Split(
      flog_line, kGSCToolFlogCrashEventMarker, true, true);
  if (event_strings.size() != 2) {
    LOG(ERROR) << "Invalid flog line format: '" << flog_line << "'";
    return Status::Fail;
  }

  // The crash number is a little-endian 32b value. We need to byte swap the
  // string back to build up the correct 32b value.
  // 1. Get the 4 byte strings.
  std::vector<std::string> crash_number_parts =
      brillo::string_utils::Split(event_strings[1], " ", true, true);
  if (crash_number_parts.size() != 4) {
    LOG(ERROR) << "Invalid crash number format: '" << event_strings[1]
               << "', crash_number_parts.size() = "
               << crash_number_parts.size();
    return Status::Fail;
  }
  // 2. Perform the byte swapping by building up the string in reverse order.
  std::string crash_num_string = "";
  for (auto rev_iter = crash_number_parts.rbegin();
       rev_iter != crash_number_parts.rend(); ++rev_iter) {
    if ((*rev_iter).length() != 2) {
      LOG(ERROR) << "Invalid crash number part: '" << *rev_iter
                 << "', (*rev_iter).length() = " << (*rev_iter).length();
      return Status::Fail;
    }
    crash_num_string.append(*rev_iter);
  }

  if (!base::HexStringToUInt(crash_num_string, crash_id)) {
    LOG(ERROR) << "Invalid crash_num_string string: '" << crash_num_string
               << "'";
    return Status::Fail;
  }

  return Status::Success;
}

GscCollectorBase::Status GscCollectorBase::ParseGscFlog(
    const std::string& gsctool_flog) {
  std::vector<std::string> flog_strings =
      brillo::string_utils::Split(gsctool_flog, "\n", true, true);

  for (const std::string& flog_line : flog_strings) {
    if (flog_line.find(kGSCToolFlogCrashEventMarker) != std::string::npos) {
      LOG(INFO) << "Found GSC crash: " << flog_line;
      crash_detected_ = true;

      // Get the crash ID. We only care about the last crash in the flog, since
      // that value is what's checked against whether we generate a crash report
      // or not, and is the only crash the GSC will retain the data for. While
      // it's a bit wasteful to parse all the crash entries to get the crash ID,
      // it's simpler to implement and debug. We also don't expect many crashes
      // in the first place (ideally none), so overwriting the value each time
      // shouldn't add any measurable overhead.
      if (GetCrashId(flog_line, &latest_crash_id_) != Status::Success) {
        return Status::Fail;
      }
    }
  }

  return Status::Success;
}

GscCollectorBase::Status GscCollectorBase::GetPreviousGscCrashId(
    uint32_t* crash_id) {
  if (base::PathExists(paths::Get(paths::kGscPrevCrashLogIdPath))) {
    std::string gsc_prev_crash_log_id_string;

    if (!base::ReadFileToString(paths::Get(paths::kGscPrevCrashLogIdPath),
                                &gsc_prev_crash_log_id_string)) {
      LOG(ERROR) << "Unable to read "
                 << paths::Get(paths::kGscPrevCrashLogIdPath).value();
      return Status::Fail;
    }

    if (!base::StringToUint(
            base::CollapseWhitespaceASCII(gsc_prev_crash_log_id_string, true),
            crash_id)) {
      LOG(ERROR) << "Invalid previous GSC crash ID: '"
                 << gsc_prev_crash_log_id_string << "'";
      return Status::Fail;
    }
  } else {
    // File doesn't exist, so there are no previous GSC crashes. Return invalid
    // to indicate we successfully found nothing.
    *crash_id = kInvalidCrashLogID;
  }

  return Status::Success;
}

GscCollectorBase::Status GscCollectorBase::PersistGscCrashId(
    uint32_t crash_id) {
  if (!base::WriteFile(paths::Get(paths::kGscPrevCrashLogIdPath),
                       base::NumberToString(crash_id))) {
    LOG(ERROR) << "Unable to write "
               << paths::Get(paths::kGscPrevCrashLogIdPath).value();
    return Status::Fail;
  }

  return Status::Success;
}

bool GscCollectorBase::Collect(bool use_saved_lsb) {
  SetUseSavedLsb(use_saved_lsb);

  std::string output;

  if (GetGscFlog(&output) != Status::Success) {
    LOG(INFO) << "Failed to get the GSC flog output.";
    return false;
  }

  if (ParseGscFlog(output) != Status::Success) {
    LOG(INFO) << "Failed to parse the GSC flog output.";
    return false;
  }

  if (!crash_detected_) {
    LOG(INFO) << "No GSC crash detected.";
    return false;
  }

  if (GetPreviousGscCrashId(&prev_crash_id_) != Status::Success) {
    LOG(INFO) << "Failed to get the previous GSC crash log ID.";
    return false;
  }

  if (prev_crash_id_ != kInvalidCrashLogID &&
      prev_crash_id_ >= latest_crash_id_) {
    LOG(INFO) << "Latest crash ID (" << latest_crash_id_
              << ") is not more recent than previously reported crash ID ("
              << prev_crash_id_ << ")";
    return false;
  }

  LOG(INFO) << "Generating crash report. Previously reported crash ID: "
            << prev_crash_id_ << ", Latest crash ID: " << latest_crash_id_;

  FilePath root_crash_directory;
  if (!GetCreatedCrashDirectoryByEuid(constants::kRootUid,
                                      &root_crash_directory, nullptr)) {
    LOG(ERROR) << "Failed to create crash directory.";
    return false;
  }

  // Persist the latest crash ID, so we only report it once.
  // We do this before calling GetLogContents(), since crash_reporter_logs.conf
  // needs the crash log ID to pass to `gsctool --clog`, and reading the ID from
  // the persistent file saves us from the complexity of parsing the ID from the
  // `gsctool --flog` output (essentially re-implementing
  // GetPreviousGscCrashId() with shell commands).
  // NOTE: This should be the final check we make that can return |false|. Once
  // this value is recorded, the GSC crash will never have a crash report
  // generated for it every again.
  if (PersistGscCrashId(latest_crash_id_) != Status::Success) {
    // Don't generate a crash report when we fail to persist this crash ID,
    // since the next boot will attempt to upload the same crash ID (and
    // presumably continue failing to persist, resulting in infinite crash
    // reports for the same ID).
    LOG(INFO) << "Failed to persist latest GSC crash ID.";
    return false;
  }

  std::string dump_basename =
      FormatDumpBasename(kGscExecName, time(nullptr), 0);
  FilePath gsc_crash_path =
      GetCrashPath(root_crash_directory, dump_basename, "log.gz");

  // TODO(b/265310865): Create unique GSC crash signatures based on the crash
  // data.
  AddCrashMetaData(kSignatureKey, kGscExecName);

  // Get the log contents, compress, and attach to crash report.
  if (!GetLogContents(log_config_path_, kGscExecName, gsc_crash_path)) {
    // Don't return if we fail here. We still want upload whatever we were able
    // output to syslog, as well as give some indication to developers that the
    // GSC is crashing at all.
    LOG(ERROR) << "Failed to collect GSC logs.";
  }

  // Create meta file with GSC dump info and finish up.
  FinishCrash(GetCrashPath(root_crash_directory, dump_basename, "meta"),
              kGscExecName, gsc_crash_path.BaseName().value());

  LOG(INFO) << "Stored GSC crash to " << gsc_crash_path.value();

  return true;
}

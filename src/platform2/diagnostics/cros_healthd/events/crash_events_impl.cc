// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/events/crash_events.h"

#include <iterator>
#include <limits>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/json/json_reader.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/timer/timer.h>

#include "diagnostics/cros_healthd/system/context.h"

namespace diagnostics {
namespace mojom = ash::cros_healthd::mojom;

namespace {

// The period of collecting crashes.
constexpr auto kPeriod = base::Minutes(20);

// Parses a single log entry and returns the result.
mojom::CrashEventInfoPtr ParseUploadsLogEntry(const std::string& line,
                                              bool is_uploaded,
                                              base::Time creation_time,
                                              uint64_t offset) {
  // The SplitString call guarantees that line can't be empty.
  DCHECK(!line.empty());

  const auto json = base::JSONReader::Read(line);
  if (!json.has_value() || !json->is_dict()) {
    LOG(ERROR) << "Invalid JSON in crash uploads log: " << line;
    return nullptr;
  }

  // Extract relevant fields.
  auto result = mojom::CrashEventInfo::New();
  const auto& json_dict = json->GetDict();

  // crash_type
  result->crash_type = mojom::CrashEventInfo::CrashType::kUnknown;
  if (const auto* crash_type = json_dict.FindString("fatal_crash_type");
      crash_type != nullptr) {
    if (*crash_type == "kernel") {
      result->crash_type = mojom::CrashEventInfo::CrashType::kKernel;
    } else if (*crash_type == "ec") {
      result->crash_type =
          mojom::CrashEventInfo::CrashType::kEmbeddedController;
    }
  }

  // crash_report_id
  if (is_uploaded) {
    if (const auto* crash_report_id = json_dict.FindString("upload_id");
        crash_report_id != nullptr) {
      result->upload_info =
          mojom::CrashUploadInfo::New(*crash_report_id, creation_time, offset);
    } else {
      LOG(ERROR) << "Crash report ID is not found while the crash has been "
                    "uploaded: "
                 << line;
      return nullptr;
    }
  }

  // local_id
  if (const auto* local_id = json_dict.FindString("path_hash");
      local_id != nullptr) {
    result->local_id = *local_id;
  } else {
    LOG(ERROR) << "Local ID not found: " << line;
    return nullptr;
  }

  // capture_time
  const auto* capture_time_string = json_dict.FindString("capture_time");
  if (capture_time_string == nullptr) {
    LOG(ERROR) << "Capture time not found: " << line;
    return nullptr;
  }
  double capture_time_double;
  if (!base::StringToDouble(*capture_time_string, &capture_time_double)) {
    LOG(ERROR) << "Invalid capture time: " << line;
    return nullptr;
  }
  result->capture_time = base::Time::FromDoubleT(capture_time_double);

  return result;
}
}  // namespace

CrashEvents::CrashEvents(Context* context) : context_(context) {
  CHECK(context_);
  timer_.Start(FROM_HERE, kPeriod,
               base::BindRepeating(&CrashEvents::CollectCrashes,
                                   weak_ptr_factory_.GetWeakPtr()));
}

CrashEvents::~CrashEvents() = default;

void CrashEvents::AddObserver(
    mojo::PendingRemote<mojom::EventObserver> observer) {
  new_observers_.push_back(observers_.Add(std::move(observer)));
  timer_.Reset();
  // Noticeably, there's a very low chance that this may be called during which
  // the followup tasks of another `CrashEvents::CollectCrashes` call haven't
  // been done yet. The results won't be affected in this case.
  CrashEvents::CollectCrashes();
}

void CrashEvents::CollectCrashes() {
  // No subscriber, no need to collect any crash events.
  if (observers_.empty()) {
    return;
  }

  // Emit all past crashes to new subscribers.
  for (const auto observer_id : new_observers_) {
    auto* observer = observers_.Get(observer_id);
    if (observer == nullptr) {
      // The observer is no longer in the observer remote set, likely it has
      // disconnected already.
      continue;
    }
    for (const auto& [/* unused */ local_id, crash] :
         past_unuploaded_crashes_) {
      observer->OnEvent(mojom::EventInfo::NewCrashEventInfo(crash.Clone()));
    }
    for (const auto& crash : past_uploaded_crashes_) {
      observer->OnEvent(mojom::EventInfo::NewCrashEventInfo(crash.Clone()));
    }
  }
  new_observers_.clear();

  // Get unuploaded crashes before getting uploaded crashes. In this way, if an
  // unuploaded crash is uploaded after we have collected unuploaded crashes and
  // before we have collected uploaded crashes, the subscriber would be less
  // confused because it would receive the same crash as unuploaded before as
  // uploaded.
  context_->executor()->FetchCrashFromCrashSender(
      base::BindOnce(&CrashEvents::HandleUnuploadedCrashCrashSenderResult,
                     weak_ptr_factory_.GetWeakPtr()));
}

void CrashEvents::StartGettingUploadedCrashes() {
  // Get uploaded crashes. Roughly speaking, first get file info. In the file
  // info result callback, collect the crashes from uploads.log. Then in the
  // reading file result callback, it emits crashes to the subscribers.
  context_->executor()->GetFileInfo(
      mojom::Executor::File::kCrashLog,
      base::BindOnce(&CrashEvents::HandleUploadedCrashGetFileInfoResult,
                     weak_ptr_factory_.GetWeakPtr()));
}

void CrashEvents::HandleUnuploadedCrashCrashSenderResult(
    const mojom::ExecutedProcessResultPtr crash_sender_result) {
  if (crash_sender_result->return_code != 0) {
    LOG(ERROR) << "crash_sender failed with exit code "
               << crash_sender_result->return_code << ": "
               << crash_sender_result->err.substr(0u, 30u);
    // crash_sender failure shouldn't stop healthD from emitting uploaded
    // crashes.
    StartGettingUploadedCrashes();
    return;
  }

  auto results =
      ParseUploadsLog(crash_sender_result->out, /*is_uploaded=*/false,
                      /*creation_time=ignored*/ base::Time(),
                      /*init_offset=ignored*/ 0u);

  for (const auto& result : results) {
    if (past_unuploaded_crashes_.count(result->local_id) > 0) {
      continue;
    }
    for (auto& observer : observers_) {
      observer->OnEvent(mojom::EventInfo::NewCrashEventInfo(result.Clone()));
    }
  }

  // Since crashes that do not appear as unuploaded crashes anymore should have
  // become uploaded crashes, clear the past unuploaded crashes and
  // reconstruct them here.
  past_unuploaded_crashes_.clear();
  for (auto& result : results) {
    past_unuploaded_crashes_.insert(
        std::make_pair(result->local_id, std::move(result)));
  }

  StartGettingUploadedCrashes();
}

void CrashEvents::HandleUploadedCrashGetFileInfoResult(
    const mojom::FileInfoPtr file_info) {
  if (file_info.is_null()) {
    LOG(ERROR) << "Failed to get info from uploads.log.";
    return;
  }

  if (file_info->creation_time != uploads_log_info_.creation_time) {
    // New log file.
    //
    // Why do we keep past crashes here?
    // ---------------------------------
    //
    // New log file shouldn't be created within one session, as the only normal
    // (i.e., system not tampered) way to clean uploads.log is powerwash.
    //
    // In case of a future uploads.log cleanup behavior change, we document some
    // of the considerations why we chose to keep all past crash events here. If
    // uploads.log is cleared within one session and past crashes are cleared,
    // new subscribers would not receive the same crashes as the other
    // subscribers do, which is not desirable.
    //
    // However, if uploads.log is cleared within one session and the past events
    // are not cleared (as in this implementation), the following two scenarios
    // would give subscribers different crash events:
    //
    //  subscriber X added (receive all uploaded crashes) -> uploads.log cleared
    //   -> subscriber Y added (receive all uploaded crashes)
    //  [no subscribers] -> uploads.log cleared
    //   -> subscriber Y added(receive no uploaded crashes)
    //
    // To some degree, keeping the past events is less evil here. Detailed
    // considerations can be made when the uploads.log behavior is truly
    // changed.
    //
    // Why do we not check that creation_time is later than the current?
    // -----------------------------------------------------------------
    //
    // If the creation time is earlier than the current, it implies that the log
    // file has been recreated when the system's clock was abnormal. In this
    // case, what's important here is to know the file has been recreated, not
    // the actual creation time.
    uploads_log_info_.byte_location = 0u;
    uploads_log_info_.offset = 0u;
    uploads_log_info_.creation_time = file_info->creation_time;
  }

  context_->executor()->ReadFilePart(
      mojom::Executor::File::kCrashLog,
      /*begin=*/uploads_log_info_.byte_location,
      /*size=*/std::nullopt,
      base::BindOnce(&CrashEvents::HandleUploadedCrashReadFileResult,
                     weak_ptr_factory_.GetWeakPtr(), file_info->creation_time));
}

void CrashEvents::HandleUploadedCrashReadFileResult(
    base::Time creation_time, const std::optional<std::string>& log) {
  if (!log.has_value()) {
    LOG(ERROR) << "Failed to read uploads.log.";
    return;
  }

  if (log.value().empty()) {
    // No new log content was added to uploads.log since last read.
    return;
  }

  uint64_t parsed_bytes;
  std::vector<mojom::CrashEventInfoPtr> results =
      ParseUploadsLog(log.value(), /*is_uploaded=*/true,
                      /*creation_time=*/uploads_log_info_.creation_time,
                      /*init_offset=*/uploads_log_info_.offset,
                      /*parsed_bytes=*/&parsed_bytes);

  if (results.empty()) {
    // No valid log lines. One possibility is that a new line is partly written
    // and isn't valid yet. Be conservative and don't modify uploads_log_info_
    // and do anything else in this case.
    return;
  }

  // Rarely, we may have read uploads.log when it is being written. In this
  // case, the last line may contain only part of an otherwise valid line. To
  // ensure this last line would be parsed next time, we make sure byte_location
  // only advances to the end of the final valid log line.
  uploads_log_info_.byte_location += parsed_bytes;
  uploads_log_info_.offset += results.size();

  for (const auto& result : results) {
    for (auto& observer : observers_) {
      observer->OnEvent(mojom::EventInfo::NewCrashEventInfo(result.Clone()));
    }
  }

  past_uploaded_crashes_.insert(past_uploaded_crashes_.end(),
                                std::make_move_iterator(results.begin()),
                                std::make_move_iterator(results.end()));
}

std::vector<mojom::CrashEventInfoPtr> ParseUploadsLog(base::StringPiece log,
                                                      bool is_uploaded,
                                                      base::Time creation_time,
                                                      uint64_t init_offset,
                                                      uint64_t* parsed_bytes) {
  if (parsed_bytes) {
    *parsed_bytes = log.size();
  }
  std::vector<mojom::CrashEventInfoPtr> result;
  // Using whitespace (instead of line breakers) as the delimiter here is a
  // bit odd, but this is what `TextLogUploadList::SplitIntoLines` does.
  const auto log_lines =
      base::SplitString(log, base::kWhitespaceASCII, base::KEEP_WHITESPACE,
                        base::SPLIT_WANT_NONEMPTY);
  for (size_t i = 0; i < log_lines.size(); ++i) {
    const auto& line = log_lines[i];
    // each line is a log entry, from which we can extract crash info.
    auto log_entry = ParseUploadsLogEntry(line, is_uploaded, creation_time,
                                          init_offset + result.size());
    if (log_entry.is_null()) {
      // The last log line requires some special processing for parsed_bytes.
      if (i == log_lines.size() - 1 && parsed_bytes &&
          !base::IsAsciiWhitespace(log.back())) {
        CHECK_GE(log.size(), line.size());
        *parsed_bytes = log.size() - line.size();
      }
      continue;
    }
    result.push_back(std::move(log_entry));
  }

  return result;
}
}  // namespace diagnostics

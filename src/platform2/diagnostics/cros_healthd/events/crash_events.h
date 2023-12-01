// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_EVENTS_CRASH_EVENTS_H_
#define DIAGNOSTICS_CROS_HEALTHD_EVENTS_CRASH_EVENTS_H_

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include <base/strings/string_piece.h>
#include <base/time/time.h>
#include <base/timer/timer.h>
#include <mojo/public/cpp/bindings/pending_remote.h>
#include <mojo/public/cpp/bindings/remote_set.h>

#include "diagnostics/cros_healthd/mojom/executor.mojom.h"
#include "diagnostics/mojom/public/cros_healthd_events.mojom.h"

namespace diagnostics {

class Context;

// Interface that allows clients to subscribe to crash events.
//
// To manually test crash events on a DUT, first generate some unuploaded and
// uploaded crashes. This can be done by:
//   (DUT) $ metrics_client -C  # Consent for crash reporting.
//   (DUT) $ sleep 100&
//   (DUT) $ kill -SEGV $!  # Generating unuploaded crash
//   (DUT) $ crash_sender --dev --max_spread_time=0  # Convert to uploaded crash
// Now, generate one more unuploaded crash as the previous one have been
// deleted.
//   (DUT) $ sleep 100&
//   (DUT) $ kill -SEGV $!
//
// Subscribe to crash events with cros-health-tool:
//   (DUT) $ cros-health-tool events --category=crash --length_seconds=400
//
// Inspect the output and the logs of cros_healthd.
//
// You may also want to change the timer period to a smaller time for testing
// purposes (kPeriod in crash_events_impl.cc). Also check out
// https://www.chromium.org/chromium-os/packages/crash-reporting/faq/#will-a-developers-build-image-upload-crash-reports
// for reference.
class CrashEvents final {
 public:
  explicit CrashEvents(Context* context);
  CrashEvents(const CrashEvents&) = delete;
  CrashEvents& operator=(const CrashEvents&) = delete;
  ~CrashEvents();

  void AddObserver(
      mojo::PendingRemote<ash::cros_healthd::mojom::EventObserver> observer);

 private:
  // Information related to uploads.log.
  struct UploadsLogInfo {
    // Creation time of uploads.log.
    base::Time creation_time = base::Time();
    // The location of uploads.log that was read last time.
    uint64_t byte_location = 0u;
    // The number of valid logs that have been read from uploads.log.
    uint64_t offset = 0u;
  };

  // Collects crashes and emits subscribers crash events.
  void CollectCrashes();

  // Starts getting uploaded crashes.
  void StartGettingUploadedCrashes();

  // Handles the output from crash_sender.
  void HandleUnuploadedCrashCrashSenderResult(
      const ash::cros_healthd::mojom::ExecutedProcessResultPtr
          crash_sender_result);

  // Handles the file creation time once finish getting the info of uploads.log.
  void HandleUploadedCrashGetFileInfoResult(
      const ash::cros_healthd::mojom::FileInfoPtr file_info);

  // Handles the file content once finish reading uploads.log.
  void HandleUploadedCrashReadFileResult(base::Time creation_time,
                                         const std::optional<std::string>& log);

  // Information related to uploads.log.
  UploadsLogInfo uploads_log_info_;

  // Uploaded crashes in the past. Would be sent to any new subscribers.
  std::vector<ash::cros_healthd::mojom::CrashEventInfoPtr>
      past_uploaded_crashes_;

  // Unuploaded crashes in the past. Would be sent to any new subscribers.
  std::unordered_map</*local id*/ std::string,
                     ash::cros_healthd::mojom::CrashEventInfoPtr>
      past_unuploaded_crashes_;

  // The collection of all new observers that haven't received past crashes
  // yet.
  std::vector<mojo::RemoteSetElementId> new_observers_;

  // Timer for invoking `CollectCrashes` periodically.
  base::RepeatingTimer timer_;

  // Each observer in |observers_| will be notified of any crash event
  // in the ash::cros_healthd::mojom::EventObserver interface. The
  // RemoteSet manages the lifetime of the endpoints, which are
  // automatically destroyed and removed when the pipe they are bound to
  // is destroyed.
  mojo::RemoteSet<ash::cros_healthd::mojom::EventObserver> observers_;

  // Unowned pointer. Should outlive this instance.
  Context* const context_ = nullptr;

  base::WeakPtrFactory<CrashEvents> weak_ptr_factory_{this};
};

// Parses log string as the same format used in /var/log/chrome/Crash
// Reports/uploads.log and returns the result. Performs a functionality similar
// to `TextLogUploadList::TryParseJsonLogEntry` in Chromium. If there are any
// invalid log entries, they would be logged and all of the rest (i.e., the
// valid log entries) are returned.
//
// Params:
//   - log: The content of the the log string to be parsed.
//   - is_uploaded: Whether the log is taken from uploads.log.
//   - creation_time: The creation time of uploads.log. Used only when
//     is_uploaded is true.
//   - init_offset: The initial offset of the log string in uploads.log. Used
//     only when is_uploaded is true.
//   - parsed_bytes: Optional. Ignored if null. When not null, and the final
//     line is complete, it is set to the size of `log`. Otherwise, it is set to
//     the number of bytes parsed until the beginning of the final line because
//     the final line is incomplete. For this function, any whitespace character
//     breaks a line. A line is said to be complete if it ends with a whitespace
//     character. This is useful for continuing parsing in case when the final
//     line of uploads.log is partly written.
//
// Exported for test reasons.
std::vector<ash::cros_healthd::mojom::CrashEventInfoPtr> ParseUploadsLog(
    base::StringPiece log,
    bool is_uploaded,
    base::Time creation_time,
    uint64_t init_offset,
    uint64_t* parsed_bytes = nullptr);
}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_EVENTS_CRASH_EVENTS_H_

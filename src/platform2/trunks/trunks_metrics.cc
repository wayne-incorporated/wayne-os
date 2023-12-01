// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "trunks/trunks_metrics.h"

#include <string>

#include <base/check_op.h>
#include <base/logging.h>
#include <base/time/time.h>

#include "trunks/error_codes.h"

extern "C" {
#include <sys/sysinfo.h>
}

namespace trunks {

namespace {

constexpr char kFirstTimeoutWritingCommand[] =
    "Platform.Trunks.FirstTimeoutWritingCommand";
constexpr char kFirstTimeoutWritingTime[] =
    "Platform.Trunks.FirstTimeoutWritingTime";

constexpr char kFirstTimeoutReadingCommand[] =
    "Platform.Trunks.FirstTimeoutReadingCommand";
constexpr char kFirstTimeoutReadingTime[] =
    "Platform.Trunks.FirstTimeoutReadingTime";

constexpr char kRecoverableWriteErrorNo[] =
    "Platform.Trunks.RecoverableWriteErrorNo";
constexpr char kUnrecoverableWriteErrorNo[] =
    "Platform.Trunks.UnrecoverableWriteErrorNo";
constexpr char kTransitionedWriteErrorNo[] =
    "Platform.Trunks.TransitionedWriteErrorNo";

constexpr char kTpmErrorCode[] = "Platform.Trunks.TpmErrorCode";

}  // namespace

bool TrunksMetrics::ReportTpmHandleTimeoutCommandAndTime(int error_result,
                                                         TPM_CC command_code) {
  std::string command_metrics, time_metrics;
  switch (error_result) {
    case TRUNKS_RC_WRITE_ERROR:
      command_metrics = kFirstTimeoutWritingCommand;
      time_metrics = kFirstTimeoutWritingTime;
      break;
    case TRUNKS_RC_READ_ERROR:
      command_metrics = kFirstTimeoutReadingCommand;
      time_metrics = kFirstTimeoutReadingTime;
      break;
    default:
      LOG(INFO) << "Reporting unexpected error: " << error_result;
      return false;
  }

  metrics_library_.SendSparseToUMA(command_metrics,
                                   static_cast<int>(command_code));
  struct sysinfo info;
  if (sysinfo(&info) == 0) {
    constexpr int kMinUptimeInSeconds = 1;
    constexpr int kMaxUptimeInSeconds = 7 * 24 * 60 * 60;  // 1 week
    constexpr int kNumUptimeBuckets = 50;

    metrics_library_.SendToUMA(time_metrics, info.uptime, kMinUptimeInSeconds,
                               kMaxUptimeInSeconds, kNumUptimeBuckets);
  } else {
    PLOG(WARNING) << "Error getting system uptime";
  }
  return true;
}

void TrunksMetrics::ReportTpmErrorCode(TPM_RC error_code) {
  metrics_library_.SendSparseToUMA(kTpmErrorCode, static_cast<int>(error_code));
}

void TrunksMetrics::ReportWriteErrorNo(int prev, int next) {
  // Don't record any UMA if the state is good or just goes from good to bad.
  if (prev <= 0) {
    return;
  }

  static bool has_error_transitioned = false;
  if (next <= 0) {
    metrics_library_.SendSparseToUMA(kRecoverableWriteErrorNo, prev);
  } else if (prev == next) {
    // It is possible for the error to change, and the new error keeps
    // happending. In that case, it is not conclusive if the error is
    // unrecoverable until the next process cycle.
    if (has_error_transitioned) {
      return;
    }
    // Since the status gets stuck in a single error, the same call occurs for
    // every single TPM commands, need a call-once guard for this case.
    static bool call_once = [&]() {
      this->metrics_library_.SendSparseToUMA(kUnrecoverableWriteErrorNo, prev);
      return true;
    }();
    (void)(call_once);
  } else {
    metrics_library_.SendSparseToUMA(kTransitionedWriteErrorNo, prev);
    has_error_transitioned = true;
  }
}

}  // namespace trunks

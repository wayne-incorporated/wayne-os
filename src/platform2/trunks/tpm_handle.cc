// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "trunks/tpm_handle.h"

#include <fcntl.h>
#include <optional>
#include <unistd.h>
#include <utility>

#include <base/check_op.h>
#include <base/functional/callback.h>
#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>
#include <base/threading/platform_thread.h>
#include <base/time/time.h>

#include "trunks/command_codes.h"
#include "trunks/error_codes.h"
#include "trunks/resilience/write_error_tracker.h"
#include "trunks/tpm_generated.h"

namespace trunks {

namespace {

const char kTpmDevice[] = "/dev/tpm0";
const uint32_t kTpmBufferSize = 4096;
const int kInvalidFileDescriptor = -1;

// Retry parameters for opening /dev/tpm0.
// How long do we wait after the first try?
constexpr base::TimeDelta kInitialRetry = base::Seconds(0.1);
// When we retry the next time, how much longer do we wait?
constexpr double kRetryMultiplier = 2.0;
// How many times to retry?
constexpr int kMaxRetry = 5;
// Total of 4 wait time between 5 retries.
// sum 0.1*2^k for k = 0 to 3 = 1.5s
// Note that if this period is not enough, upstart will still respawn trunksd
// after it all fall through.

int MaskEINTR(int err) {
  return (err == EINTR) ? 0 : err;
}

}  // namespace

TpmHandle::TpmHandle(WriteErrorTracker& write_error_tracker)
    : fd_(kInvalidFileDescriptor), write_error_tracker_(write_error_tracker) {}

TpmHandle::~TpmHandle() {
  int result = IGNORE_EINTR(close(fd_));
  if (result == -1) {
    PLOG(ERROR) << "TPM: couldn't close " << kTpmDevice;
  }
  LOG(INFO) << "TPM: " << kTpmDevice << " closed successfully";
}

bool TpmHandle::Init() {
  if (fd_ != kInvalidFileDescriptor) {
    VLOG(1) << "Tpm already initialized.";
    return true;
  }
  base::TimeDelta current_wait = kInitialRetry;
  for (int i = 0; i < kMaxRetry; i++) {
    fd_ = HANDLE_EINTR(open(kTpmDevice, O_RDWR));
    if (fd_ == kInvalidFileDescriptor) {
      PLOG(ERROR) << "TPM: Error opening tpm0 file descriptor at "
                  << kTpmDevice;
      if (i == kMaxRetry - 1) {
        // If we get here, it doesn't work.
        return false;
      }
      base::PlatformThread::Sleep(current_wait);
      current_wait = current_wait * kRetryMultiplier;
      continue;
    }
    LOG(INFO) << "TPM: " << kTpmDevice << " opened successfully";
    break;
  }
  return true;
}

void TpmHandle::SendCommand(const std::string& command,
                            ResponseCallback callback) {
  std::move(callback).Run(SendCommandAndWait(command));
}

std::string TpmHandle::SendCommandAndWait(const std::string& command) {
  std::string response;
  TPM_RC result = SendCommandInternal(command, &response);
  if (result != TPM_RC_SUCCESS) {
    response = CreateErrorResponse(result);
    // Send the command code and system uptime of the first timeout command
    if (errno == ETIME) {
      static bool has_reported = false;
      if (!has_reported) {
        TPM_CC cc;
        TPM_RC parse_rc = GetCommandCode(command, cc);
        if (parse_rc != TPM_RC_SUCCESS) {
          LOG(ERROR) << __func__ << ": failed to parse time out command: "
                     << GetErrorString(parse_rc);
        } else if (metrics_.ReportTpmHandleTimeoutCommandAndTime(result, cc)) {
          has_reported = true;
        }
      }
    }
  }
  TPM_RC rc;
  TPM_RC parse_rc = GetResponseCode(response, rc);
  if (parse_rc != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__ << ": failed to parse response: " << parse_rc;
    rc = TRUNKS_RC_PARSE_ERROR;
  }
  metrics_.ReportTpmErrorCode(rc);
  return response;
}

TPM_RC TpmHandle::SendCommandInternal(const std::string& command,
                                      std::string* response) {
  CHECK_NE(fd_, kInvalidFileDescriptor);
  // Make sure `errno` is set by `write()`.
  errno = 0;
  int result = HANDLE_EINTR(write(fd_, command.data(), command.length()));
  if (result < 0 && errno == EREMOTEIO) {
    // Retry once in case the error is caused by late wakeup from sleep.
    // Repeated error should lead to failure.
    LOG(WARNING) << "TPM: Retrying write after Remote I/O error.";
    result = HANDLE_EINTR(write(fd_, command.data(), command.length()));
  }

  const int write_errno = MaskEINTR(errno);
  const int prev_write_errno = write_error_tracker_.PushError(write_errno);
  metrics_.ReportWriteErrorNo(prev_write_errno, write_errno);
  // Recover errno in metrics reporting changes errno.
  errno = write_errno;

  if (result < 0) {
    PLOG(ERROR) << "TPM: Error writing to TPM handle.";
    return TRUNKS_RC_WRITE_ERROR;
  }
  if (static_cast<size_t>(result) != command.length()) {
    LOG(ERROR) << "TPM: Error writing to TPM handle: " << result << " vs "
               << command.length();
    return TRUNKS_RC_WRITE_ERROR;
  }
  char response_buf[kTpmBufferSize];
  result = HANDLE_EINTR(read(fd_, response_buf, kTpmBufferSize));
  if (result < 0) {
    PLOG(ERROR) << "TPM: Error reading from TPM handle.";
    return TRUNKS_RC_READ_ERROR;
  }
  response->assign(response_buf, static_cast<size_t>(result));
  return TPM_RC_SUCCESS;
}

}  // namespace trunks

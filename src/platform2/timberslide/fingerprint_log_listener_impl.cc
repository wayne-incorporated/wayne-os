// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <re2/re2.h>

#include "timberslide/fingerprint_log_listener_impl.h"

namespace timberslide {

namespace {
constexpr char kFingerprintMCUReboot[] = "Fingerprint.MCU.Reboot";
}  // namespace

void FingerprintLogListenerImpl::OnLogLine(const std::string& line) {
  if (!IsRebootLine(line)) {
    return;
  }
  if (have_seen_first_boot_) {
    SendFingerprintMCUReboot();
  }
  have_seen_first_boot_ = true;
}

bool FingerprintLogListenerImpl::SendFingerprintMCUReboot() {
  return metrics_lib_->SendCrosEventToUMA(kFingerprintMCUReboot);
}

bool FingerprintLogListenerImpl::IsRebootLine(const std::string& line) {
  return RE2::FullMatch(line, R"(^\[Image: RW.*)");
}

}  // namespace timberslide

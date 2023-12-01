// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TIMBERSLIDE_FINGERPRINT_LOG_LISTENER_IMPL_H_
#define TIMBERSLIDE_FINGERPRINT_LOG_LISTENER_IMPL_H_

#include <memory>
#include <string>

#include <metrics/metrics_library.h>
#include "timberslide/log_listener.h"

namespace timberslide {

class FingerprintLogListenerImpl : public LogListener {
 public:
  ~FingerprintLogListenerImpl() override = default;
  void OnLogLine(const std::string& line) override;

  virtual bool SendFingerprintMCUReboot();
  virtual bool IsRebootLine(const std::string& line);

 private:
  bool have_seen_first_boot_ = false;

  std::unique_ptr<MetricsLibrary> metrics_lib_ =
      std::make_unique<MetricsLibrary>();
};

}  // namespace timberslide

#endif  // TIMBERSLIDE_FINGERPRINT_LOG_LISTENER_IMPL_H_

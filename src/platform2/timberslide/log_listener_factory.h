// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TIMBERSLIDE_LOG_LISTENER_FACTORY_H_
#define TIMBERSLIDE_LOG_LISTENER_FACTORY_H_

#include <memory>
#include <string>

#include "timberslide/fingerprint_log_listener_impl.h"
#include "timberslide/log_listener.h"

namespace timberslide {

class LogListenerFactory {
 public:
  static std::unique_ptr<LogListener> Create(const std::string& ec_type) {
    if (ec_type == "cros_fp") {
      return std::make_unique<FingerprintLogListenerImpl>();
    }
    return nullptr;
  }
};

}  // namespace timberslide

#endif  // TIMBERSLIDE_LOG_LISTENER_FACTORY_H_

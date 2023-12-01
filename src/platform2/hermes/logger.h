// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HERMES_LOGGER_H_
#define HERMES_LOGGER_H_

#include <string>

#include <base/logging.h>
#include <google-lpa/lpa/util/euicc_log.h>

namespace hermes {

// Class to allow the google-lpa library to log messages.
class Logger : public lpa::util::EuiccLog {
 public:
  void E(std::string msg) override { LOG(ERROR) << msg; }
  void W(std::string msg) override { LOG(WARNING) << msg; }
  void I(std::string msg) override { LOG(INFO) << msg; }
  void D(std::string msg) override { VLOG(1) << msg; }
};

}  // namespace hermes

#endif  // HERMES_LOGGER_H_

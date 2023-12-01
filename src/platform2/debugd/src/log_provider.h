// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DEBUGD_SRC_LOG_PROVIDER_H_
#define DEBUGD_SRC_LOG_PROVIDER_H_

#include <optional>
#include <string>

namespace debugd {

// An interface class for requesting named logs, as defined in debugd::LogTool.
class LogProvider {
 public:
  virtual ~LogProvider() = default;

  // Get the named log's contents.
  virtual std::optional<std::string> GetLog(const std::string& name) = 0;
};

}  // namespace debugd

#endif  // DEBUGD_SRC_LOG_PROVIDER_H_

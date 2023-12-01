// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TIMBERSLIDE_LOG_LISTENER_H_
#define TIMBERSLIDE_LOG_LISTENER_H_

#include <string>

namespace timberslide {

class LogListener {
 public:
  virtual ~LogListener() = default;
  virtual void OnLogLine(const std::string& line) = 0;
};

}  // namespace timberslide

#endif  // TIMBERSLIDE_LOG_LISTENER_H_

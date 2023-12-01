// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PRINTSCANMGR_EXECUTOR_UPSTART_TOOLS_H_
#define PRINTSCANMGR_EXECUTOR_UPSTART_TOOLS_H_

#include <memory>
#include <string>

#include <dbus/bus.h>

#include "printscanmgr/mojom/executor.mojom.h"

namespace printscanmgr {

// This tool assists in starting or stopping upstart jobs.
class UpstartTools {
 public:
  virtual ~UpstartTools() = default;

  static std::unique_ptr<UpstartTools> Create(
      const scoped_refptr<dbus::Bus>& bus);

  virtual bool IsJobRunning(mojom::UpstartJob job, std::string* error) = 0;
  virtual bool RestartJob(mojom::UpstartJob job, std::string* error) = 0;
  virtual bool StopJob(mojom::UpstartJob job, std::string* error) = 0;
};

}  // namespace printscanmgr

#endif  // PRINTSCANMGR_EXECUTOR_UPSTART_TOOLS_H_

// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MINIOS_METRICS_REPORTER_INTERFACE_H_
#define MINIOS_METRICS_REPORTER_INTERFACE_H_

#include <string>

namespace minios {

class MetricsReporterInterface {
 public:
  virtual ~MetricsReporterInterface() = default;

  // Record the NBR start time.
  virtual void RecordNBRStart() = 0;

  // Report the recovery reason to be NBR, and the duration for it to complete.
  // The metrics will be written to the stateful partition to be reported after
  // next boot. See: init/upstart/send-recovery-metrics.conf
  virtual void ReportNBRComplete() = 0;
};

}  // namespace minios

#endif  // MINIOS_METRICS_REPORTER_INTERFACE_H_

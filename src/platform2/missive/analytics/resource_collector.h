// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MISSIVE_ANALYTICS_RESOURCE_COLLECTOR_H_
#define MISSIVE_ANALYTICS_RESOURCE_COLLECTOR_H_

#include <memory>

#include <base/sequence_checker.h>
#include <base/time/time.h>
#include <base/timer/timer.h>
#include <gtest/gtest_prod.h>

#include "missive/analytics/metrics.h"

namespace reporting::analytics {

class ResourceCollector {
 public:
  explicit ResourceCollector(base::TimeDelta interval);
  ResourceCollector(const ResourceCollector&) = delete;
  ResourceCollector& operator=(const ResourceCollector&) = delete;
  virtual ~ResourceCollector();

 protected:
  SEQUENCE_CHECKER(sequence_checker_);

  // Stop the timer. A derived classes should call this method before
  // |ResourceCollector::~ResourceCollector| is called so as to prevent the
  // timer from executing code that accesses destructed members of the derived
  // class.
  void StopTimer();

 private:
  friend class ResourceCollectorTest;

  // The implementation of this method should collects analytics data, such as
  // resource usage info, and send them to the UMA Chrome client, typically via
  // |MetricsLibrary| in libmetrics (//platform2/metrics/README.md). It should
  // log any errors but ignore them.
  //
  // This method is called on a fixed time interval, as specified in the
  // |interval| param in the constructor.
  virtual void Collect() = 0;

  // Calls |Collect|. Checks for sequence.
  void CollectWrapper();

  // Timer for executing the resource usage collection task.
  base::RepeatingTimer timer_ GUARDED_BY_CONTEXT(sequence_checker_);
};

}  // namespace reporting::analytics

#endif  // MISSIVE_ANALYTICS_RESOURCE_COLLECTOR_H_

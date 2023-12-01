// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// CumulativeMetrics helps maintain and report "accumulated" quantities, for
// instance how much data has been sent over WiFi and LTE in a day.  Here's
// roughly how a continuously running daemon would do that:
//
// {
//   // initialization, at daemon startup
//   ...
//   base::FilePath backing_dir("/var/lib/metrics/shill");
//   std::vector<std::string> stat_names = {"wifi", "cellular", "total"};
//   CumulativeMetrics cm(
//     backing_dir,
//     stat_names,
//     base::Minutes(5),
//     base::BindRepeating(&UpdateConnectivityStats),
//     base::Days(1),
//     base::BindRepeating(&ReportConnectivityStats,
//     base::Unretained(metrics_lib_));
//
//   ...
// }
//
// void UpdateConnectivityStats(CumulativeMetrics *cm) {
//   if (wifi_connected) {
//     cm->Add("wifi", cm->ActiveTimeSinceLastUpdate());
//   }
//   if (lte_connected) {
//     cm->Add("cellular", cm->ActiveTimeSinceLastUpdate());
//   }
//   cm->Add("total", cm->ActiveTimeSinceLastUpdate());
// }
//
// void ReportConnectivityStats(MetricsLibrary* ml, CumulativeMetrics* cm) {
//   int64_t total = cm->Get("total");
//   ml->SendSample(total, ...);
//   int64_t wifi_time = cm->Get("wifi");
//   ml->SendSample(wifi_time * 100 / total, ...);
//   ...
// }
//
// In the above example, the cumulative metrics object helps maintain three
// quantities (wifi, cellular, and total) persistently across boot sessions and
// other daemon restarts.  The quantities are updated every 5 minutes, and
// samples are sent at most once a day.
//
// The class clears (i.e. sets to 0) all accumulated quantities on an OS
// version change.

#ifndef METRICS_CUMULATIVE_METRICS_H_
#define METRICS_CUMULATIVE_METRICS_H_

#include <map>
#include <memory>
#include <string>
#include <vector>

#include <base/memory/weak_ptr.h>
#include <base/time/time.h>
#include <base/timer/timer.h>

#include "metrics/persistent_integer.h"

namespace chromeos_metrics {

class CumulativeMetrics {
 public:
  using Callback = base::RepeatingCallback<void(CumulativeMetrics*)>;
  // Constructor.
  //
  // |backing_dir| points to a subdirectory for the backing files, for instance
  // "/var/lib/shill/metrics".
  //
  // |names| are the names of the quantities to be maintained.  They also name
  // the corresponding backing files.
  //
  // |update_callback| and |cycle_end_callback| are partial closures which take
  // one argument of type CumulativeMetrics* and return void.  The former is
  // called (roughly) every |update_period_seconds|, and similarly
  // |cycle_end_callback| is called every |accumulation_period_seconds| (see
  // example at the top of this file).
  //
  // Note that the accumulated values are cleared at the end of each cycle
  // after calling |cycle_end_callback_|, which typically sends those
  // quantities as histogram values.  They are also cleared on Chrome OS
  // version changes, but in that case |cycle_end_callback_| is not called
  // unless the version change happens together with the end of a cycle.  The
  // reason is that we want to ship correct histograms for each version, so we
  // can notice the impact of the version change.
  CumulativeMetrics(const base::FilePath& backing_dir,
                    const std::vector<std::string>& names,
                    base::TimeDelta update_period,
                    Callback update_callback,
                    base::TimeDelta accumulation_period,
                    Callback cycle_end_callback);
  CumulativeMetrics(const CumulativeMetrics&) = delete;
  CumulativeMetrics& operator=(const CumulativeMetrics&) = delete;

  virtual ~CumulativeMetrics() {}

  // Calls |update_callback_|.
  // This is automatically called every |update_period_seconds_| of active time,
  // but also can be manually called when a relevant change has occurred. Manual
  // calls to this method do not cause the timing of automatic invocations to
  // change.
  //
  // Note that clients who choose to manually call this method must ensure that
  // the update callback implementation can properly handle being invoked at a
  // variable frequency.
  void Update();

  // Returns the time delta (in active time, not elapsed wall clock time) since
  // the last invocation of Update, or the daemon start.  Note that this could
  // be a lot smaller than the elapsed time.
  // This method is virtual so it can be mocked for testing.
  virtual base::TimeDelta ActiveTimeSinceLastUpdate() const;
  // Sets the value of |name| to |value|.
  void Set(const std::string& name, int64_t value);
  // Adds |value| to the current value of |name|.
  void Add(const std::string& name, int64_t value);
  // Sets |name| to the max of its current value and the specified |value|.
  void Max(const std::string& name, int64_t value);
  // Gets the value of |name|
  int64_t Get(const std::string& name) const;
  // Returns the value of |name| and sets it to 0.
  int64_t GetAndClear(const std::string& name);

 private:
  // Checks if the current cycle has expired and takes appropriate actions.
  // Returns true if the current cycle has expired, false otherwise.
  bool ProcessCycleEnd();
  // Returns a pointer to the persistent integer for |name| if |name| is a
  // valid cumulative metric.  Otherwise returns nullptr.
  PersistentInteger* Find(const std::string& name) const;
  // Convenience function for reporting uses of invalid metric names.
  void PanicFromBadName(const char* action, const std::string& name) const;

 private:
  // for PersistentInteger backing files
  base::FilePath backing_dir_;
  // name -> accumulated value
  std::map<std::string, std::unique_ptr<PersistentInteger>> values_;
  // interval between update callbacks
  base::TimeDelta update_period_;
  // cycle length
  base::TimeDelta accumulation_period_;
  // clock at beginning of cycle (usecs)
  std::unique_ptr<PersistentInteger> cycle_start_;
  // active time at latest update
  base::TimeTicks last_update_time_;
  // |update_callback_| is called every |update_period_seconds_| to update the
  // accumulators.
  Callback update_callback_;
  // |cycle_end_callback_| is called every |accumulation_period_seconds_| (for
  // instance, one day worth) to send histogram samples.
  Callback cycle_end_callback_;
  base::RepeatingTimer timer_;
};

}  // namespace chromeos_metrics

#endif  // METRICS_CUMULATIVE_METRICS_H_

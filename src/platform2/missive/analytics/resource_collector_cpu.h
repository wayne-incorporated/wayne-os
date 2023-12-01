// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MISSIVE_ANALYTICS_RESOURCE_COLLECTOR_CPU_H_
#define MISSIVE_ANALYTICS_RESOURCE_COLLECTOR_CPU_H_

#include <cstddef>
#include <ctime>
#include <memory>

#include <base/sequence_checker.h>
#include <base/time/time.h>
#include <gtest/gtest_prod.h>
#include <metrics/metrics_library.h>

#include "missive/analytics/resource_collector.h"
#include "missive/util/statusor.h"

namespace reporting {

// Forward declarations for `friend class` directives.
class MissiveArgsTest;
class MissiveImplTest;

namespace analytics {

class ResourceCollectorCpu : public ResourceCollector {
 public:
  explicit ResourceCollectorCpu(base::TimeDelta interval);
  ResourceCollectorCpu(const ResourceCollectorCpu&) = delete;
  ResourceCollectorCpu& operator=(const ResourceCollectorCpu&) = delete;
  ~ResourceCollectorCpu() override;

 private:
  friend class ::reporting::MissiveArgsTest;
  friend class ::reporting::MissiveImplTest;
  friend class ResourceCollectorCpuTest;
  friend class ResourceCollectorCpuTestWithCpuPercentageParams;
  FRIEND_TEST(ResourceCollectorCpuTest, SuccessfullySendRealCpu);
  FRIEND_TEST(ResourceCollectorCpuTest, FailToSendMockCpu);
  FRIEND_TEST(ResourceCollectorCpuTestWithCpuPercentageParams,
              SuccessfullySendMockCpu);

  // Tally CPU usages. Not thread-safe, must be accessed sequentially. It is
  // accessed sequentially because it is only accessed by
  // |ResourceCollectorCpu|'s constructor, destructor, and |Collect|, all of
  // which are required to be executed on the same sequence. |Collect| is called
  // by a |base::Timer| instance that starts in the constructor, which
  // guarantees that the constructor and |Collect| access |CpuUsageTallier|
  // sequentially. The destructor also runs on the same thread as the
  // constructor on the thread that |MissiveDaemon| runs on.
  class CpuUsageTallier {
   public:
    virtual ~CpuUsageTallier();
    // Tally the CPU usage in percentage since last time Tally() was called.
    virtual StatusOr<uint64_t> Tally();

   private:
    // The CPU usage (in seconds) since Tally() was called last time.
    time_t last_cpu_time_ GUARDED_BY_CONTEXT(sequence_checker_){0};
    // The wall-clock time (in seconds) since Tally() was called last time.
    time_t last_wall_time_ GUARDED_BY_CONTEXT(sequence_checker_){0};

    // This should check the same sequence as
    // |ResourceCollector::sequence_checker_|, because this sequence checker is
    // always instantiated in the sequence associated with
    // |ResourceCollector::sequence_checker_|.
    SEQUENCE_CHECKER(sequence_checker_);
  };

  // UMA name
  static constexpr char kUmaName[] = "Platform.Missive.CpuUsage";

  // Collect CPU usage.
  void Collect() override;
  // Send CPU usage in percentage to UMA.
  bool SendCpuUsagePercentageToUma(uint64_t cpu_percentage);

  // The tallier instance that retrieve CPU usage from the OS.
  std::unique_ptr<CpuUsageTallier> tallier_{
      std::make_unique<CpuUsageTallier>()};
};

}  // namespace analytics
}  // namespace reporting

#endif  // MISSIVE_ANALYTICS_RESOURCE_COLLECTOR_CPU_H_

// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MISSIVE_RESOURCES_ENQUEUING_RECORD_TALLIER_H_
#define MISSIVE_RESOURCES_ENQUEUING_RECORD_TALLIER_H_

#include <atomic>
#include <cstdint>
#include <ctime>
#include <limits>
#include <optional>

#include <base/sequence_checker.h>
#include <base/time/time.h>
#include <base/timer/timer.h>

#include "missive/proto/record.pb.h"
#include "missive/util/statusor.h"
#include "missive/util/time.h"

namespace reporting {

// Tallies the size of enqueuing records and calculate the enqueuing size per
// second. An average rate of enqueuing records in bytes/sec since last time
// is collected once every |interval| and can be accessed via |GetAverage|.
class EnqueuingRecordTallier {
 public:
  explicit EnqueuingRecordTallier(base::TimeDelta interval);
  EnqueuingRecordTallier(const EnqueuingRecordTallier&) = delete;
  EnqueuingRecordTallier& operator=(const EnqueuingRecordTallier&) = delete;
  virtual ~EnqueuingRecordTallier();

  // Tallies the size of a given record. This method only atomically increases
  // |cumulated_size_| and can be called on any sequences.
  void Tally(const Record& record);

  // Returns the current average rate of enqueuing records in bytes/sec during
  // the last time period.
  std::optional<uint64_t> GetAverage() const;

 private:
  friend class FakeEnqueuingRecordTallier;

  // If average_ is this value, then it is nullopt
  static constexpr uint64_t kAverageNullOpt =
      std::numeric_limits<uint64_t>::max();

  // Gets the current wall time.
  virtual StatusOr<uint64_t> GetCurrentWallTime() const;

  // Updates the average rate of enqueuing records in bytes/sec since last time
  // this method is called. If the wall-clock time or the last wall-clock time
  // was not successfully obtained, |Average| will return |std::nullopt|. All
  // calls to this method must be on the same sequence. It is called by the
  // timer owned by this instance.
  void UpdateAverage() VALID_CONTEXT_REQUIRED(sequence_checker_);

  // Resets |cumulated_size_| and |last_wall_time_|. Returns the average rate of
  // enqueuing records in bytes/sec since last time this method is called. If
  // the wall-clock time or the last wall-clock time was not successfully
  // obtained, an error status is returned. All calls to this method must be on
  // the same sequence.
  [[nodiscard]] StatusOr<uint64_t> ComputeAverage()
      VALID_CONTEXT_REQUIRED(sequence_checker_);

  // The tallied size until now.
  std::atomic<uint64_t> cumulated_size_{0};
  // The last time |UpdateAverage| is called or the object is constructed.
  // Initialized to the current wall time. If the status is not OK, it means the
  // wall time was not successfully obtained last time. No atomic is needed
  // because this variable is always accessed on the same sequence.
  StatusOr<time_t> last_wall_time_ GUARDED_BY_CONTEXT(sequence_checker_){
      GetCurrentWallTime()};
  // The average during the last period. Semantically this should be
  // std::atomic<std::optional<uint64_t>>, but this would create an explicit
  // lock and does not compile well on some ChromeOS images.
  std::atomic<uint64_t> average_{kAverageNullOpt};
  // Timer for executing the resource usage collection task.
  base::RepeatingTimer timer_;

  SEQUENCE_CHECKER(sequence_checker_);
};

}  // namespace reporting

#endif  // MISSIVE_RESOURCES_ENQUEUING_RECORD_TALLIER_H_

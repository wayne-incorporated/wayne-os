// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_NET_EVENT_HISTORY_H_
#define SHILL_NET_EVENT_HISTORY_H_

#include <deque>
#include <string>
#include <vector>

#include <gtest/gtest_prod.h>  // for FRIEND_TEST

#include "shill/net/shill_export.h"
#include "shill/net/shill_time.h"

namespace shill {

// EventHistory is a list of timestamps tracking the occurrence of one or more
// events. Events are ordered from earliest to latest. |max_events_saved|
// can optionally be provided to limit the number of event timestamps saved
// at any one time.
class SHILL_EXPORT EventHistory {
 public:
  enum ClockType {
    kClockTypeBoottime = 0,
    kClockTypeMonotonic = 1,
  };

  EventHistory() : max_events_specified_(false), time_(Time::GetInstance()) {}
  explicit EventHistory(int max_events_saved)
      : max_events_specified_(true),
        max_events_saved_(max_events_saved),
        time_(Time::GetInstance()) {}
  EventHistory(const EventHistory&) = delete;
  EventHistory& operator=(const EventHistory&) = delete;

  // Records the current event by adding the current time to the list.
  // If |event_limit_specificed_| and the size of |events_| is larger than
  // |max_events_saved_|, event timestamps are removed in FIFO order until the
  // size of |events_| is equal to |max_events_saved_|.
  void RecordEvent();

  // Start at the head of |events_| and remove all entries that occurred
  // more than |seconds_ago| prior to the current time. |clock_type| determines
  // what time of clock we use for time-related calculations.
  void ExpireEventsBefore(int seconds_ago, ClockType clock_type);

  // Records the current event by adding the current time to the list, and uses
  // this same timestamp to remove all entries that occurred more than
  // |seconds_ago|. |clock_type| determines what time of clock we use for time-
  // related calculations.
  void RecordEventAndExpireEventsBefore(int seconds_ago, ClockType clock_type);

  // Returns a vector of human-readable strings representing each timestamp in
  // |events_|.
  std::vector<std::string> ExtractWallClockToStrings() const;

  // Returns the number of timestamps in |events_| within the interval spanning
  // now and the time |seconds_ago| before now (inclusive). |clock_type|
  // determines what time of clock we use for time-related calculations.
  int CountEventsWithinInterval(int seconds_ago, ClockType clock_type);

  size_t Size() const { return events_.size(); }
  bool Empty() { return events_.empty(); }
  Timestamp Front() { return events_.front(); }
  void Clear() { events_.clear(); }

 private:
  friend class EventHistoryTest;
  friend class ServiceTest;     // RecordEventInternal, time_
  friend class WakeOnWiFiTest;  // time_

  void RecordEventInternal(Timestamp now);

  void ExpireEventsBeforeInternal(int seconds_ago,
                                  Timestamp now,
                                  ClockType clock_type);

  bool max_events_specified_;
  int max_events_saved_;
  std::deque<Timestamp> events_;
  Time* time_;
};

}  // namespace shill

#endif  // SHILL_NET_EVENT_HISTORY_H_

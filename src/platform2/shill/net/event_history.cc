// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/net/event_history.h"

#include <time.h>

#include <base/logging.h>
#include <base/notreached.h>

namespace shill {

void EventHistory::RecordEvent() {
  RecordEventInternal(time_->GetNow());
}

void EventHistory::ExpireEventsBefore(int seconds_ago, ClockType clock_type) {
  ExpireEventsBeforeInternal(seconds_ago, time_->GetNow(), clock_type);
}

void EventHistory::RecordEventAndExpireEventsBefore(int seconds_ago,
                                                    ClockType clock_type) {
  Timestamp now = time_->GetNow();
  RecordEventInternal(now);
  ExpireEventsBeforeInternal(seconds_ago, now, clock_type);
}

std::vector<std::string> EventHistory::ExtractWallClockToStrings() const {
  std::vector<std::string> strings;
  for (std::deque<Timestamp>::const_iterator it = events_.begin();
       it != events_.end(); ++it) {
    strings.push_back(it->wall_clock);
  }
  return strings;
}

void EventHistory::RecordEventInternal(Timestamp now) {
  events_.push_back(now);
  while (!events_.empty() && max_events_specified_ &&
         (events_.size() > static_cast<size_t>(max_events_saved_))) {
    events_.pop_front();
  }
}

void EventHistory::ExpireEventsBeforeInternal(int seconds_ago,
                                              Timestamp now,
                                              ClockType clock_type) {
  struct timeval interval = (const struct timeval){seconds_ago};
  while (!events_.empty()) {
    struct timeval elapsed = {0, 0};
    switch (clock_type) {
      case kClockTypeBoottime:
        timersub(&now.boottime, &events_.front().boottime, &elapsed);
        break;
      case kClockTypeMonotonic:
        timersub(&now.monotonic, &events_.front().monotonic, &elapsed);
        break;
      default: {
        NOTIMPLEMENTED()
            << __func__ << ": "
            << "Invalid clock type specified - defaulting to boottime clock";
        timersub(&now.boottime, &events_.front().boottime, &elapsed);
      }
    }
    if (timercmp(&elapsed, &interval, <)) {
      break;
    }
    events_.pop_front();
  }
}

int EventHistory::CountEventsWithinInterval(int seconds_ago,
                                            ClockType clock_type) {
  int num_events_in_interval = 0;
  Timestamp now = time_->GetNow();
  struct timeval interval = (const struct timeval){seconds_ago};
  int i = 0;
  for (const auto& event : events_) {
    struct timeval elapsed = {0, 0};
    switch (clock_type) {
      case kClockTypeBoottime:
        timersub(&now.boottime, &event.boottime, &elapsed);
        break;
      case kClockTypeMonotonic:
        timersub(&now.monotonic, &event.monotonic, &elapsed);
        break;
      default: {
        NOTIMPLEMENTED()
            << __func__ << ": "
            << "Invalid clock type specified - defaulting to boottime clock";
        timersub(&now.boottime, &event.boottime, &elapsed);
      }
    }
    if (timercmp(&elapsed, &interval, <=)) {
      num_events_in_interval = events_.size() - i;
      break;
    }
    ++i;
  }
  return num_events_in_interval;
}

}  // namespace shill

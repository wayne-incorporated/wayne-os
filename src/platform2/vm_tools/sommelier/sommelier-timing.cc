// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "sommelier-timing.h"  // NOLINT(build/include_directory)

#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

#define NSEC_PER_SEC 1000000000
#define NSEC_PER_USEC 1000

static inline int64_t timespec_to_ns(timespec* t) {
  return (int64_t)t->tv_sec * NSEC_PER_SEC + t->tv_nsec;
}

// Records start time to calculate first delta.
void Timing::RecordStartTime() {
  clock_gettime(CLOCK_REALTIME, &last_event);
}

int64_t Timing::GetTime() {
  timespec tp;
  clock_gettime(CLOCK_REALTIME, &tp);
  int64_t now = timespec_to_ns(&tp);
  int64_t last = timespec_to_ns(&last_event);
  last_event = tp;
  return now - last;
}

// Create a new action, add info gained from attach call.
void Timing::UpdateLastAttach(int surface_id, int buffer_id) {
  actions[event_id % kMaxNumActions] =
      BufferAction(GetTime(), surface_id, buffer_id, BufferAction::ATTACH);
  event_id++;
}

// Create a new action, add info gained from commit call.
void Timing::UpdateLastCommit(int surface_id) {
  actions[event_id % kMaxNumActions] = BufferAction(
      GetTime(), surface_id, kUnknownBufferId, BufferAction::COMMIT);
  event_id++;
}

// Add a release action with release timing info.
void Timing::UpdateLastRelease(int buffer_id) {
  actions[event_id % kMaxNumActions] = BufferAction(
      GetTime(), kUnknownSurfaceId, buffer_id, BufferAction::RELEASE);
  event_id++;
}

// Output the recorded actions to the timing log file.
void Timing::OutputLog() {
  if (event_id == 0) {
    std::cout << "No events in buffer, exiting" << std::endl;
    return;
  }

  std::cout << "Writing buffer activity to the timing log file" << std::endl;

  std::string output_filename =
      std::string(filename) + "_set_" + std::to_string(saves);

  std::ofstream outfile(output_filename);

  int start = 0;
  int buf_size = event_id;
  if (event_id >= kMaxNumActions) {
    start = event_id % kMaxNumActions;
    buf_size = kMaxNumActions;
  }

  outfile << "Type Surface_ID Buffer_ID Delta_Time" << std::endl;
  for (int i = 0; i < buf_size; i++) {
    int idx = (i + start) % kMaxNumActions;
    std::string type("?");
    if (actions[idx].action_type == BufferAction::ATTACH) {
      type = "a";
    } else if (actions[idx].action_type == BufferAction::COMMIT) {
      type = "c";
    } else if (actions[idx].action_type == BufferAction::RELEASE) {
      type = "r";
    }
    outfile << type << " ";
    outfile << actions[idx].surface_id << " ";
    outfile << actions[idx].buffer_id << " ";
    outfile << static_cast<double>(actions[idx].delta_time) / NSEC_PER_USEC
            << std::endl;
  }

  std::stringstream nsec;
  nsec << std::setw(9) << std::setfill('0') << last_event.tv_nsec;
  outfile << "EndTime " << event_id - 1 << " " << last_event.tv_sec << "."
          << nsec.str() << std::endl;

  outfile.close();
  std::cout << "Finished writing " << output_filename << std::endl;
  ++saves;
}

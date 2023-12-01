// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_SOMMELIER_SOMMELIER_TIMING_H_
#define VM_TOOLS_SOMMELIER_SOMMELIER_TIMING_H_

#include <stdint.h>
#include <time.h>

const int kUnknownBufferId = -1;
const int kUnknownSurfaceId = -1;

class Timing {
 public:
  explicit Timing(const char* fname) : filename(fname) {}
  void RecordStartTime();
  void UpdateLastAttach(int surface_id, int buffer_id);
  void UpdateLastCommit(int surface_id);
  void UpdateLastRelease(int buffer_id);
  void OutputLog();

 private:
  // 10 min * 60 sec/min * 60 frames/sec * 3 actions/frame = 108000 actions
  static const int kMaxNumActions = 10 * 60 * 60 * 3;

  struct BufferAction {
    enum Type { UNKNOWN, ATTACH, COMMIT, RELEASE };
    int64_t delta_time;
    int surface_id;
    int buffer_id;
    Type action_type;
    BufferAction()
        : surface_id(kUnknownSurfaceId),
          buffer_id(kUnknownBufferId),
          action_type(UNKNOWN) {}
    explicit BufferAction(int64_t dt,
                          int sid = kUnknownSurfaceId,
                          int bid = kUnknownBufferId,
                          Type type = UNKNOWN)
        : delta_time(dt), surface_id(sid), buffer_id(bid), action_type(type) {}
  };

  BufferAction actions[kMaxNumActions];
  int event_id = 0;
  int saves = 0;
  const char* filename;
  timespec last_event;

  int64_t GetTime();
};      // class Timing
#endif  // VM_TOOLS_SOMMELIER_SOMMELIER_TIMING_H_

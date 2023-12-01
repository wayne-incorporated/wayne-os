// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// A simple event bridge to allow glib programs to operate on a libchrome
// message loop.

#ifndef GLIB_BRIDGE_GLIB_BRIDGE_H_
#define GLIB_BRIDGE_GLIB_BRIDGE_H_

#include <glib.h>

#include <map>
#include <memory>
#include <vector>

#include <base/cancelable_callback.h>
#include <base/files/file_descriptor_watcher_posix.h>
#include <base/functional/bind.h>

#include "glib-bridge/glib_bridge_export.h"

namespace glib_bridge {

struct GLIB_BRIDGE_EXPORT GlibBridge {
 public:
  GlibBridge();
  virtual ~GlibBridge();

 private:
  enum class State {
    kPreparingIteration,
    kWaitingForEvents,
    kReadyForDispatch,
  };

  struct Watcher {
    std::unique_ptr<base::FileDescriptorWatcher::Controller> reader;
    std::unique_ptr<base::FileDescriptorWatcher::Controller> writer;
  };

  void PrepareIteration();
  void Timeout();
  void Dispatch();

  void OnEvent(int fd, int flag);

  // If we ever need to support multiple GMainContexts instead of just the
  // default one then we can wrap a different context here. This is a weak
  // pointer.
  GMainContext* glib_context_;

  // glib event and source bits.
  int max_priority_ = -1;
  std::vector<GPollFD> poll_fds_;
  std::map<int, std::vector<GPollFD*>> fd_map_;

  // libchrome message loop bits.
  std::map<int, Watcher> watchers_;
  base::CancelableOnceClosure timeout_closure_;

  State state_;

  base::WeakPtrFactory<GlibBridge> weak_ptr_factory_;
};

}  // namespace glib_bridge

#endif  // GLIB_BRIDGE_GLIB_BRIDGE_H_

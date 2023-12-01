// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_BINDER_WATCHER_H_
#define LIBBRILLO_BRILLO_BINDER_WATCHER_H_

#include <memory>

#include <base/files/file_descriptor_watcher_posix.h>

namespace brillo {

// Bridge between libbinder and brillo::MessageLoop. Construct at startup to
// make the message loop watch for binder events and pass them to libbinder.
class BinderWatcher final {
 public:
  BinderWatcher();
  BinderWatcher(const BinderWatcher&) = delete;
  BinderWatcher& operator=(const BinderWatcher&) = delete;

  ~BinderWatcher();

  // Initializes the object, returning true on success.
  bool Init();

 private:
  std::unique_ptr<base::FileDescriptorWatcher::Controller> watcher_;
};

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_BINDER_WATCHER_H_

// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBCONTAINER_CONFIG_H_
#define LIBCONTAINER_CONFIG_H_

#include <vector>

#include <base/functional/callback_forward.h>
#include <brillo/brillo_export.h>
#include <libminijail.h>

#include "libcontainer/libcontainer.h"

namespace libcontainer {

// A hook that can be run at different stages of the container startup. The PID
// parameter is the pid of the container's init process in the outer namespace.
// The hook should return true on success.
using HookCallback = base::OnceCallback<bool(pid_t)>;

class BRILLO_EXPORT Config {
 public:
  Config();
  Config(const Config&) = delete;
  Config& operator=(const Config&) = delete;

  ~Config();

  container_config* get() const { return config_; }

  // Runs |callback| when |event| is reached. If |callback| fails,
  // container_start() will fail and tear down the container.
  void AddHook(minijail_hook_event_t event,
               libcontainer::HookCallback callback);

 private:
  container_config* const config_;
};

}  // namespace libcontainer

#endif  // LIBCONTAINER_CONFIG_H_

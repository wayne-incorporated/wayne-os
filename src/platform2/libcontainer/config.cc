// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libcontainer/config.h"

#include <utility>

#include <base/check.h>
#include <base/functional/callback.h>
#include <base/logging.h>

// TODO(lhchavez): Remove this once container_config only holds a pointer to
// libcontainer::Config.
extern void container_config_add_hook(struct container_config* c,
                                      minijail_hook_event_t event,
                                      libcontainer::HookCallback callback);

namespace libcontainer {

Config::Config() : config_(container_config_create()) {
  // container_config_create() allocates using std::nothrow, so we need to
  // explicitly call abort(2) when allocation fails.
  CHECK(config_);
}

Config::~Config() {
  container_config_destroy(config_);
}

void Config::AddHook(minijail_hook_event_t event,
                     libcontainer::HookCallback callback) {
  container_config_add_hook(config_, event, std::move(callback));
}

}  // namespace libcontainer

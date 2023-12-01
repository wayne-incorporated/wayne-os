// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/dbus/upstart_proxy.h"

#include <base/functional/bind.h>
#include <base/logging.h>

#include "shill/logging.h"

namespace shill {

const char UpstartProxy::kUpstartServiceName[] = "com.ubuntu.Upstart";

UpstartProxy::UpstartProxy(const scoped_refptr<dbus::Bus>& bus)
    : shill_event_proxy_(
          new com::ubuntu::Upstart0_6::JobProxy(bus, kUpstartServiceName)) {}

void UpstartProxy::EmitEvent(const std::string& name,
                             const std::vector<std::string>& env,
                             bool wait) {
  std::vector<std::string> start_job_env = env;
  start_job_env.push_back("EVENT_NAME=" + name);
  shill_event_proxy_->StartAsync(
      start_job_env, wait, base::BindOnce([](const dbus::ObjectPath& path) {
        VLOG(2) << "Event emitted successful";
      }),
      base::BindOnce([](brillo::Error* error) {
        LOG(ERROR) << "Failed to emit event: " << error->GetCode() << " "
                   << error->GetMessage();
      }));
}

}  // namespace shill

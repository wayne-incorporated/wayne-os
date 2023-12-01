// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MODEMFWD_UPSTART_JOB_CONTROLLER_H_
#define MODEMFWD_UPSTART_JOB_CONTROLLER_H_

#include <memory>
#include <string>
#include <vector>

#include "modemfwd/journal.h"
#include "upstart/dbus-proxies.h"

namespace modemfwd {

class UpstartJobController {
 public:
  explicit UpstartJobController(std::string upstart_service_name,
                                std::string job_name,
                                scoped_refptr<dbus::Bus> bus);
  ~UpstartJobController();

  bool IsRunning();
  bool IsInstalled();
  bool Stop();
  bool Start();
  bool Start(std::vector<std::string> in_env);

 private:
  dbus::ObjectPath job_name_;
  std::unique_ptr<com::ubuntu::Upstart0_6Proxy> upstart_proxy_;
  std::unique_ptr<com::ubuntu::Upstart0_6::JobProxy> job_proxy_;
  bool job_stopped_;
};

}  // namespace modemfwd

#endif  // MODEMFWD_UPSTART_JOB_CONTROLLER_H_

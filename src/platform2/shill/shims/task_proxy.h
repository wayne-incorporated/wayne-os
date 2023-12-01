// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_SHIMS_TASK_PROXY_H_
#define SHILL_SHIMS_TASK_PROXY_H_

#include <shill/dbus-proxies.h>

#include <map>
#include <string>

namespace shill {

namespace shims {

class TaskProxy {
 public:
  TaskProxy(scoped_refptr<dbus::Bus> bus,
            const std::string& path,
            const std::string& service);
  TaskProxy(const TaskProxy&) = delete;
  TaskProxy& operator=(const TaskProxy&) = delete;

  ~TaskProxy();

  void Notify(const std::string& reason,
              const std::map<std::string, std::string>& dict);

  bool GetSecret(std::string* username, std::string* password);

 private:
  org::chromium::flimflam::TaskProxy proxy_;
};

}  // namespace shims

}  // namespace shill

#endif  // SHILL_SHIMS_TASK_PROXY_H_

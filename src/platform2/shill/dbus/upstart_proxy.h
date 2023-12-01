// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_DBUS_UPSTART_PROXY_H_
#define SHILL_DBUS_UPSTART_PROXY_H_

#include <memory>
#include <string>
#include <vector>

#include <base/memory/ref_counted.h>
#include <base/memory/weak_ptr.h>

#include "shill/upstart/upstart_proxy_interface.h"
#include "upstart/dbus-proxies.h"

namespace shill {

class UpstartProxy : public UpstartProxyInterface {
 public:
  explicit UpstartProxy(const scoped_refptr<dbus::Bus>& bus);
  UpstartProxy(const UpstartProxy&) = delete;
  UpstartProxy& operator=(const UpstartProxy&) = delete;

  ~UpstartProxy() override = default;

  // Inherited from UpstartProxyInterface.
  void EmitEvent(const std::string& name,
                 const std::vector<std::string>& env,
                 bool wait) override;

 private:
  static const char kUpstartServiceName[];

  std::unique_ptr<com::ubuntu::Upstart0_6::JobProxy> shill_event_proxy_;

  base::WeakPtrFactory<UpstartProxy> weak_factory_{this};
};

}  // namespace shill

#endif  // SHILL_DBUS_UPSTART_PROXY_H_

// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_UPSTART_UPSTART_H_
#define SHILL_UPSTART_UPSTART_H_

#include <memory>

#include "shill/upstart/upstart_proxy_interface.h"

namespace shill {

class ControlInterface;

class Upstart {
 public:
  // |control_interface| creates the UpstartProxy. Use a fake for testing.
  explicit Upstart(ControlInterface* control_interface);
  Upstart(const Upstart&) = delete;
  Upstart& operator=(const Upstart&) = delete;

  virtual ~Upstart();

  // Report an event to upstart indicating that the system has disconnected.
  virtual void NotifyDisconnected();
  // Report an event to upstart indicating that the system has connected.
  virtual void NotifyConnected();

 private:
  // Event string to be provided to upstart to indicate we have disconnected.
  static const char kShillDisconnectEvent[];
  // Event string to be provided to upstart to indicate we have connected.
  static const char kShillConnectEvent[];

  // The upstart proxy created by this class.
  const std::unique_ptr<UpstartProxyInterface> upstart_proxy_;
};

}  // namespace shill

#endif  // SHILL_UPSTART_UPSTART_H_

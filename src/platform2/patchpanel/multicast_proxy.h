// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PATCHPANEL_MULTICAST_PROXY_H_
#define PATCHPANEL_MULTICAST_PROXY_H_

#include <map>
#include <memory>
#include <string>

#include <brillo/daemons/daemon.h>

#include "patchpanel/broadcast_forwarder.h"
#include "patchpanel/ipc.h"
#include "patchpanel/message_dispatcher.h"
#include "patchpanel/multicast_forwarder.h"

namespace patchpanel {

// MulticastProxy manages multiple MulticastForwarder instances to forward
// multicast for multiple physical interfaces.
class MulticastProxy : public brillo::Daemon {
 public:
  explicit MulticastProxy(base::ScopedFD control_fd);
  MulticastProxy(const MulticastProxy&) = delete;
  MulticastProxy& operator=(const MulticastProxy&) = delete;

  virtual ~MulticastProxy() = default;

 protected:
  int OnInit() override;

  void OnParentProcessExit();
  void OnDeviceMessage(const SubprocessMessage& msg);

 private:
  void Reset();

  MessageDispatcher<SubprocessMessage> msg_dispatcher_;
  std::map<std::string, std::unique_ptr<MulticastForwarder>> mdns_fwds_;
  std::map<std::string, std::unique_ptr<MulticastForwarder>> ssdp_fwds_;
  std::map<std::string, std::unique_ptr<BroadcastForwarder>> bcast_fwds_;

  base::WeakPtrFactory<MulticastProxy> weak_factory_{this};
};

}  // namespace patchpanel

#endif  // PATCHPANEL_MULTICAST_PROXY_H_

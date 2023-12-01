// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/multicast_proxy.h"

#include <sysexits.h>

#include <utility>

#include <base/logging.h>

#include "patchpanel/ipc.h"
#include "patchpanel/minijailed_process_runner.h"

namespace patchpanel {

MulticastProxy::MulticastProxy(base::ScopedFD control_fd)
    : msg_dispatcher_(std::move(control_fd)) {
  msg_dispatcher_.RegisterFailureHandler(base::BindRepeating(
      &MulticastProxy::OnParentProcessExit, weak_factory_.GetWeakPtr()));

  msg_dispatcher_.RegisterMessageHandler(base::BindRepeating(
      &MulticastProxy::OnDeviceMessage, weak_factory_.GetWeakPtr()));
}

int MulticastProxy::OnInit() {
  // Prevent the main process from sending us any signals.
  if (setsid() < 0) {
    PLOG(ERROR) << "Failed to created a new session with setsid; exiting";
    return EX_OSERR;
  }

  EnterChildProcessJail();
  return Daemon::OnInit();
}

void MulticastProxy::Reset() {
  mdns_fwds_.clear();
  ssdp_fwds_.clear();
  bcast_fwds_.clear();
}

void MulticastProxy::OnParentProcessExit() {
  LOG(ERROR) << "Quitting because the parent process died";
  Reset();
  Quit();
}

void MulticastProxy::OnDeviceMessage(const SubprocessMessage& root_msg) {
  if (!root_msg.has_control_message()) {
    LOG(ERROR) << "Unexpected message type";
    return;
  }
  if (!root_msg.control_message().has_device_message()) {
    return;
  }
  const DeviceMessage& msg = root_msg.control_message().device_message();
  const std::string& dev_ifname = msg.dev_ifname();
  if (dev_ifname.empty()) {
    LOG(DFATAL) << "Received DeviceMessage w/ empty dev_ifname";
    return;
  }

  auto mdns_fwd = mdns_fwds_.find(dev_ifname);
  auto ssdp_fwd = ssdp_fwds_.find(dev_ifname);
  auto bcast_fwd = bcast_fwds_.find(dev_ifname);

  if (!msg.has_teardown()) {
    // Start multicast forwarders.
    if (mdns_fwd == mdns_fwds_.end()) {
      LOG(INFO) << "Enabling mDNS forwarding for device " << dev_ifname;
      auto fwd = std::make_unique<MulticastForwarder>(
          dev_ifname, kMdnsMcastAddress, kMdnsMcastAddress6, kMdnsPort);
      fwd->Init();
      mdns_fwd = mdns_fwds_.emplace(dev_ifname, std::move(fwd)).first;
    }

    LOG(INFO) << "Starting mDNS forwarding between " << dev_ifname << " and "
              << msg.br_ifname();
    if (!mdns_fwd->second->AddGuest(msg.br_ifname())) {
      LOG(WARNING) << "mDNS forwarder could not be started between "
                   << dev_ifname << " and " << msg.br_ifname();
    }

    if (ssdp_fwd == ssdp_fwds_.end()) {
      LOG(INFO) << "Enabling SSDP forwarding for device " << dev_ifname;
      auto fwd = std::make_unique<MulticastForwarder>(
          dev_ifname, kSsdpMcastAddress, kSsdpMcastAddress6, kSsdpPort);
      fwd->Init();
      ssdp_fwd = ssdp_fwds_.emplace(dev_ifname, std::move(fwd)).first;
    }

    LOG(INFO) << "Starting SSDP forwarding between " << dev_ifname << " and "
              << msg.br_ifname();
    if (!ssdp_fwd->second->AddGuest(msg.br_ifname())) {
      LOG(WARNING) << "SSDP forwarder could not be started on " << dev_ifname
                   << " and " << msg.br_ifname();
    }

    if (bcast_fwd == bcast_fwds_.end()) {
      LOG(INFO) << "Enabling broadcast forwarding for device " << dev_ifname;
      auto fwd = std::make_unique<BroadcastForwarder>(dev_ifname);
      fwd->Init();
      bcast_fwd = bcast_fwds_.emplace(dev_ifname, std::move(fwd)).first;
    }

    LOG(INFO) << "Starting broadcast forwarding between " << dev_ifname
              << " and " << msg.br_ifname();
    if (!bcast_fwd->second->AddGuest(msg.br_ifname())) {
      LOG(WARNING) << "Broadcast forwarder could not be started on "
                   << dev_ifname << " and " << msg.br_ifname();
    }

    return;
  }

  if (msg.has_br_ifname()) {
    // A bridge interface is removed.
    if (mdns_fwd != mdns_fwds_.end()) {
      LOG(INFO) << "Disabling mDNS forwarding between " << dev_ifname << " and "
                << msg.br_ifname();
      mdns_fwd->second->RemoveGuest(msg.br_ifname());
    }
    if (ssdp_fwd != ssdp_fwds_.end()) {
      LOG(INFO) << "Disabling SSDP forwarding between " << dev_ifname << " and "
                << msg.br_ifname();
      ssdp_fwd->second->RemoveGuest(msg.br_ifname());
    }
    if (bcast_fwd != bcast_fwds_.end()) {
      LOG(INFO) << "Disabling broadcast forwarding between " << dev_ifname
                << " and " << msg.br_ifname();
      bcast_fwd->second->RemoveGuest(msg.br_ifname());
    }
    return;
  }

  // A physical interface is removed.
  if (mdns_fwd != mdns_fwds_.end()) {
    LOG(INFO) << "Disabling mDNS forwarding for physical interface "
              << dev_ifname;
    mdns_fwds_.erase(mdns_fwd);
  }
  if (ssdp_fwd != ssdp_fwds_.end()) {
    LOG(INFO) << "Disabling SSDP forwarding for physical interface "
              << dev_ifname;
    ssdp_fwds_.erase(ssdp_fwd);
  }
  if (bcast_fwd != bcast_fwds_.end()) {
    LOG(INFO) << "Disabling broadcast forwarding for physical interface "
              << dev_ifname;
    bcast_fwds_.erase(bcast_fwd);
  }
}

}  // namespace patchpanel

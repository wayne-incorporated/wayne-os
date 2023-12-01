// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <unistd.h>

#include <base/command_line.h>
#include <base/files/scoped_file.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <brillo/daemons/daemon.h>
#include <net-base/ipv6_address.h>

#include "patchpanel/minijailed_process_runner.h"
#include "patchpanel/ndproxy.h"
#include "patchpanel/system.h"

void OnSocketReadReady(patchpanel::NDProxy* proxy, int fd) {
  proxy->ReadAndProcessOnePacket(fd);
}

void OnGuestIpDiscovery(int if_id, const net_base::IPv6Address& ip6addr) {
  patchpanel::System system;
  const std::string ifname = system.IfIndextoname(if_id);
  const std::string ip6_str = ip6addr.ToString();

  patchpanel::MinijailedProcessRunner runner;
  if (runner.ip6("route", "replace", {ip6_str + "/128", "dev", ifname}) != 0) {
    LOG(WARNING) << "Failed to setup the IPv6 route for interface " << ifname;
  }
}

// Stand-alone daemon to proxy ND frames between a pair of interfaces
// Usage: ndproxyd $physical_ifname $guest_ifname
int main(int argc, char* argv[]) {
  base::CommandLine::Init(argc, argv);
  base::CommandLine* cl = base::CommandLine::ForCurrentProcess();
  base::CommandLine::StringVector args = cl->GetArgs();
  if (args.size() < 2) {
    LOG(ERROR) << "Missing command line arguments; exiting";
    return EXIT_FAILURE;
  }

  brillo::Daemon daemon;

  patchpanel::System system;
  if (!system.SysNetSet(patchpanel::System::SysNet::kIPv6AcceptRA, "2",
                        args[0])) {
    LOG(ERROR) << "Failed to enable net.ipv6.conf." << args[0] << ".accept_ra";
    return EXIT_FAILURE;
  }
  if (!system.SysNetSet(patchpanel::System::SysNet::kIPv6Forward, "1")) {
    LOG(ERROR) << "Failed to enable net.ipv6.conf.all.forwarding.";
    return EXIT_FAILURE;
  }

  patchpanel::NDProxy proxy;
  if (!proxy.Init()) {
    PLOG(ERROR) << "Failed to initialize NDProxy internal state";
    return EXIT_FAILURE;
  }

  int ifid_host = system.IfNametoindex(args[0]);
  if (ifid_host == 0) {
    LOG(ERROR) << "Host-bound network interface " << args[0]
               << " does not exist.";
    return EXIT_FAILURE;
  }

  // Crostini depends on another daemon (LXD) creating the guest bridge
  // interface. This can take a few seconds, so retry if necessary.
  int ifid_guest = 0;
  for (int i = 0; i < 6; i++) {
    if (i != 0) {
      usleep(10 * 1000 * 1000 /* 10 seconds */);
    }
    ifid_guest = system.IfNametoindex(args[1]);
    if (ifid_guest == 0) {
      // Guest bridge doesn't exist yet, try again later.
      continue;
    }
  }
  if (ifid_guest == 0) {
    LOG(ERROR) << "Guest-bound network interface " << args[1]
               << " does not exist after retrying.";
    return EXIT_FAILURE;
  }

  proxy.StartRSRAProxy(ifid_host, ifid_guest);
  proxy.StartNSNAProxy(ifid_host, ifid_guest);
  proxy.StartNSNAProxy(ifid_guest, ifid_host);
  proxy.RegisterOnGuestIpDiscoveryHandler(
      base::BindRepeating(&OnGuestIpDiscovery));

  base::ScopedFD fd = patchpanel::NDProxy::PreparePacketSocket();
  if (!fd.is_valid()) {
    PLOG(ERROR) << "Failed to initialize data socket";
    return EXIT_FAILURE;
  }

  std::unique_ptr<base::FileDescriptorWatcher::Controller> watcher =
      base::FileDescriptorWatcher::WatchReadable(
          fd.get(), base::BindRepeating(&OnSocketReadReady, &proxy, fd.get()));

  return daemon.Run();
}

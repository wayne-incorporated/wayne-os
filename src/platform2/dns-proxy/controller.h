// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DNS_PROXY_CONTROLLER_H_
#define DNS_PROXY_CONTROLLER_H_

#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>

#include <base/memory/weak_ptr.h>
#include <brillo/daemons/dbus_daemon.h>
#include <brillo/process/process_reaper.h>
#include <chromeos/patchpanel/dbus/client.h>
#include <chromeos/patchpanel/message_dispatcher.h>
#include <shill/dbus/client/client.h>

#include "dns-proxy/chrome_features_service_client.h"
#include "dns-proxy/ipc.pb.h"
#include "dns-proxy/metrics.h"
#include "dns-proxy/proxy.h"
#include "dns-proxy/resolv_conf.h"

namespace dns_proxy {

// The parent process for the service. Responsible for managing the proxy
// subprocesses.
class Controller : public brillo::DBusDaemon {
 public:
  explicit Controller(const std::string& progname);
  // For testing.
  explicit Controller(std::unique_ptr<ResolvConf> resolv_conf);

  Controller(const Controller&) = delete;
  Controller& operator=(const Controller&) = delete;
  ~Controller() = default;

 protected:
  int OnInit() override;
  void OnShutdown(int*) override;

 private:
  struct ProxyProc {
    ProxyProc() : pid(0) {}
    ProxyProc(Proxy::Type type, const std::string& ifname) : pid(0) {
      opts.type = type;
      opts.ifname = ifname;
    }

    friend std::ostream& operator<<(std::ostream& stream,
                                    const Controller::ProxyProc& proc) {
      stream << proc.opts;
      if (proc.pid > 0) {
        stream << "(pid: " << proc.pid << ")";
      }
      return stream;
    }

    // |pid| is intentionally excluded as only the strings are used as a key.
    bool operator<(const ProxyProc& that) const {
      return (opts.type < that.opts.type || opts.ifname < that.opts.ifname);
    }

    pid_t pid;
    Proxy::Options opts;
  };

  struct ProxyRestarts {
    static constexpr int kRestartLimit = 10;
    static constexpr base::TimeDelta kRestartWindow = base::Seconds(20);

    bool is_valid() const { return count > 0; }

    bool try_next() {
      if (base::Time::Now() - kRestartWindow <= since)
        return (--count > 0);

      since = base::Time::Now();
      count = kRestartLimit;
      return true;
    }

    base::Time since{base::Time::Now()};
    int count{kRestartLimit};
  };

  void Setup();
  void SetupPatchpanel();
  void OnPatchpanelReady(bool success);
  void OnPatchpanelReset(bool reset);
  void OnShillReady(bool success);
  void OnShillReset(bool reset);

  void RunProxy(Proxy::Type type, const std::string& ifname = "");
  void KillProxy(Proxy::Type type,
                 const std::string& ifname = "",
                 bool forget = true);
  void Kill(const ProxyProc& proc, bool forget = true);
  void OnProxyExit(pid_t pid, const siginfo_t& siginfo);
  void EvalProxyExit(const ProxyProc& proc);
  bool RestartProxy(const ProxyProc& proc);

  // Callback to be triggered when there is a message from the proxy. On
  // failure, restart the listener and the sender of the message (system
  // proxy).
  void OnProxyAddrMessageFailure();
  void OnProxyAddrMessage(const ProxyAddrMessage& msg);

  // Callback used to run/kill default proxy based on its dependencies.
  // |has_deps| will be true if either VPN or a single-networked guest OS is
  // running.
  void EvalDefaultProxyDeps(bool has_deps);

  // Notified by shill whenever the default device changes.
  void OnDefaultDeviceChanged(const shill::Client::Device* const device);

  // Notified by shill whenever a device is removed.
  void OnDeviceRemoved(const shill::Client::Device* const device);

  // Notified by patchpanel whenever a change occurs in one of its virtual
  // network devices.
  void OnVirtualDeviceChanged(patchpanel::Client::VirtualDeviceEvent event,
                              const patchpanel::Client::VirtualDevice& device);
  void VirtualDeviceAdded(const patchpanel::Client::VirtualDevice& device);

  // Triggered by the Chrome features client in response to checking
  // IsDNSProxyEnabled.
  void OnFeatureEnabled(std::optional<bool> enabled);

  FRIEND_TEST(ControllerTest, SetProxyAddrs);
  FRIEND_TEST(ControllerTest, ClearProxyAddrs);

  const std::string progname_;
  brillo::ProcessReaper process_reaper_;
  std::set<ProxyProc> proxies_;
  std::map<ProxyProc, ProxyRestarts> restarts_;

  // Listener for system proxy's IP addresses to be written to /etc/resolv.conf.
  std::unique_ptr<patchpanel::MessageDispatcher<ProxyAddrMessage>>
      msg_dispatcher_;

  // Helper class to update resolv.conf entries.
  std::unique_ptr<ResolvConf> resolv_conf_;

  bool shill_ready_{false};
  std::unique_ptr<shill::Client> shill_;
  std::unique_ptr<patchpanel::Client> patchpanel_;

  bool is_shutdown_{false};

  std::optional<bool> feature_enabled_;
  std::unique_ptr<ChromeFeaturesServiceClient> features_;

  Metrics metrics_;

  base::WeakPtrFactory<Controller> weak_factory_{this};
};

}  // namespace dns_proxy

#endif  // DNS_PROXY_CONTROLLER_H_

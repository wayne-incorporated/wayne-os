// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PATCHPANEL_DHCP_SERVER_CONTROLLER_H_
#define PATCHPANEL_DHCP_SERVER_CONTROLLER_H_

#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/memory/weak_ptr.h>
#include <net-base/ipv4_address.h>
#include <shill/net/process_manager.h>

namespace patchpanel {

// This class manages the one IPv4 DHCP server on a certain network interface.
class DHCPServerController {
 public:
  using ExitCallback = shill::ProcessManager::ExitCallback;

  // The configuration of the DHCP server. The instance is read-only once
  // created, so the configuration is always valid.
  class Config {
   public:
    using DHCPOptions =
        std::vector<std::pair<uint8_t /*tag*/, std::string /*content*/>>;

    // Creates the Config instance if the arguments are valid.
    // |host_cidr| is CIDR of the DHCP server. Its prefix_length() determines
    // the subnet that the DHCP server serves.
    // |start_ip| and |end_ip| defines the DHCP IP range, which should be under
    // the same subnet as the DHCP server serves.
    // |dns_servers| is the list of DNS servers.
    // |domain_searches| is the list of the domain search.
    // |mtu| is the MTU of the downstream. std::nullopt means the default value.
    // |dhcp_options| is the list of the DHCP options.
    static std::optional<Config> Create(
        const net_base::IPv4CIDR& host_cidr,
        const net_base::IPv4Address& start_ip,
        const net_base::IPv4Address& end_ip,
        const std::vector<net_base::IPv4Address>& dns_servers,
        const std::vector<std::string>& domain_searches,
        const std::optional<int>& mtu,
        const DHCPOptions& dhcp_options);

    // Getter methods of each field.
    const std::string& host_ip() const { return host_ip_; }
    const std::string& netmask() const { return netmask_; }
    const std::string& start_ip() const { return start_ip_; }
    const std::string& end_ip() const { return end_ip_; }
    const std::string& dns_servers() const { return dns_servers_; }
    const std::string& domain_searches() const { return domain_searches_; }
    const std::string& mtu() const { return mtu_; }
    const DHCPOptions& dhcp_options() const { return dhcp_options_; }

   private:
    Config(const std::string& host_ip,
           const std::string& netmask,
           const std::string& start_ip,
           const std::string& end_ip,
           const std::string& dns_servers,
           const std::string& domain_searches,
           const std::string& mtu,
           const DHCPOptions& dhcp_options);

    friend std::ostream& operator<<(std::ostream& os, const Config& config);

    std::string host_ip_;
    std::string netmask_;
    std::string start_ip_;
    std::string end_ip_;
    // The comma-split string for the list of DNS servers.
    std::string dns_servers_;
    // The comma-split string for the list of domain search.
    std::string domain_searches_;
    // Empty if the MTU is default value.
    std::string mtu_;
    // The extra DHCP options.
    DHCPOptions dhcp_options_;
  };

  explicit DHCPServerController(const std::string& ifname);

  DHCPServerController(const DHCPServerController&) = delete;
  DHCPServerController& operator=(const DHCPServerController&) = delete;

  virtual ~DHCPServerController();

  // Injects the mock ProcessManager for testing.
  void set_process_manager_for_testing(shill::ProcessManager* process_manager) {
    process_manager_ = process_manager;
  }

  // Starts a DHCP server at the |ifname_| interface. Returns true if the server
  // is created successfully. Note that if the previous server process is still
  // running, then returns false and does nothing. |exit_callback| is called if
  // the server process is exited unexpectedly.
  bool Start(const Config& config, ExitCallback exit_callback);

  // Stops the DHCP server. No-op if the server is not running.
  void Stop();

  // Returns true if the dnsmasq process is running.
  bool IsRunning() const;

 private:
  // Callback when the process is exited unexpectedly.
  void OnProcessExitedUnexpectedly(int exit_status);

  // The network interface that the DHCP server listens.
  const std::string ifname_;

  // The process manager to create the dnsmasq subprocess.
  shill::ProcessManager* process_manager_;

  // The pid of the dnsmasq process, nullopt iff the process is not running.
  std::optional<pid_t> pid_;
  // The configuration of the dnsmasq process, nullopt iff the process is not
  // running.
  std::optional<Config> config_;
  // The callback that is called when the dnsmasq process is exited
  // unexpectedly, null state iff the process is not running.
  ExitCallback exit_callback_;

  base::WeakPtrFactory<DHCPServerController> weak_ptr_factory_{this};
};

}  // namespace patchpanel

#endif  // PATCHPANEL_DHCP_SERVER_CONTROLLER_H_

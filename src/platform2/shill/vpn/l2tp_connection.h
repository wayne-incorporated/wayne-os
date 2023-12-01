// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_VPN_L2TP_CONNECTION_H_
#define SHILL_VPN_L2TP_CONNECTION_H_

#include <map>
#include <memory>
#include <string>

#include <base/files/file_path.h>
#include <base/files/scoped_temp_dir.h>
#include <base/functional/callback.h>
#include <libpasswordprovider/password_provider.h>

#include "shill/control_interface.h"
#include "shill/device_info.h"
#include "shill/event_dispatcher.h"
#include "shill/external_task.h"
#include "shill/net/process_manager.h"
#include "shill/service.h"
#include "shill/vpn/vpn_connection.h"
#include "shill/vpn/vpn_util.h"

namespace shill {

// TODO(b/165170125): Document temporary files.
class L2TPConnection : public VPNConnection, public RpcTaskDelegate {
 public:
  struct Config {
    std::string remote_ip;

    // Fields for xl2tpd.
    bool refuse_pap;
    bool require_auth;
    bool require_chap;
    bool length_bit;

    // Fields for pppd.
    bool lcp_echo;  // lcp echo connection monitoring
    std::string user;
    std::string password;
    bool use_login_password;
  };

  L2TPConnection(std::unique_ptr<Config> config,
                 std::unique_ptr<Callbacks> callbacks,
                 ControlInterface* control_interface,
                 DeviceInfo* device_info,
                 EventDispatcher* dispatcher,
                 ProcessManager* process_manager);
  ~L2TPConnection();

  // Implements RpcTaskDelegate.
  void GetLogin(std::string* user, std::string* password) override;
  void Notify(const std::string& reason,
              const std::map<std::string, std::string>& dict) override;

 private:
  friend class L2TPConnectionUnderTest;  // For unit tests.

  void OnConnect() override;
  void OnDisconnect() override;

  // Writes config file for pppd. |pppd_config_path_| will be filled with the
  // path to the file. Returns true on success.
  bool WritePPPDConfig();
  // Writes config file for xl2tpd. |l2tpd_config_path_| will be filled with the
  // path to the file. Returns true on success. This function needs to be called
  // after WritePPPDConfig() since this file contains the path to the ppp config
  // file.
  bool WriteL2TPDConfig();

  // Starts the xl2tpd process. Invokes NotifyFailure() on failure. Otherwise,
  // the connect process will be continued in Notify() (callback from the pppd
  // plugin).
  void StartXl2tpd();

  // Callback registered in DeviceInfo to invoke NotifyConnected() once
  // DeviceInfo notices the ppp interface.
  void OnLinkReady(std::unique_ptr<IPConfig::Properties> ipv4_properties,
                   const std::string& if_name,
                   int if_index);
  void OnXl2tpdExitedUnexpectedly(pid_t pid, int exit_code);

  // Callback for running `xl2tpd-control` to disconnect the connection.
  void OnXl2tpdControlDisconnectDone(int exit_code);

  std::unique_ptr<Config> config_;

  base::ScopedTempDir temp_dir_;

  // Paths to the runtime files. All the files are stored in |temp_dir_| and
  // thus will be removed when this class is destroyed.
  base::FilePath l2tpd_config_path_;
  base::FilePath l2tpd_control_path_;
  base::FilePath pppd_config_path_;

  std::unique_ptr<ExternalTask> external_task_;

  // External dependencies.
  ControlInterface* control_interface_;
  DeviceInfo* device_info_;
  std::unique_ptr<password_provider::PasswordProviderInterface>
      password_provider_;
  ProcessManager* process_manager_;
  std::unique_ptr<VPNUtil> vpn_util_;

  base::WeakPtrFactory<L2TPConnection> weak_factory_{this};
};

}  // namespace shill

#endif  // SHILL_VPN_L2TP_CONNECTION_H_

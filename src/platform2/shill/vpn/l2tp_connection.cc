// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/vpn/l2tp_connection.h"

#include <map>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/functional/callback.h>
#include <base/logging.h>
#include <base/strings/strcat.h>
#include <base/strings/string_piece.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <chromeos/dbus/service_constants.h>
#include <libpasswordprovider/password_provider.h>

#include "shill/ppp_daemon.h"
#include "shill/vpn/vpn_util.h"

namespace shill {

namespace {

constexpr char kRunDir[] = "/run/xl2tpd";
constexpr char kXl2tpdPath[] = "/usr/sbin/xl2tpd";
constexpr char kXl2tpdControlPath[] = "/usr/sbin/xl2tpd-control";
constexpr char kL2TPDConfigFileName[] = "l2tpd.conf";
constexpr char kL2TPDControlFileName[] = "l2tpd.control";
constexpr char kPPPDConfigFileName[] = "pppd.conf";

// Environment variable available to ppp plugin to know the resolved address
// of the L2TP server.
const char kLnsAddress[] = "LNS_ADDRESS";

// Constants used in the config file for xl2tpd.
const char kL2TPConnectionName[] = "managed";
const char kBpsParameter[] = "1000000";
const char kRedialTimeoutParameter[] = "2";
const char kMaxRedialsParameter[] = "30";

// xl2tpd (1.3.12 at the time of writing) uses fgets with a size 1024 buffer to
// get configuration lines. If a configuration line was longer than that and
// didn't contain the comment delimiter ';', it could be used to populate
// multiple configuration options.
constexpr size_t kXl2tpdMaxConfigurationLength = 1023;

}  // namespace

L2TPConnection::L2TPConnection(std::unique_ptr<Config> config,
                               std::unique_ptr<Callbacks> callbacks,
                               ControlInterface* control_interface,
                               DeviceInfo* device_info,
                               EventDispatcher* dispatcher,
                               ProcessManager* process_manager)
    : VPNConnection(std::move(callbacks), dispatcher),
      config_(std::move(config)),
      control_interface_(control_interface),
      device_info_(device_info),
      password_provider_(
          std::make_unique<password_provider::PasswordProvider>()),
      process_manager_(process_manager),
      vpn_util_(VPNUtil::New()) {}

// |external_task_| will be killed in its dtor if it is still running so no
// explicit cleanup is needed here.
L2TPConnection::~L2TPConnection() {}

void L2TPConnection::OnConnect() {
  temp_dir_ = vpn_util_->CreateScopedTempDir(base::FilePath(kRunDir));

  if (!WritePPPDConfig()) {
    NotifyFailure(Service::kFailureInternal,
                  "Failed to write pppd config file");
    return;
  }

  if (!WriteL2TPDConfig()) {
    NotifyFailure(Service::kFailureInternal,
                  "Failed to write xl2tpd config file");
    return;
  }

  StartXl2tpd();
}

void L2TPConnection::GetLogin(std::string* user, std::string* password) {
  LOG(INFO) << "Login requested.";
  if (config_->user.empty()) {
    LOG(ERROR) << "User not set.";
    return;
  }

  std::string password_local = config_->password;
  if (config_->use_login_password) {
    std::unique_ptr<password_provider::Password> login_password =
        password_provider_->GetPassword();
    if (login_password == nullptr || login_password->size() == 0) {
      LOG(ERROR) << "Unable to retrieve user password";
      return;
    }
    password_local =
        std::string(login_password->GetRaw(), login_password->size());
  } else if (password_local.empty()) {
    LOG(ERROR) << "Password not set.";
    return;
  }

  *user = config_->user;
  *password = password_local;
}

void L2TPConnection::Notify(const std::string& reason,
                            const std::map<std::string, std::string>& dict) {
  if (reason == kPPPReasonAuthenticating || reason == kPPPReasonAuthenticated) {
    // These are uninteresting intermediate states that do not indicate failure.
    return;
  }

  if (reason == kPPPReasonDisconnect) {
    // Ignored. Failure is handled when pppd exits since the exit status
    // contains more information.
    LOG(INFO) << "pppd disconnected";
    return;
  }

  if (reason == kPPPReasonExit) {
    if (!IsConnectingOrConnected()) {
      // We have notified the upper layer, or the disconnect is triggered by the
      // upper layer. In both cases, we don't need call NotifyFailure().
      LOG(INFO) << "pppd notifies us of " << reason << ", the current state is "
                << state();
      return;
    }
    NotifyFailure(PPPDaemon::ParseExitFailure(dict), "pppd disconnected");
    return;
  }

  // The message is kPPPReasonConnect. Checks if we are in the connecting state
  // at first.
  if (state() != State::kConnecting) {
    LOG(WARNING) << "pppd notifies us of " << reason
                 << ", the current state is " << state();
    return;
  }

  std::string interface_name = PPPDaemon::GetInterfaceName(dict);
  auto ipv4_properties = std::make_unique<IPConfig::Properties>(
      PPPDaemon::ParseIPConfiguration(dict));
  std::unique_ptr<IPConfig::Properties> ipv6_properties;

  // There is no IPv6 support for L2TP/IPsec VPN at this moment, so create a
  // blackhole route for IPv6 traffic after establishing a IPv4 VPN.
  ipv4_properties->blackhole_ipv6 = true;

  // Reduce MTU to the minimum viable for IPv6, since the IPsec layer consumes
  // some variable portion of the payload.  Although this system does not yet
  // support IPv6, it is a reasonable value to start with, since the minimum
  // IPv6 packet size will plausibly be a size any gateway would support, and
  // is also larger than the IPv4 minimum size.
  ipv4_properties->mtu = IPConfig::kMinIPv6MTU;

  ipv4_properties->method = kTypeVPN;

  // Notify() could be invoked either before or after the creation of the ppp
  // interface. We need to make sure that the interface is ready (by checking
  // DeviceInfo) before invoking the connected callback here.
  int interface_index = device_info_->GetIndex(interface_name);
  if (interface_index != -1) {
    NotifyConnected(interface_name, interface_index, std::move(ipv4_properties),
                    /*ipv6_properties=*/nullptr);
  } else {
    device_info_->AddVirtualInterfaceReadyCallback(
        interface_name,
        base::BindOnce(&L2TPConnection::OnLinkReady, weak_factory_.GetWeakPtr(),
                       std::move(ipv4_properties)));
  }
}

void L2TPConnection::OnDisconnect() {
  // Do the cleanup directly if xl2tpd is not running.
  if (!external_task_) {
    OnXl2tpdControlDisconnectDone(/*exit_code=*/0);
    return;
  }

  const std::vector<std::string> args = {"-c", l2tpd_control_path_.value(),
                                         "disconnect", kL2TPConnectionName};
  int pid = process_manager_->StartProcessInMinijail(
      FROM_HERE, base::FilePath(kXl2tpdControlPath), args, {},
      VPNUtil::BuildMinijailOptions(0),
      base::BindOnce(&L2TPConnection::OnXl2tpdControlDisconnectDone,
                     weak_factory_.GetWeakPtr()));
  if (pid != -1) {
    return;
  }
  LOG(ERROR) << "Failed to start xl2tpd-control";
  OnXl2tpdControlDisconnectDone(/*exit_code=*/0);
}

bool L2TPConnection::WritePPPDConfig() {
  pppd_config_path_ = temp_dir_.GetPath().Append(kPPPDConfigFileName);

  // Note that since StringPiece is used here, all the strings in this vector
  // MUST be alive until the end of this function. Unit tests are supposed to
  // catch the issue if this condition is not met.
  // TODO(b/200636771): Use proper mtu and mru.
  std::vector<base::StringPiece> lines = {
      "ipcp-accept-local",
      "ipcp-accept-remote",
      "refuse-eap",
      "noccp",
      "noauth",
      "crtscts",
      "mtu 1410",
      "mru 1410",
      "lock",
      "connect-delay 5000",
      "nodefaultroute",
      "nosystemconfig",
      "usepeerdns",
  };
  if (config_->lcp_echo) {
    lines.push_back("lcp-echo-failure 4");
    lines.push_back("lcp-echo-interval 30");
  }

  // This option avoids pppd logging to the fd of stdout (which is 1) (note that
  // pppd will still log to syslog). We need to put this option before the
  // plugin option below, since pppd will try to log when process that option,
  // and fd of 1 may point to the actual data channel, which in turn causes that
  // pppd sends the log string to the peer (see b/218437737 for an issue caused
  // by this).
  lines.push_back("logfd -1");

  const std::string plugin_line =
      base::StrCat({"plugin ", PPPDaemon::kShimPluginPath});
  lines.push_back(plugin_line);

  std::string contents = base::JoinString(lines, "\n");
  return vpn_util_->WriteConfigFile(pppd_config_path_, contents);
}

bool L2TPConnection::WriteL2TPDConfig() {
  CHECK(!pppd_config_path_.empty());

  // b/187984628: When UseLoginPassword is enabled, PAP must be refused to
  // prevent potential password leak to a malicious server.
  if (config_->use_login_password) {
    config_->refuse_pap = true;
  }

  l2tpd_config_path_ = temp_dir_.GetPath().Append(kL2TPDConfigFileName);

  std::vector<std::string> lines;
  lines.push_back(base::StringPrintf("[lac %s]", kL2TPConnectionName));

  // Fills in bool properties.
  auto bool_property = [](base::StringPiece key, bool value) -> std::string {
    return base::StrCat({key, " = ", value ? "yes" : "no"});
  };
  lines.push_back(bool_property("require chap", config_->require_chap));
  lines.push_back(bool_property("refuse pap", config_->refuse_pap));
  lines.push_back(
      bool_property("require authentication", config_->require_auth));
  lines.push_back(bool_property("length bit", config_->length_bit));
  lines.push_back(bool_property("redial", true));
  lines.push_back(bool_property("autodial", true));

  // Fills in string properties. Note that some values are input by users, we
  // need to check them to ensure that the generated config file will not be
  // polluted. See https://crbug.com/1077754. Note that the ordering of
  // properties in the config file does not matter, we use a vector instead of
  // map just for the ease of unit tests. Using StringPiece is safe here since
  // because there is no temporary string object when constructing this vector.
  const std::vector<std::pair<base::StringPiece, base::StringPiece>>
      string_properties = {
          {"lns", config_->remote_ip},
          {"name", config_->user},
          {"bps", kBpsParameter},
          {"redial timeout", kRedialTimeoutParameter},
          {"max redials", kMaxRedialsParameter},
          {"pppoptfile", pppd_config_path_.value()},
      };
  for (const auto& [key, value] : string_properties) {
    if (value.find('\n') != value.npos) {
      LOG(ERROR) << "The value for " << key << " contains newline characters";
      return false;
    }
    const auto line = base::StrCat({key, " = ", value});
    if (line.size() > kXl2tpdMaxConfigurationLength) {
      LOG(ERROR) << "Line length for " << key << " exceeds "
                 << kXl2tpdMaxConfigurationLength;
      return false;
    }
    lines.push_back(line);
  }

  std::string contents = base::JoinString(lines, "\n");
  return vpn_util_->WriteConfigFile(l2tpd_config_path_, contents);
}

void L2TPConnection::StartXl2tpd() {
  l2tpd_control_path_ = temp_dir_.GetPath().Append(kL2TPDControlFileName);

  std::vector<std::string> args = {
      "-c", l2tpd_config_path_.value(), "-C", l2tpd_control_path_.value(),
      "-D",  // prevents xl2tpd from detaching from the terminal and daemonizing
      "-l",  // lets xl2tpd use syslog
  };

  std::map<std::string, std::string> env = {
      {kLnsAddress, config_->remote_ip},
  };

  auto external_task_local = std::make_unique<ExternalTask>(
      control_interface_, process_manager_, weak_factory_.GetWeakPtr(),
      base::BindOnce(&L2TPConnection::OnXl2tpdExitedUnexpectedly,
                     weak_factory_.GetWeakPtr()));

  Error error;
  constexpr uint64_t kCapMask = CAP_TO_MASK(CAP_NET_ADMIN);
  if (!external_task_local->StartInMinijail(
          base::FilePath(kXl2tpdPath), &args, env,
          VPNUtil::BuildMinijailOptions(kCapMask), &error)) {
    NotifyFailure(Service::kFailureInternal,
                  base::StrCat({"Failed to start xl2tpd: ", error.message()}));
    return;
  }

  external_task_ = std::move(external_task_local);
}

void L2TPConnection::OnLinkReady(
    std::unique_ptr<IPConfig::Properties> ipv4_properties,
    const std::string& if_name,
    int if_index) {
  if (state() != State::kConnecting) {
    // Needs to do nothing here. The ppp interface is managed by the pppd
    // process so we don't need to remove it here.
    LOG(WARNING) << "OnLinkReady() called but the current state is " << state();
    return;
  }
  NotifyConnected(if_name, if_index, std::move(ipv4_properties),
                  /*ipv6_properties=*/nullptr);
}

void L2TPConnection::OnXl2tpdExitedUnexpectedly(pid_t pid, int exit_code) {
  external_task_ = nullptr;
  const std::string message =
      base::StringPrintf("xl2tpd exited unexpectedly with code=%d", exit_code);
  if (!IsConnectingOrConnected()) {
    LOG(WARNING) << message;
    return;
  }
  NotifyFailure(Service::kFailureInternal, message);
}

void L2TPConnection::OnXl2tpdControlDisconnectDone(int exit_code) {
  // Since this is only called in the disconnecting procedure, we only log this
  // uncommon event instead of reporting it to the upper layer.
  if (exit_code != 0) {
    LOG(ERROR) << "xl2tpd-control exited with code=" << exit_code;
  }

  // Kill xl2tpd if it is still running. Note that it is usually the case that
  // xl2tpd has disconnected the connection at this time, but this cannot be
  // guaranteed, but we don't have better signal for that. Some servers might be
  // unhappy when that happens (see b/234162302).
  external_task_ = nullptr;
  if (state() == State::kDisconnecting) {
    NotifyStopped();
  }
}

}  // namespace shill

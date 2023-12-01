// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "lorgnette/firewall_manager.h"

#include <unistd.h>

#include <algorithm>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/files/scoped_file.h>
#include <base/functional/bind.h>
#include <brillo/errors/error.h>

using std::string;

namespace lorgnette {

namespace {

const uint16_t kCanonBjnpPort = 8612;

}  // namespace

PortToken::PortToken(base::WeakPtr<FirewallManager> firewall_manager,
                     uint16_t port)
    : firewall_manager_(firewall_manager), port_(port) {}

PortToken::PortToken(PortToken&& token) : firewall_manager_(nullptr), port_(0) {
  firewall_manager_ = token.firewall_manager_;
  port_ = token.port_;

  token.firewall_manager_ = nullptr;
  token.port_ = 0;
}

PortToken::~PortToken() {
  if (firewall_manager_)
    firewall_manager_->ReleaseUdpPortAccess(port_);
}

FirewallManager::FirewallManager(const std::string& interface)
    : interface_(interface) {}

void FirewallManager::Init(
    std::unique_ptr<org::chromium::PermissionBrokerProxyInterface>
        permission_broker_proxy) {
  CHECK(!permission_broker_proxy_) << "Already started";

  if (!SetupLifelinePipe()) {
    return;
  }

  permission_broker_proxy_ = std::move(permission_broker_proxy);

  // This will connect the name owner changed signal in DBus object proxy,
  // The callback will be invoked as soon as service is avalilable and will
  // be cleared after it is invoked. So this will be an one time callback.
  permission_broker_proxy_->GetObjectProxy()->WaitForServiceToBeAvailable(
      base::BindOnce(&FirewallManager::OnServiceAvailable,
                     weak_factory_.GetWeakPtr()));

  // This will continuously monitor the name owner of the service. However,
  // it does not connect the name owner changed signal in DBus object proxy
  // for some reason. In order to connect the name owner changed signal,
  // either WaitForServiceToBeAvaiable or ConnectToSignal need to be invoked.
  // Since we're not interested in any signals from the proxy,
  // WaitForServiceToBeAvailable is used.
  permission_broker_proxy_->GetObjectProxy()->SetNameOwnerChangedCallback(
      base::BindRepeating(&FirewallManager::OnServiceNameChanged,
                          weak_factory_.GetWeakPtr()));
}

PortToken FirewallManager::RequestPixmaPortAccess() {
  // Request access for the well-known port used by the Pixma backend.
  return RequestUdpPortAccess(kCanonBjnpPort);
}

bool FirewallManager::SetupLifelinePipe() {
  if (lifeline_read_.is_valid()) {
    LOG(ERROR) << "Lifeline pipe already created";
    return false;
  }

  // Setup lifeline pipe.
  int fds[2];
  if (pipe(fds) != 0) {
    PLOG(ERROR) << "Failed to create lifeline pipe";
    return false;
  }
  lifeline_read_ = base::ScopedFD(fds[0]);
  lifeline_write_ = base::ScopedFD(fds[1]);

  return true;
}

void FirewallManager::OnServiceAvailable(bool service_available) {
  LOG(INFO) << "FirewallManager::OnServiceAvailable " << service_available;
  // Nothing to be done if proxy service is not available.
  if (!service_available) {
    return;
  }
  RequestAllPortsAccess();
}

void FirewallManager::OnServiceNameChanged(const string& old_owner,
                                           const string& new_owner) {
  LOG(INFO) << "FirewallManager::OnServiceNameChanged old " << old_owner
            << " new " << new_owner;
  // Nothing to be done if no owner is attached to the proxy service.
  if (new_owner.empty()) {
    return;
  }
  RequestAllPortsAccess();
}

void FirewallManager::RequestAllPortsAccess() {
  std::set<uint16_t> attempted_ports;
  attempted_ports.swap(requested_ports_);
  for (const auto& port : attempted_ports) {
    SendPortAccessRequest(port);
  }
}

void FirewallManager::SendPortAccessRequest(uint16_t port) {
  LOG(INFO) << "Received port access request for UDP port " << port;

  if (!permission_broker_proxy_) {
    LOG(INFO) << "Permission broker does not exist (yet); adding request for "
              << "port " << port << " to queue.";
    requested_ports_.insert(port);
    return;
  }

  bool allowed = false;
  // Pass the read end of the pipe to permission_broker, for it to monitor this
  // process.
  brillo::ErrorPtr error;
  if (!permission_broker_proxy_->RequestUdpPortAccess(
          port, interface_, base::ScopedFD(dup(lifeline_read_.get())), &allowed,
          &error)) {
    LOG(ERROR) << "Failed to request UDP port access: " << error->GetCode()
               << " " << error->GetMessage();
    return;
  }
  if (!allowed) {
    LOG(ERROR) << "Access request for UDP port " << port << " on interface "
               << interface_ << " is denied";
    return;
  }
  LOG(INFO) << "Access granted for UDP port " << port << " on interface "
            << interface_;
  requested_ports_.insert(port);
}

PortToken FirewallManager::RequestUdpPortAccess(uint16_t port) {
  SendPortAccessRequest(port);
  return PortToken(weak_factory_.GetWeakPtr(), port);
}

void FirewallManager::ReleaseUdpPortAccess(uint16_t port) {
  brillo::ErrorPtr error;
  bool success;
  if (requested_ports_.find(port) == requested_ports_.end()) {
    LOG(ERROR) << "UDP access has not been requested for port: " << port;
    return;
  }
  if (!permission_broker_proxy_) {
    requested_ports_.erase(port);
    return;
  }

  if (!permission_broker_proxy_->ReleaseUdpPort(port, interface_, &success,
                                                &error)) {
    LOG(ERROR) << "Failed to release UDP port access: " << error->GetCode()
               << " " << error->GetMessage();
    return;
  }
  if (!success) {
    LOG(ERROR) << "Release request for UDP port " << port << " on interface "
               << interface_ << " is denied";
    return;
  }
  LOG(INFO) << "Access released for UDP port " << port << " on interface "
            << interface_;
  requested_ports_.erase(port);
}

}  // namespace lorgnette

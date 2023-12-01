// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/vpn/vpn_connection.h"

#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <base/functional/callback.h>
#include <base/location.h>
#include <base/logging.h>
#include <base/strings/string_util.h>

namespace shill {

namespace {

std::string StateToString(VPNConnection::State state) {
  switch (state) {
    case VPNConnection::State::kIdle:
      return "Idle";
    case VPNConnection::State::kConnecting:
      return "Connecting";
    case VPNConnection::State::kConnected:
      return "Connected";
    case VPNConnection::State::kDisconnecting:
      return "Disconnecting";
    case VPNConnection::State::kStopped:
      return "Stopped";
    default:
      NOTREACHED();
  }
}

// Checks if |current_state| is in |allowed_states|, if not, crashes (in the
// debug environment) or leaves a log.
void CheckCallWithState(const std::string& call,
                        VPNConnection::State current_state,
                        std::set<VPNConnection::State> allowed_states) {
  if (allowed_states.find(current_state) != allowed_states.end()) {
    return;
  }

  std::vector<std::string> state_names;
  for (const auto state : allowed_states) {
    state_names.push_back(StateToString(state));
  }

  LOG(DFATAL) << call << " should only be called if the state is in {"
              << base::JoinString(state_names, ",")
              << "}, but current state is " << current_state;
}

}  // namespace

std::ostream& operator<<(std::ostream& stream,
                         const VPNConnection::State& state) {
  return stream << StateToString(state);
}

VPNConnection::VPNConnection(std::unique_ptr<Callbacks> callbacks,
                             EventDispatcher* dispatcher)
    : callbacks_(std::move(callbacks)),
      state_(State::kIdle),
      dispatcher_(dispatcher) {}
VPNConnection::~VPNConnection() = default;

void VPNConnection::Connect() {
  CheckCallWithState(__func__, state_, {State::kIdle});
  state_ = State::kConnecting;
  dispatcher_->PostTask(FROM_HERE, base::BindOnce(&VPNConnection::OnConnect,
                                                  weak_factory_.GetWeakPtr()));
}

void VPNConnection::Disconnect() {
  CheckCallWithState(__func__, state_, {State::kConnecting, State::kConnected});
  state_ = State::kDisconnecting;
  dispatcher_->PostTask(FROM_HERE, base::BindOnce(&VPNConnection::OnDisconnect,
                                                  weak_factory_.GetWeakPtr()));
}

void VPNConnection::ResetCallbacks(std::unique_ptr<Callbacks> callbacks) {
  callbacks_ = std::move(callbacks);
}

bool VPNConnection::IsConnectingOrConnected() const {
  return state_ == State::kConnecting || state_ == State::kConnected;
}

void VPNConnection::NotifyConnected(
    const std::string& link_name,
    int interface_index,
    std::unique_ptr<IPConfig::Properties> ipv4_properties,
    std::unique_ptr<IPConfig::Properties> ipv6_properties) {
  CheckCallWithState(__func__, state_, {State::kConnecting});
  state_ = State::kConnected;
  dispatcher_->PostTask(
      FROM_HERE,
      base::BindOnce(callbacks_->on_connected_cb, link_name, interface_index,
                     std::move(ipv4_properties), std::move(ipv6_properties)));
}

void VPNConnection::NotifyFailure(Service::ConnectFailure reason,
                                  base::StringPiece detail) {
  CheckCallWithState(__func__, state_,
                     {State::kConnecting, State::kConnected,
                      State::kDisconnecting, State::kStopped});
  LOG(ERROR) << "VPN connection failed, current state: " << state_
             << ", reason: " << Service::ConnectFailureToString(reason)
             << ", detail: " << detail;

  if (state_ == State::kDisconnecting || state_ == State::kStopped) {
    // We don't need to invoke callback to VPNDriver here since this is not a
    // connect failure, but a failure during disconnecting.
    return;
  }

  state_ = State::kDisconnecting;
  dispatcher_->PostTask(
      FROM_HERE, base::BindOnce(std::move(callbacks_->on_failure_cb), reason));
  dispatcher_->PostTask(FROM_HERE, base::BindOnce(&VPNConnection::OnDisconnect,
                                                  weak_factory_.GetWeakPtr()));
}

void VPNConnection::NotifyStopped() {
  CheckCallWithState(__func__, state_, {State::kDisconnecting});
  state_ = State::kStopped;
  dispatcher_->PostTask(FROM_HERE, std::move(callbacks_->on_stopped_cb));
}

}  // namespace shill

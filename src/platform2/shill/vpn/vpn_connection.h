// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_VPN_VPN_CONNECTION_H_
#define SHILL_VPN_VPN_CONNECTION_H_

#include <memory>
#include <string>
#include <utility>

#include <base/functional/callback.h>

#include "shill/event_dispatcher.h"
#include "shill/ipconfig.h"
#include "shill/mockable.h"
#include "shill/net/process_manager.h"
#include "shill/service.h"

namespace shill {

// A VPNConnection is a base class represents a VPN connection. It contains a
// state, which is driven by either external calls (Connect()/Disconnect()) or
// internal events (Notify*() functions). Different with VPNDriver, this class
// is supposed to be created before connecting to a VPN service and be destroyed
// after the connection is finished.
class VPNConnection {
 public:
  enum class State {
    // This instance is just initialized.
    kIdle,
    // This instance is trying to connect to a VPN service.
    kConnecting,
    // The VPN connection has been established.
    kConnected,
    // The VPN connection is not available now. It means either a failure or a
    // disconnection initiated by the user.
    kDisconnecting,
    // Resources have been released and this instance can be destroyed safely.
    kStopped,
  };

  struct Callbacks {
    // The state has been changed from kConnecting to kConnected. Use
    // RepeatingCallback here since some VPNs may do a reconnect by themselves.
    // and thus kConnected state can be entered for several times.
    using OnConnectedCallback = base::RepeatingCallback<void(
        const std::string& link_name,
        int interface_index,
        std::unique_ptr<IPConfig::Properties> ipv4_properties,
        std::unique_ptr<IPConfig::Properties> ipv6_properties)>;
    // The state has been changed to kDisconnecting caused by a failure
    // unexpectedly (i.e., Disconnect() is not called).
    using OnFailureCallback = base::OnceCallback<void(Service::ConnectFailure)>;
    // The state has been change to kStopped.
    using OnStoppedCallback = base::OnceClosure;

    Callbacks(OnConnectedCallback on_connected,
              OnFailureCallback on_failure,
              OnStoppedCallback on_stopped)
        : on_connected_cb(on_connected),
          on_failure_cb(std::move(on_failure)),
          on_stopped_cb(std::move(on_stopped)) {}

    OnConnectedCallback on_connected_cb;
    OnFailureCallback on_failure_cb;
    OnStoppedCallback on_stopped_cb;
  };

  explicit VPNConnection(std::unique_ptr<Callbacks> callbacks,
                         EventDispatcher* dispatcher);

  // Note that we cannot guarantee that when destructor is called, the state is
  // kIdle or kStopped, so the derived class should check the state and release
  // resources (e.g., call OnDisconnect()) if needed.
  virtual ~VPNConnection();

  void Connect();
  void Disconnect();

  void ResetCallbacks(std::unique_ptr<Callbacks> callbacks);

  State state() { return state_; }
  bool IsConnectingOrConnected() const;

 private:
  // Implemented by the derived class for the real connect/disconnect logic.
  // Note that these functions will be invoked asynchronously by a PostTask() in
  // Connect()/Disconnect().
  // In OnConnect(), the derived class is supposed to initiate the connection,
  // and call NotifyConnected() on connected, or NotifyFailure() on a failure.
  virtual void OnConnect() = 0;
  // In OnDisconnect(), the derived class is supposed to disconnect the
  // connection (if connected) or stop the connecting procedure (if connecting),
  // and clean up all the resources used in this connection. Once the cleanup is
  // done, the derived class should call NotifyStopped(). Note that this
  // function will be called not only when the user initiates the disconnection,
  // but also in NotifyFailure().
  virtual void OnDisconnect() = 0;

 protected:
  // This group of functions should be called by the derived class to indicate
  // an event, change the state, and invoke the corresponding callback. See the
  // comments above for the callbacks for their meanings. Note that the
  // callbacks will be invoked asynchronously by a PostTask() in these
  // functions.
  void NotifyConnected(const std::string& link_name,
                       int interface_index,
                       std::unique_ptr<IPConfig::Properties> ipv4_properties,
                       std::unique_ptr<IPConfig::Properties> ipv6_properties);
  // Note that NotifyFailure() will also invoke OnDisconnect() on the derived
  // class (by a PostTask()), and thus the derived class don't need to do any
  // clean up other than calling this function on failures.
  mockable void NotifyFailure(Service::ConnectFailure reason,
                              base::StringPiece detail);
  void NotifyStopped();

  EventDispatcher* dispatcher() { return dispatcher_; }

 private:
  // For able to modify |state_| in the tests.
  friend class IPsecConnectionUnderTest;
  friend class L2TPConnectionUnderTest;
  friend class VPNConnectionUnderTest;

  std::unique_ptr<Callbacks> callbacks_;
  State state_;
  EventDispatcher* dispatcher_;
  base::WeakPtrFactory<VPNConnection> weak_factory_{this};
};

std::ostream& operator<<(std::ostream& stream,
                         const VPNConnection::State& state);

}  // namespace shill

#endif  // SHILL_VPN_VPN_CONNECTION_H_

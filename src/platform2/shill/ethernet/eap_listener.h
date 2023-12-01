// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_ETHERNET_EAP_LISTENER_H_
#define SHILL_ETHERNET_EAP_LISTENER_H_

#include <memory>
#include <string>

#include <base/functional/callback.h>

namespace shill {

class IOHandler;
class IOHandlerFactory;
class ScopedSocketCloser;
class Sockets;

// Listens for EAP packets on |interface_index| and invokes a
// callback when a request frame arrives.
class EapListener {
 public:
  using EapRequestReceivedCallback = base::RepeatingCallback<void()>;

  EapListener(int interface_index, const std::string& link_name);
  EapListener(const EapListener&) = delete;
  EapListener& operator=(const EapListener&) = delete;

  virtual ~EapListener();

  // Create a socket for tranmission and reception.  Returns true
  // if successful, false otherwise.
  virtual bool Start();

  // Destroy the client socket.
  virtual void Stop();

  // Setter for |request_received_callback_|.
  virtual void set_request_received_callback(
      const EapRequestReceivedCallback& callback) {
    request_received_callback_ = callback;
  }

 private:
  friend class EapListenerTest;

  // The largest EAP packet we expect to receive.
  static const size_t kMaxEapPacketLength;

  // Creates |socket_|.  Returns true on succes, false on failure.
  bool CreateSocket();

  // Retrieves an EAP packet from |socket_|.  This is the callback method
  // configured on |receive_request_handler_|.
  void ReceiveRequest(int fd);

  const std::string& LoggingTag();

  // Factory to use for creating an input handler.
  IOHandlerFactory* io_handler_factory_;

  // The interface index for the device to monitor.
  const int interface_index_;

  // The link name of the parent device (for logging).
  const std::string link_name_;

  // Callback handle to invoke when an EAP request is received.
  EapRequestReceivedCallback request_received_callback_;

  // Sockets instance to perform socket calls on.
  std::unique_ptr<Sockets> sockets_;

  // Receive socket configured to receive PAE (Port Access Entity) packets.
  int socket_;

  // Scoped socket closer for the receive |socket_|.
  std::unique_ptr<ScopedSocketCloser> socket_closer_;

  // Input handler for |socket_|.  Calls ReceiveRequest().
  std::unique_ptr<IOHandler> receive_request_handler_;
};

}  // namespace shill

#endif  // SHILL_ETHERNET_EAP_LISTENER_H_

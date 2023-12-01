// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HERMES_SOCKET_INTERFACE_H_
#define HERMES_SOCKET_INTERFACE_H_

#include <cstdint>

#include <base/functional/callback.h>

namespace hermes {

// Interface representing a socket used to communicate with a modem.
class SocketInterface {
 public:
  using DataAvailableCallback = base::RepeatingCallback<void(SocketInterface*)>;

  enum class Type {
    kQrtr,
    kMbim,
  };

  virtual ~SocketInterface() {}

  // Sets callback to run when data is available to be read from the
  // socket. Note that the client is responsible for ensuring that the
  // SocketInterface* passed as a parameter to the callback remains valid while
  // the callback is being run.
  virtual void SetDataAvailableCallback(DataAvailableCallback cb) = 0;

  // Opens the socket. Returns whether socket is open at the end of the call.
  virtual bool Open() = 0;
  // Closes the socket.
  virtual void Close() = 0;
  // Returns whether the socket is valid to be read from and written to.
  virtual bool IsValid() const = 0;
  // Returns the type of socket represented by this class.
  virtual Type GetType() const = 0;

  // Requests a service start (e.g. a QMI or MBIM service). The caller is
  // responsible for handling any (potentially asynchronous) response to the
  // service request. Returns whether the request was successfully sent.
  virtual bool StartService(uint32_t service,
                            uint16_t version_major,
                            uint16_t version_minor) = 0;
  // Requests a service stop. The caller is responsible for handling any
  // (potentially asynchronous) response to the service end request. Returns
  // whether the request was successfully sent.
  virtual bool StopService(uint32_t service,
                           uint16_t version_major,
                           uint16_t version_minor) = 0;

  // Receives data into the provided data buffer. On success, returns the bytes
  // received out. On failure, returns -1.
  virtual int Recv(void* buf, size_t size, void* metadata) = 0;
  // Sends provided data buffer. On success, returns the bytes sent out. On
  // failure, returns -1.
  virtual int Send(const void* data, size_t size, const void* metadata) = 0;
};

}  // namespace hermes

#endif  // HERMES_SOCKET_INTERFACE_H_

// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MEDIA_PERCEPTION_DBUS_SERVICE_H_
#define MEDIA_PERCEPTION_DBUS_SERVICE_H_

#include <functional>
#include <string>
#include <utility>
#include <vector>

namespace mri {

// TODO(lasoren): Move these string and enum definitions to a separate file from
// this abstract base class.
constexpr char kMediaPerceptionServiceName[] = "org.chromium.MediaPerception";
constexpr char kMediaPerceptionServicePath[] = "/org/chromium/MediaPerception";

// The following values are meant to be used in checking dbus method call names.
constexpr char kState[] = "State";
constexpr char kGetDiagnostics[] = "GetDiagnostics";
constexpr char kDetectionSignal[] = "MediaPerceptionDetection";
constexpr char kBootstrapMojoConnection[] = "BootstrapMojoConnection";

enum Service { MEDIA_PERCEPTION };

enum Method { STATE, GET_DIAGNOSTICS, BOOTSTRAP_MOJO_CONNECTION };

enum Signal { MEDIA_PERCEPTION_DETECTION };

// This class provides a generic base class for encapsulating methods used for
// communicating over D-Bus.
class DbusService {
 public:
  virtual ~DbusService() {}

  // Handler for incoming method calls. |bytes| stores the reply message.
  using MessageHandler = std::function<bool(const Method method,
                                            const uint8_t* arg_bytes,
                                            const int arg_size,
                                            std::vector<uint8_t>* bytes)>;

  // This handler function should be set after the DBusService is instantiated
  // to handle incoming D-Bus messages.
  void SetMessageHandler(MessageHandler message_handler) {
    message_handler_ = std::move(message_handler);
  }

  std::string ServiceEnumToServiceName(const Service service) {
    switch (service) {
      case MEDIA_PERCEPTION:
        return kMediaPerceptionServiceName;
    }
    return "";
  }

  std::string ServiceEnumToServicePath(const Service service) {
    switch (service) {
      case MEDIA_PERCEPTION:
        return kMediaPerceptionServicePath;
    }
    return "";
  }

  std::string MethodEnumToMethodName(const Method method) {
    switch (method) {
      case STATE:
        return kState;
      case GET_DIAGNOSTICS:
        return kGetDiagnostics;
      case BOOTSTRAP_MOJO_CONNECTION:
        return kBootstrapMojoConnection;
    }
    return "";
  }

  std::string SignalEnumToSignalName(const Signal signal) {
    switch (signal) {
      case MEDIA_PERCEPTION_DETECTION:
        return kDetectionSignal;
    }
    return "";
  }

  // Pure virtuals for the interfaces that need to be available in the
  // implementation.
  virtual void Connect(const Service service) = 0;
  virtual bool IsConnected() const = 0;
  virtual bool PublishSignal(const Signal signal,
                             const std::vector<uint8_t>* bytes) = 0;
  virtual void PollMessageQueue() = 0;

 protected:
  MessageHandler message_handler_;

  // Stores the service enum for the active connection.
  Service service_;
};

}  // namespace mri

#endif  // MEDIA_PERCEPTION_DBUS_SERVICE_H_

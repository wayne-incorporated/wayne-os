// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "media_perception/cros_dbus_service.h"

#include <vector>

#include <base/check.h>
#include <base/logging.h>

namespace mri {

namespace {

// We need to poll the dbus message queue periodically for handling new method
// calls. This variable defines the polling period in milliseconds, and it will
// affect the responsiveness of the dbus server and cpu usage.
constexpr int kPollingPeriodMilliSeconds = 1;

std::string RequestOwnershipReplyToString(unsigned int reply) {
  switch (reply) {
    case DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER:
      return "DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER";
    case DBUS_REQUEST_NAME_REPLY_IN_QUEUE:
      return "DBUS_REQUEST_NAME_REPLY_IN_QUEUE";
    case DBUS_REQUEST_NAME_REPLY_EXISTS:
      return "DBUS_REQUEST_NAME_REPLY_EXISTS";
    case DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER:
      return "DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER";
    default:
      return "UNKNOWN_TYPE";
  }
}

}  // namespace

CrOSDbusService::~CrOSDbusService() {
  // Applications should unref the shared connection created with
  // dbus_bus_get().
  if (IsConnected()) {
    std::lock_guard<std::mutex> lock(connection_lock_);
    dbus_connection_unref(connection_);
    connection_ = nullptr;
  }
}

void CrOSDbusService::Connect(const Service service) {
  if (IsConnected()) {
    LOG(WARNING) << "Dbus connection has already been established.";
    return;
  }

  DBusError error;
  dbus_error_init(&error);

  if (dbus_error_is_set(&error)) {
    LOG(ERROR) << "Dbus connection error: " << error.message;
    dbus_error_free(&error);
    return;
  }

  std::lock_guard<std::mutex> lock(connection_lock_);
  connection_ = dbus_bus_get(DBUS_BUS_SYSTEM, &error);
  CHECK(connection_ != nullptr) << "Connection is nullptr.";

  // This request will return -1 if error is set, and a non-negative number
  // otherwise.
  const int reply = dbus_bus_request_name(
      connection_, ServiceEnumToServiceName(service).c_str(),
      DBUS_NAME_FLAG_REPLACE_EXISTING, &error);

  CHECK(reply >= 0) << "Failed to own media perception service: "
                    << error.message;

  DLOG(INFO) << "dbus_connection_get_server_id = "
             << dbus_connection_get_server_id(connection_);
  DLOG(INFO) << "dbus_bus_get_id = " << dbus_bus_get_id(connection_, &error);
  DLOG(INFO) << "dbus_get_local_machine_id = " << dbus_get_local_machine_id();
  DLOG(INFO) << "dbus_request_name() has reply: "
             << RequestOwnershipReplyToString(reply);

  // Store the service enum for the active connection.
  service_ = service;
}

bool CrOSDbusService::IsConnected() const {
  std::lock_guard<std::mutex> lock(connection_lock_);
  return connection_ != nullptr;
}

bool CrOSDbusService::PublishSignal(const mri::Signal signal,
                                    const std::vector<uint8_t>* bytes) {
  if (bytes == nullptr) {
    LOG(WARNING) << "Failed to publish signal - bytes is nullptr.";
    return false;
  }

  if (!IsConnected()) {
    LOG(WARNING) << "Failed to publish signal - not connected.";
    return false;
  }

  DBusMessage* message =
      dbus_message_new_signal(ServiceEnumToServicePath(service_).c_str(),
                              ServiceEnumToServiceName(service_).c_str(),
                              SignalEnumToSignalName(signal).c_str());

  if (message == nullptr) {
    LOG(WARNING) << "Out of memory!";
    return false;
  }

  if (!dbus_message_append_args(message, DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, bytes,
                                bytes->size(), DBUS_TYPE_INVALID)) {
    LOG(WARNING) << "Out of memory!";
    dbus_message_unref(message);
    return false;
  }

  {
    std::lock_guard<std::mutex> lock(connection_lock_);
    dbus_connection_send(connection_, message, nullptr);
    dbus_connection_flush(connection_);
  }

  dbus_message_unref(message);
  return true;
}

void CrOSDbusService::PollMessageQueue() {
  if (!IsConnected()) {
    LOG(WARNING) << "Failed to poll message queue.";
    return;
  }

  // This loop will continue until another management process explicitly kills
  // the current program.
  while (true) {
    DBusMessage* message = nullptr;

    {
      std::lock_guard<std::mutex> lock(connection_lock_);

      // Non-blocking read of the next available message.
      dbus_connection_read_write(connection_, 0);

      message = dbus_connection_pop_message(connection_);
    }

    // Poll the message queue every kPollingPeriodMilliSeconds for the new
    // method call.
    if (message == nullptr) {
      usleep(kPollingPeriodMilliSeconds * 1000);
      continue;
    }

    // Process this message and store the reply in |bytes|.
    std::vector<uint8_t> bytes;
    if (!ProcessMessage(message, &bytes)) {
      continue;
    }

    DBusMessage* reply = dbus_message_new_method_return(message);

    if (!bytes.empty()) {
      dbus_message_append_args(reply, DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &bytes,
                               bytes.size(), DBUS_TYPE_INVALID);
    }

    {
      std::lock_guard<std::mutex> lock(connection_lock_);
      dbus_connection_send(connection_, reply, nullptr);
      dbus_connection_flush(connection_);
    }

    dbus_message_unref(reply);
    dbus_message_unref(message);
  }
}

bool CrOSDbusService::ProcessMessage(DBusMessage* message,
                                     std::vector<uint8_t>* bytes) {
  if (message == nullptr || bytes == nullptr) {
    LOG(WARNING) << "Failed to process this Dbus message.";
    return false;
  }

  // Check to see if its a BootstrapMojoConnection method call.
  if (dbus_message_is_method_call(
          message, ServiceEnumToServiceName(service_).c_str(),
          MethodEnumToMethodName(Method::BOOTSTRAP_MOJO_CONNECTION).c_str())) {
    DBusMessageIter iter;
    if (!dbus_message_iter_init(message, &iter)) {
      LOG(ERROR) << "Could not get iter.";
      return false;
    }

    DBusBasicValue value;
    if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_UNIX_FD) {
      LOG(ERROR) << "Arg type is not UNIX_FD.";
    }
    dbus_message_iter_get_basic(&iter, &value);

    if (mojo_connector_ == nullptr) {
      LOG(ERROR) << "Mojo Connector is nullptr.";
      return false;
    }
    LOG(INFO) << "File descriptor: " << value.fd;
    mojo_connector_->ReceiveMojoInvitationFileDescriptor(value.fd);
    return true;
  }

  if (message_handler_ == nullptr) {
    LOG(ERROR) << "Message handler is not set.";
    return false;
  }

  // Check to see if its a GetDiagnostics method call.
  if (dbus_message_is_method_call(
          message, ServiceEnumToServiceName(service_).c_str(),
          MethodEnumToMethodName(Method::GET_DIAGNOSTICS).c_str())) {
    // No input arguments for GetDiagnostics.
    message_handler_(Method::GET_DIAGNOSTICS, nullptr, 0, bytes);
    return true;
  }

  // Check to see if its a State method call.
  if (!dbus_message_is_method_call(
          message, ServiceEnumToServiceName(service_).c_str(),
          MethodEnumToMethodName(Method::STATE).c_str())) {
    // Neither GetDiagnostics or State.
    return false;
  }

  // We have a State method call, check to see if it is a GetState call.
  DBusMessageIter iter;
  if (!dbus_message_iter_init(message, &iter)) {
    // No input arguments for GetState.
    message_handler_(Method::STATE, nullptr, 0, bytes);
    return true;
  }

  // This means SetState and we use the following variables to store
  // arguments of this method call.
  uint8_t* arg_bytes = nullptr;
  int arg_size = 0;

  if (!dbus_message_get_args(message, nullptr, DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE,
                             &arg_bytes, &arg_size, DBUS_TYPE_INVALID)) {
    LOG(WARNING) << "Failed to parse args of a SetState method call.";
    return false;
  }

  message_handler_(Method::STATE, arg_bytes, arg_size, bytes);
  return true;
}

}  // namespace mri

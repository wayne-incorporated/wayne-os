// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// This file implements DBus functionality.
// Because hammerd is not a daemon, it can only send signals to other
// processes or call methods provided by others.

#ifndef HAMMERD_DBUS_WRAPPER_H_
#define HAMMERD_DBUS_WRAPPER_H_

#include <memory>
#include <string>

#include <base/memory/ptr_util.h>
#include <base/memory/ref_counted.h>
#include <dbus/bus.h>
#include <dbus/exported_object.h>
#include <dbus/message.h>

namespace hammerd {

class DBusWrapperInterface {
 public:
  virtual ~DBusWrapperInterface() = default;

  // Send a signal without argument.
  virtual void SendSignal(const std::string& signal_name) = 0;
  // Send a signal with a binary-blob argument.
  // Currently we only have one signal with a binary-blob argument. If we need
  // other kind of arguments in the future, then switch to protobuf.
  virtual void SendSignalWithArg(const std::string& signal_name,
                                 const uint8_t* values,
                                 size_t length) = 0;
};

class DBusWrapper : public DBusWrapperInterface {
 public:
  DBusWrapper();
  DBusWrapper(const DBusWrapper&) = delete;
  DBusWrapper& operator=(const DBusWrapper&) = delete;

  virtual ~DBusWrapper() = default;

  void SendSignal(const std::string& signal_name) override;
  void SendSignalWithArg(const std::string& signal_name,
                         const uint8_t* values,
                         size_t length) override;

 protected:
  scoped_refptr<dbus::Bus> bus_;
  dbus::ExportedObject* exported_object_;
};

// The dummy class used in hammerd API.
class DummyDBusWrapper : public DBusWrapperInterface {
 public:
  DummyDBusWrapper() {}
  DummyDBusWrapper(const DummyDBusWrapper&) = delete;
  DummyDBusWrapper& operator=(const DummyDBusWrapper&) = delete;

  virtual ~DummyDBusWrapper() = default;

  void SendSignal(const std::string& signal_name) override {
    SendSignalWithArg(signal_name, NULL, 0);
  }
  void SendSignalWithArg(const std::string& signal_name,
                         const uint8_t* values,
                         size_t length) override {
    last_signal_name_ = std::string(signal_name);
    if (values == NULL)
      last_value_ = "";
    else
      last_value_ = std::string(reinterpret_cast<const char*>(values), length);
  }

  std::string GetLastSignalName() { return last_signal_name_; }
  std::string GetLastValue() { return last_value_; }

 private:
  // Record the last signal that was "sent"
  std::string last_signal_name_;
  std::string last_value_;
};

}  // namespace hammerd
#endif  // HAMMERD_DBUS_WRAPPER_H_

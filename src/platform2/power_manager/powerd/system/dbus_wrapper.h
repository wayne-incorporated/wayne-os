// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_DBUS_WRAPPER_H_
#define POWER_MANAGER_POWERD_SYSTEM_DBUS_WRAPPER_H_

#include <memory>
#include <string>

#include <base/compiler_specific.h>
#include <base/memory/ref_counted.h>
#include <base/memory/weak_ptr.h>
#include <base/observer_list.h>
#include <base/observer_list_types.h>
#include <dbus/exported_object.h>
#include <dbus/object_proxy.h>

namespace dbus {
class Bus;
}  // namespace dbus

namespace google::protobuf {
class MessageLite;
}  // namespace google::protobuf

namespace power_manager::system {

// Interface for sending D-Bus messages.  A stub implementation can be
// instantiated by tests to verify behavior without actually communicating with
// D-Bus.
class DBusWrapperInterface {
 public:
  class Observer : public base::CheckedObserver {
   public:
    ~Observer() override = default;

    // Called when DBusWrapper has successfully published its service to D-Bus.
    virtual void OnServicePublished() {}

    // Called when the ownership of a D-Bus service name changes. |old_owner| or
    // |new_owner| may be empty if the service just started or stopped.
    virtual void OnDBusNameOwnerChanged(const std::string& service_name,
                                        const std::string& old_owner,
                                        const std::string& new_owner) {}
  };

  virtual ~DBusWrapperInterface() = default;

  // Adds or removes an observer.
  virtual void AddObserver(Observer* observer) = 0;
  virtual void RemoveObserver(Observer* observer) = 0;

  // Returns the underlying object representing the bus. This will be null in
  // test situations.
  virtual scoped_refptr<dbus::Bus> GetBus() = 0;

  // Returns a proxy for making calls to another service. |service_name| is a
  // D-Bus service name like "org.chromium.cras" while |object_path| is the
  // D-Bus path to the corresponding object, e.g. "/org/chromium/cras".
  // Ownership of the returned object is not transferred to the caller.
  virtual dbus::ObjectProxy* GetObjectProxy(const std::string& service_name,
                                            const std::string& object_path) = 0;

  // Registers to be notified when a service identified by |proxy| becomes
  // initially available. If the service is already available, the callback will
  // be run asynchronously immediately. The callback will only be called once.
  virtual void RegisterForServiceAvailability(
      dbus::ObjectProxy* proxy,
      dbus::ObjectProxy::WaitForServiceToBeAvailableCallback callback) = 0;

  // Registers to receive signals. |interface_name| is a D-Bus interface name
  // like "org.chromium.cras.Control", while |signal_name| is an unqualified
  // D-Bus signal name, e.g. "ActiveOutputNodeChanged".
  virtual void RegisterForSignal(
      dbus::ObjectProxy* proxy,
      const std::string& interface_name,
      const std::string& signal_name,
      dbus::ObjectProxy::SignalCallback callback) = 0;

  // Exports a method named |method_name|.
  virtual void ExportMethod(
      const std::string& method_name,
      dbus::ExportedObject::MethodCallCallback callback) = 0;

  // Takes ownership of a well-known service name to allow other processes to
  // find |exported_object_|. This should be called once after all methods have
  // been exported via ExportMethod().
  virtual bool PublishService() = 0;

  // Emits |signal|. Ownership remains with the caller.
  virtual void EmitSignal(dbus::Signal* signal) = 0;

  // Emits a signal named |signal_name| without any arguments.
  virtual void EmitBareSignal(const std::string& signal_name) = 0;

  // Emits a signal named |signal_name| and containing a serialized copy of
  // |protobuf| as a single byte array argument.
  virtual void EmitSignalWithProtocolBuffer(
      const std::string& signal_name,
      const google::protobuf::MessageLite& protobuf) = 0;

  // Synchronously calls |method_call| on |proxy| and returns the response (or
  // null on error). Ownership of |method_call| remains with the caller.
  virtual std::unique_ptr<dbus::Response> CallMethodSync(
      dbus::ObjectProxy* proxy,
      dbus::MethodCall* method_call,
      base::TimeDelta timeout) = 0;

  // Asynchronously calls |method_call| on |proxy|. Ownership of |method_call|
  // remains with the caller. The response will be passed to |callback|.
  virtual void CallMethodAsync(
      dbus::ObjectProxy* proxy,
      dbus::MethodCall* method_call,
      base::TimeDelta timeout,
      dbus::ObjectProxy::ResponseCallback callback) = 0;
};

// DBusWrapper implementation that actually communicates with systemwide D-Bus
// bus.
class DBusWrapper : public DBusWrapperInterface {
 public:
  DBusWrapper(const DBusWrapper&) = delete;
  DBusWrapper& operator=(const DBusWrapper&) = delete;

  ~DBusWrapper() override;

  // Factory method for DBusWrapper. Returns nullptr on failure.
  static std::unique_ptr<DBusWrapper> Create();

  // DBusWrapperInterface overrides:
  void AddObserver(Observer* observer) override;
  void RemoveObserver(Observer* observer) override;
  scoped_refptr<dbus::Bus> GetBus() override;
  dbus::ObjectProxy* GetObjectProxy(const std::string& service_name,
                                    const std::string& object_path) override;
  void RegisterForServiceAvailability(
      dbus::ObjectProxy* proxy,
      dbus::ObjectProxy::WaitForServiceToBeAvailableCallback callback) override;
  void RegisterForSignal(dbus::ObjectProxy* proxy,
                         const std::string& interface_name,
                         const std::string& signal_name,
                         dbus::ObjectProxy::SignalCallback callback) override;
  void ExportMethod(const std::string& method_name,
                    dbus::ExportedObject::MethodCallCallback callback) override;
  bool PublishService() override;
  void EmitSignal(dbus::Signal* signal) override;
  void EmitBareSignal(const std::string& signal_name) override;
  void EmitSignalWithProtocolBuffer(
      const std::string& signal_name,
      const google::protobuf::MessageLite& protobuf) override;
  std::unique_ptr<dbus::Response> CallMethodSync(
      dbus::ObjectProxy* proxy,
      dbus::MethodCall* method_call,
      base::TimeDelta timeout) override;
  void CallMethodAsync(dbus::ObjectProxy* proxy,
                       dbus::MethodCall* method_call,
                       base::TimeDelta timeout,
                       dbus::ObjectProxy::ResponseCallback callback) override;

 private:
  // Create DBusWrappers using the factory method above.
  DBusWrapper(scoped_refptr<dbus::Bus> bus,
              dbus::ExportedObject* exported_object);

  // Handles NameOwnerChanged signals emitted by dbus-daemon.
  void HandleNameOwnerChangedSignal(dbus::Signal* signal);

  // Connection to the D-Bus system bus.
  scoped_refptr<dbus::Bus> bus_;

  // Exported object permitting powerd to emit signals and other processes to
  // make method calls to it. Owned by |bus_|.
  dbus::ExportedObject* exported_object_;

  base::ObserverList<Observer> observers_;

  // Trace identifier used to connect async method calls to their responses.
  uint64_t next_async_trace_id_ = reinterpret_cast<uint64_t>(this);

  base::WeakPtrFactory<DBusWrapper> weak_ptr_factory_;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_DBUS_WRAPPER_H_

// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_DBUS_WRAPPER_STUB_H_
#define POWER_MANAGER_POWERD_SYSTEM_DBUS_WRAPPER_STUB_H_

#include <map>
#include <memory>
#include <string>
#include <vector>

#include <base/memory/ref_counted.h>
#include <base/observer_list.h>
#include <dbus/message.h>
#include <google/protobuf/message_lite.h>

#include "power_manager/powerd/system/dbus_wrapper.h"

namespace power_manager::system {

// Stub implementation of DBusWrapperInterface for testing.
class DBusWrapperStub : public DBusWrapperInterface {
 public:
  // Information about a signal that was sent.
  struct SignalInfo {
    std::string signal_name;

    // Only set if EmitSignal() was called.
    std::unique_ptr<dbus::Signal> signal;

    // Only set if EmitSignalWithProtocolBuffer() was called.
    std::string protobuf_type;
    std::string serialized_data;
  };

  DBusWrapperStub();
  DBusWrapperStub(const DBusWrapperStub&) = delete;
  DBusWrapperStub& operator=(const DBusWrapperStub&) = delete;

  ~DBusWrapperStub() override;

  bool service_published() const { return service_published_; }
  size_t num_sent_signals() const { return sent_signals_.size(); }

  // Returns the name of the signal at position |index| in |sent_signals_|.
  // Crashes if |index| is out of range.
  std::string GetSentSignalName(size_t index);

  // Copies the signal at position |index| in |sent_signals_| (that is, the
  // |index|th-sent signal) to |protobuf_out|, which should be a concrete
  // protocol buffer, and |signal_out|. false is returned if the index is
  // out-of-range, the D-Bus signal name doesn't match |expected_signal_name|,
  // or the type of protocol buffer that was attached to the signal doesn't
  // match |protobuf_out|'s type. |protobuf_out| can be null, in which case only
  // the signal name is checked. |signal_out| may also be null.
  bool GetSentSignal(size_t index,
                     const std::string& expected_signal_name,
                     google::protobuf::MessageLite* protobuf_out,
                     std::unique_ptr<dbus::Signal>* signal_out);

  // Clears |sent_signals_|.
  void ClearSentSignals();

  // Returns true if |method_name| has been exported.
  [[nodiscard]] bool IsMethodExported(const std::string& method_name) const;

  // Invokes a method previously exported with ExportedMethod().
  void CallExportedMethod(dbus::MethodCall* method_call,
                          dbus::ExportedObject::ResponseSender response_cb);
  std::unique_ptr<dbus::Response> CallExportedMethodSync(
      dbus::MethodCall* method_call);

  // Acts as if |proxy| emitted |signal|. A handler must have previously been
  // registered via RegisterForSignal().
  void EmitRegisteredSignal(dbus::ObjectProxy* proxy, dbus::Signal* signal);

  using MethodCallback =
      base::RepeatingCallback<std::unique_ptr<dbus::Response>(
          dbus::ObjectProxy*, dbus::MethodCall*)>;

  // Sets a callback to be invoked in response to calls to CallMethod*().
  void SetMethodCallback(const MethodCallback& callback);

  // Runs and clears callbacks for |proxy| in |service_availability_callbacks_|.
  void NotifyServiceAvailable(dbus::ObjectProxy* proxy, bool available);

  // Calls |observers_|' OnDBusNameOwnerChanged methods.
  void NotifyNameOwnerChanged(const std::string& service_name,
                              const std::string& old_owner,
                              const std::string& new_owner);

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
  // Information about a proxy returned by GetObjectProxy().
  struct ObjectProxyInfo {
    std::string service_name;
    std::string object_path;
    scoped_refptr<dbus::ObjectProxy> object_proxy;
  };

  // Information about a signal description passed to RegisterForSignal().
  struct RegisteredSignalInfo {
    dbus::ObjectProxy* proxy;  // Not owned.
    std::string interface_name;
    std::string signal_name;

    bool operator<(const RegisteredSignalInfo& o) const;
  };

  base::ObserverList<Observer> observers_;

  // Has PublishService() been called?
  bool service_published_ = false;

  // All proxies that have been created.
  std::vector<ObjectProxyInfo> object_proxy_infos_;

  // Map from proxy to callbacks passed to RegisterForServiceAvailability().
  std::map<dbus::ObjectProxy*,
           std::vector<dbus::ObjectProxy::WaitForServiceToBeAvailableCallback>>
      service_availability_callbacks_;

  // powerd methods that have been exported via ExportMethod(), keyed by method
  // name.
  std::map<std::string, dbus::ExportedObject::MethodCallCallback>
      exported_methods_;

  // powerd signal handlers that have been passed to RegisterForSignal().
  std::map<RegisteredSignalInfo, dbus::ObjectProxy::SignalCallback>
      signal_handlers_;

  // Information about signals that powerd has sent using Emit*Signal*().
  std::vector<SignalInfo> sent_signals_;

  // Invoked to handle calls to CallMethod*().
  MethodCallback method_callback_;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_DBUS_WRAPPER_STUB_H_

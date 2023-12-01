// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BIOD_BIOD_PROXY_BIOMETRICS_MANAGER_PROXY_BASE_H_
#define BIOD_BIOD_PROXY_BIOMETRICS_MANAGER_PROXY_BASE_H_

#include <memory>
#include <string>

#include <base/memory/weak_ptr.h>
#include <brillo/brillo_export.h>
#include <dbus/bus.h>
#include <dbus/object_manager.h>

#include "biod/biod_proxy/util.h"
#include "biod/proto_bindings/constants.pb.h"
#include "biod/proto_bindings/messages.pb.h"

namespace biod {

BRILLO_EXPORT const char* BiometricsManagerStatusToString(
    const BiometricsManagerStatus& status);

class BRILLO_EXPORT BiometricsManagerProxyBase {
 public:
  using FinishCallback = base::RepeatingCallback<void(bool success)>;
  using SignalCallback = dbus::ObjectProxy::SignalCallback;
  using OnConnectedCallback = dbus::ObjectProxy::OnConnectedCallback;

  // Factory method. Returns nullptr if cannot get a dbus proxy for biod.
  static std::unique_ptr<BiometricsManagerProxyBase> Create(
      const scoped_refptr<dbus::Bus>& bus, const dbus::ObjectPath& path);

  virtual ~BiometricsManagerProxyBase() = default;

  virtual void ConnectToAuthScanDoneSignal(
      SignalCallback signal_callback,
      OnConnectedCallback on_connected_callback);

  virtual const dbus::ObjectPath path() const;

  virtual void SetFinishHandler(const FinishCallback& on_finish);

  // Starts biometrics auth session synchronously.
  virtual bool StartAuthSession();

  // Starts biometrics auth session asynchronously.
  // |callback| is called when starting the auth session succeeds/fails.
  virtual void StartAuthSessionAsync(
      base::OnceCallback<void(bool success)> callback);

  // Ends biometrics auth session and resets state.
  virtual void EndAuthSession();

 protected:
  BiometricsManagerProxyBase();
  BiometricsManagerProxyBase(const BiometricsManagerProxyBase&) = delete;
  BiometricsManagerProxyBase& operator=(const BiometricsManagerProxyBase&) =
      delete;

  bool Initialize(const scoped_refptr<dbus::Bus>& bus,
                  const dbus::ObjectPath& path);

  void OnFinish(bool success);

  void OnSignalConnected(const std::string& interface,
                         const std::string& signal,
                         bool success);

  scoped_refptr<dbus::Bus> bus_;
  dbus::ObjectProxy* proxy_;

 private:
  friend class BiometricsManagerProxyBaseTest;

  void OnSessionFailed(dbus::Signal* signal);

  // Handler for StartAuthSessionAsync. |callback| will be called on behalf of
  // the caller of StartAuthSessionAsync.
  void OnStartAuthSessionResp(base::OnceCallback<void(bool success)> callback,
                              dbus::Response* response);

  // Parse a dbus response and return the ObjectProxy implied by the response.
  // Returns nullptr on error.
  dbus::ObjectProxy* HandleAuthSessionResponse(dbus::Response* response);

  FinishCallback on_finish_;

  base::WeakPtrFactory<BiometricsManagerProxyBase> weak_factory_;

  dbus::ObjectProxy* biod_auth_session_;
};

}  // namespace biod

#endif  // BIOD_BIOD_PROXY_BIOMETRICS_MANAGER_PROXY_BASE_H_

// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BIOD_BIOD_PROXY_AUTH_STACK_MANAGER_PROXY_BASE_H_
#define BIOD_BIOD_PROXY_AUTH_STACK_MANAGER_PROXY_BASE_H_

#include <memory>
#include <optional>
#include <string>

#include <base/memory/weak_ptr.h>
#include <brillo/brillo_export.h>
#include <dbus/bus.h>
#include <dbus/object_manager.h>

#include "biod/biod_proxy/util.h"
#include "biod/proto_bindings/constants.pb.h"
#include "biod/proto_bindings/messages.pb.h"

namespace biod {

class BRILLO_EXPORT AuthStackManagerProxyBase {
 public:
  using SignalCallback = dbus::ObjectProxy::SignalCallback;
  using OnConnectedCallback = dbus::ObjectProxy::OnConnectedCallback;
  using CreateCredentialCallback =
      base::OnceCallback<void(std::optional<CreateCredentialReply>)>;
  using AuthenticateCredentialCallback =
      base::OnceCallback<void(std::optional<AuthenticateCredentialReply>)>;

  AuthStackManagerProxyBase(const AuthStackManagerProxyBase&) = delete;
  AuthStackManagerProxyBase& operator=(const AuthStackManagerProxyBase&) =
      delete;

  // Factory method. Returns nullptr if cannot get a dbus proxy for biod.
  static std::unique_ptr<AuthStackManagerProxyBase> Create(
      const scoped_refptr<dbus::Bus>& bus, const dbus::ObjectPath& path);

  virtual ~AuthStackManagerProxyBase() = default;

  virtual void ConnectToEnrollScanDoneSignal(
      SignalCallback signal_callback,
      OnConnectedCallback on_connected_callback);

  virtual void ConnectToAuthScanDoneSignal(
      SignalCallback signal_callback,
      OnConnectedCallback on_connected_callback);

  virtual void ConnectToSessionFailedSignal(
      SignalCallback signal_callback,
      OnConnectedCallback on_connected_callback);

  // Starts biometrics enroll session asynchronously.
  // |callback| is called when starting the enroll session succeeds/fails.
  virtual void StartEnrollSession(
      base::OnceCallback<void(bool success)> callback);

  // Ends biometrics enroll session and resets state.
  virtual void EndEnrollSession();

  // Creates the actual fingerprint record. Should only be called after an
  // enroll session completes successfully. See CreateCredentialRequest/Reply
  // protos for the detailed function signature.
  virtual void CreateCredential(const CreateCredentialRequest& request,
                                CreateCredentialCallback callback);

  // Starts biometrics auth session asynchronously.
  // |callback| is called when starting the auth session succeeds/fails.
  virtual void StartAuthSession(
      std::string user_id, base::OnceCallback<void(bool success)> callback);

  // Ends biometrics auth session and resets state.
  virtual void EndAuthSession();

  // Performs the fingerprint match. Should only be called after an auth session
  // completes successfully. See AuthenticateCredentialRequest/Reply protos for
  // the detailed function signature.
  virtual void AuthenticateCredential(
      const AuthenticateCredentialRequest& request,
      AuthenticateCredentialCallback callback);

 protected:
  AuthStackManagerProxyBase() = default;

  bool Initialize(const scoped_refptr<dbus::Bus>& bus,
                  const dbus::ObjectPath& path);

  scoped_refptr<dbus::Bus> bus_;
  dbus::ObjectProxy* proxy_ = nullptr;

 private:
  friend class AuthStackManagerProxyBaseTest;

  // Handler for StartEnrollSession. |callback| will be called on behalf of
  // the caller of StartEnrollSession.
  void OnStartEnrollSessionResponse(
      base::OnceCallback<void(bool success)> callback,
      dbus::Response* response);

  // Handler for CreateCredential. |callback| will be called on behalf of
  // the caller of CreateCredential.
  void OnCreateCredentialResponse(CreateCredentialCallback callback,
                                  dbus::Response* response);

  // Handler for StartAuthSession. |callback| will be called on behalf of
  // the caller of StartAuthSession.
  void OnStartAuthSessionResponse(
      base::OnceCallback<void(bool success)> callback,
      dbus::Response* response);

  // Handler for AuthenticateCredential. |callback| will be called on behalf of
  // the caller of AuthenticateCredential.
  void OnAuthenticateCredentialResponse(AuthenticateCredentialCallback callback,
                                        dbus::Response* response);

  // Parse a dbus response and return the ObjectProxy implied by the response.
  // Returns nullptr on error.
  dbus::ObjectProxy* HandleStartSessionResponse(dbus::Response* response);

  // Parse a dbus response and return the CreateCredentialReply implied by the
  // response. Returns nullopt on error.
  std::optional<CreateCredentialReply> HandleCreateCredentialResponse(
      dbus::Response* response);

  // Parse a dbus response and return the AuthenticateCredentialReply implied by
  // the response. Returns nullopt on error.
  std::optional<AuthenticateCredentialReply>
  HandleAuthenticateCredentialResponse(dbus::Response* response);

  dbus::ObjectProxy* biod_enroll_session_ = nullptr;
  dbus::ObjectProxy* biod_auth_session_ = nullptr;
};

}  // namespace biod

#endif  // BIOD_BIOD_PROXY_AUTH_STACK_MANAGER_PROXY_BASE_H_

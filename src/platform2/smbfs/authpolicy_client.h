// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SMBFS_AUTHPOLICY_CLIENT_H_
#define SMBFS_AUTHPOLICY_CLIENT_H_

#include <memory>
#include <string>

#include <base/memory/weak_ptr.h>
#include <dbus/bus.h>
#include <dbus/object_proxy.h>

#include "smbfs/kerberos_artifact_client_interface.h"

namespace smbfs {

// AuthPolicyClient is used to communicate with the
// org.chromium.AuthPolicy service.
class AuthPolicyClient : public KerberosArtifactClientInterface {
 public:
  explicit AuthPolicyClient(scoped_refptr<dbus::Bus> bus);
  AuthPolicyClient(const AuthPolicyClient&) = delete;
  AuthPolicyClient& operator=(const AuthPolicyClient&) = delete;

  // KerberosArtifactClientInterface overrides.
  void GetUserKerberosFiles(const std::string& object_guid,
                            GetUserKerberosFilesCallback callback) override;
  void ConnectToKerberosFilesChangedSignal(
      dbus::ObjectProxy::SignalCallback signal_callback,
      dbus::ObjectProxy::OnConnectedCallback on_connected_callback) override;

 private:
  void HandleGetUserKeberosFiles(GetUserKerberosFilesCallback callback,
                                 dbus::Response* response);

  dbus::ObjectProxy* const auth_policy_object_proxy_;
  base::WeakPtrFactory<AuthPolicyClient> weak_ptr_factory_{this};
};

}  // namespace smbfs

#endif  // SMBFS_AUTHPOLICY_CLIENT_H_

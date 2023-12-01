// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SMBFS_KERBEROS_ARTIFACT_CLIENT_INTERFACE_H_
#define SMBFS_KERBEROS_ARTIFACT_CLIENT_INTERFACE_H_

#include <string>

#include <base/functional/callback.h>
#include <dbus/object_proxy.h>

namespace smbfs {

class KerberosArtifactClientInterface {
 public:
  using GetUserKerberosFilesCallback =
      base::OnceCallback<void(bool success,
                              const std::string& krb5_ccache_data,
                              const std::string& krb5_conf_data)>;

  virtual ~KerberosArtifactClientInterface() = default;

  // Gets Kerberos files for the user determined by |account_identifier|.
  // If authpolicyd or kerberosd has Kerberos files for the user specified by
  // |account_identifier| it sends them in response: credential cache and krb5
  // config files. For authpolicyd expected |account_identifier| is object guid,
  // while for kerberosd it is principal name.
  virtual void GetUserKerberosFiles(const std::string& account_identifier,
                                    GetUserKerberosFilesCallback callback) = 0;

  // Connects callbacks to OnKerberosFilesChanged D-Bus signal.
  virtual void ConnectToKerberosFilesChangedSignal(
      dbus::ObjectProxy::SignalCallback signal_callback,
      dbus::ObjectProxy::OnConnectedCallback on_connected_callback) = 0;

 protected:
  KerberosArtifactClientInterface() = default;
  KerberosArtifactClientInterface(const KerberosArtifactClientInterface&) =
      delete;
  KerberosArtifactClientInterface& operator=(
      const KerberosArtifactClientInterface&) = delete;
};

}  // namespace smbfs

#endif  // SMBFS_KERBEROS_ARTIFACT_CLIENT_INTERFACE_H_

// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SMBFS_KERBEROS_CLIENT_H_
#define SMBFS_KERBEROS_CLIENT_H_

#include <memory>
#include <string>

#include <base/memory/weak_ptr.h>
#include <dbus/bus.h>
#include <dbus/object_proxy.h>

#include "smbfs/kerberos_artifact_client_interface.h"

namespace smbfs {

// KerberosClient is used to communicate with the
// org.chromium.Kerberos service.
class KerberosClient : public KerberosArtifactClientInterface {
 public:
  explicit KerberosClient(scoped_refptr<dbus::Bus> bus);
  KerberosClient(const KerberosClient&) = delete;
  KerberosClient& operator=(const KerberosClient&) = delete;

  // KerberosArtifactClientInterface overrides.
  void GetUserKerberosFiles(const std::string& principal_name,
                            GetUserKerberosFilesCallback callback) override;
  void ConnectToKerberosFilesChangedSignal(
      dbus::ObjectProxy::SignalCallback signal_callback,
      dbus::ObjectProxy::OnConnectedCallback on_connected_callback) override;

 private:
  void HandleGetUserKeberosFiles(GetUserKerberosFilesCallback callback,
                                 dbus::Response* response);

  dbus::ObjectProxy* const kerberos_object_proxy_;
  base::WeakPtrFactory<KerberosClient> weak_ptr_factory_{this};
};

}  // namespace smbfs

#endif  // SMBFS_KERBEROS_CLIENT_H_

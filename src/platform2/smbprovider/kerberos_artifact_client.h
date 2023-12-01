// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SMBPROVIDER_KERBEROS_ARTIFACT_CLIENT_H_
#define SMBPROVIDER_KERBEROS_ARTIFACT_CLIENT_H_

#include <memory>
#include <string>

#include <base/functional/callback.h>
#include <base/memory/weak_ptr.h>
#include <dbus/bus.h>
#include <dbus/object_proxy.h>

#include "smbprovider/kerberos_artifact_client_interface.h"

namespace smbprovider {

// KerberosArtifactClient is used to communicate with the
// org.chromium.Kerberos service.
class KerberosArtifactClient : public KerberosArtifactClientInterface {
 public:
  explicit KerberosArtifactClient(scoped_refptr<dbus::Bus> bus);
  KerberosArtifactClient(const KerberosArtifactClient&) = delete;
  KerberosArtifactClient& operator=(const KerberosArtifactClient&) = delete;

  // KerberosArtifactClientInterface overrides.
  void GetKerberosFiles(const std::string& principal_name,
                        GetKerberosFilesCallback callback) override;
  void ConnectToKerberosFilesChangedSignal(
      dbus::ObjectProxy::SignalCallback signal_callback,
      dbus::ObjectProxy::OnConnectedCallback on_connected_callback) override;

 private:
  void HandleGetKerberosFiles(GetKerberosFilesCallback callback,
                              dbus::Response* response);

  dbus::ObjectProxy* kerberos_object_proxy_ = nullptr;
  base::WeakPtrFactory<KerberosArtifactClient> weak_ptr_factory_{this};
};

}  // namespace smbprovider

#endif  // SMBPROVIDER_KERBEROS_ARTIFACT_CLIENT_H_

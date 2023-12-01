// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SMBPROVIDER_FAKE_KERBEROS_ARTIFACT_CLIENT_H_
#define SMBPROVIDER_FAKE_KERBEROS_ARTIFACT_CLIENT_H_

#include <map>
#include <memory>
#include <string>
#include <utility>

#include <base/functional/callback.h>
#include <base/memory/weak_ptr.h>
#include <brillo/dbus/dbus_object.h>
#include <dbus/object_proxy.h>
#include <kerberos/proto_bindings/kerberos_service.pb.h>

#include "smbprovider/kerberos_artifact_client_interface.h"

namespace smbprovider {

// FakeKerberosArtifactClient fakes communication with the org.chromium.Kerberos
// service.
class FakeKerberosArtifactClient : public KerberosArtifactClientInterface {
 public:
  FakeKerberosArtifactClient();
  FakeKerberosArtifactClient(const FakeKerberosArtifactClient&) = delete;
  FakeKerberosArtifactClient& operator=(const FakeKerberosArtifactClient&) =
      delete;

  // KerberosArtifactClientInterface overrides.
  void GetKerberosFiles(const std::string& principal_name,
                        GetKerberosFilesCallback callback) override;

  void ConnectToKerberosFilesChangedSignal(
      dbus::ObjectProxy::SignalCallback signal_callback,
      dbus::ObjectProxy::OnConnectedCallback on_connected_callback) override;

  // Test helper method. Runs |signal_callback_| with the KerberosFilesChanged
  // signal.
  void FireSignal();

  // Test helper method. Returns the number of times that the GetKerberosFiles
  // method has been called.
  uint32_t GetFilesMethodCallCount() const;

  // Test helper method. Returns whether a signal has been connected to.
  bool IsConnected() const;

  // Test helper method. Adds |kerberos_files| to the |kerberos_files_map_| with
  // the key |principal_name|.
  void AddKerberosFiles(const std::string& principal_name,
                        const kerberos::KerberosFiles& kerberos_files);

  // Test helper method. Clears |kerberos_files_map_|.
  void ResetKerberosFiles();

 private:
  uint32_t call_count_ = 0;
  dbus::ObjectProxy::SignalCallback signal_callback_;
  // Maps account_id : KerberosFiles.
  std::map<std::string, kerberos::KerberosFiles> kerberos_files_map_;
};

}  // namespace smbprovider

#endif  // SMBPROVIDER_FAKE_KERBEROS_ARTIFACT_CLIENT_H_

// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SMBFS_FAKE_KERBEROS_ARTIFACT_CLIENT_H_
#define SMBFS_FAKE_KERBEROS_ARTIFACT_CLIENT_H_

#include <map>
#include <memory>
#include <string>
#include <utility>

#include <authpolicy/proto_bindings/active_directory_info.pb.h>
#include <base/functional/callback.h>
#include <base/memory/weak_ptr.h>
#include <brillo/dbus/dbus_object.h>
#include <dbus/object_proxy.h>

#include "smbfs/kerberos_artifact_client_interface.h"

namespace smbfs {

// FakeKerberosArtifactClient fakes communication with the
// org.chromium.AuthPolicy service.
class FakeKerberosArtifactClient : public KerberosArtifactClientInterface {
 public:
  FakeKerberosArtifactClient();
  FakeKerberosArtifactClient(const FakeKerberosArtifactClient&) = delete;
  FakeKerberosArtifactClient& operator=(const FakeKerberosArtifactClient&) =
      delete;

  // KerberosArtifactClientInterface overrides.
  void GetUserKerberosFiles(const std::string& object_guid,
                            GetUserKerberosFilesCallback callback) override;

  void ConnectToKerberosFilesChangedSignal(
      dbus::ObjectProxy::SignalCallback signal_callback,
      dbus::ObjectProxy::OnConnectedCallback on_connected_callback) override;

  // Test helper method. Runs |signal_callback_| with the KerberosFilesChanged
  // signal.
  void FireSignal();

  // Test helper method. Returns the number of times that the
  // GetUserKerberosFiles method has been called.
  uint32_t GetFilesMethodCallCount() const;

  // Test helper method. Returns whether a signal has been connected to.
  bool IsConnected() const;

  // Test helper method. Adds |kerberos_files| to the |kerberos_files_map_| with
  // the key |object_guid|.
  void AddKerberosFiles(const std::string& object_guid,
                        const authpolicy::KerberosFiles& kerberos_files);

  // Test helper method. Clears |kerberos_files_map_|.
  void ResetKerberosFiles();

 private:
  uint32_t call_count_ = 0;
  dbus::ObjectProxy::SignalCallback signal_callback_;
  // Maps account_id : KerberosFiles.
  std::map<std::string, authpolicy::KerberosFiles> kerberos_files_map_;
};

}  // namespace smbfs

#endif  // SMBFS_FAKE_KERBEROS_ARTIFACT_CLIENT_H_

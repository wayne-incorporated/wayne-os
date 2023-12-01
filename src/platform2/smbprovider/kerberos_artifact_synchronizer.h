// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SMBPROVIDER_KERBEROS_ARTIFACT_SYNCHRONIZER_H_
#define SMBPROVIDER_KERBEROS_ARTIFACT_SYNCHRONIZER_H_

#include <memory>
#include <string>

#include <base/functional/callback.h>

#include "smbprovider/kerberos_artifact_client_interface.h"

namespace dbus {

class Signal;

}  // namespace dbus

namespace smbprovider {

// `KerberosArtifactSynchronizer` manages kr5conf and krb5ccache files. It takes
// ownership of a `KerberosArtifactClientInterface` on construction.
// `SetupKerberos` fetches Kerberos files from kerberosd and writes a copy to
// the tmpfs. The Kerberos files are kept up-to-date by connecting to
// kerberosd's D-Bus signal.
class KerberosArtifactSynchronizer {
 public:
  using SetupKerberosCallback = base::OnceCallback<void(bool setup_success)>;

  KerberosArtifactSynchronizer(
      const std::string& krb5_conf_path,
      const std::string& krb5_ccache_path,
      std::unique_ptr<KerberosArtifactClientInterface> client,
      bool allow_credentials_update);
  KerberosArtifactSynchronizer(const KerberosArtifactSynchronizer&) = delete;
  KerberosArtifactSynchronizer& operator=(const KerberosArtifactSynchronizer&) =
      delete;

  // Sets up Kerberos for user with |account_identifier|. |callback| is run with
  // the result. If |allow_credentials_update| is false, it may only be called
  // once per instance. If |account_identifier| is empty, credential files will
  // not be created or will be removed.
  void SetupKerberos(const std::string& account_identifier,
                     SetupKerberosCallback callback);

 private:
  // Calls GetKerberosFiles on |client_|.
  void GetFiles(SetupKerberosCallback callback);

  // Response handler for GetKerberosFiles.
  void OnGetFilesResponse(SetupKerberosCallback callback,
                          bool success,
                          const std::string& krb5_ccache,
                          const std::string& krb5_conf);

  // Writes |krb5_ccache| and |krb5_conf| to |krb5_ccache_path_| and
  // |krb5_conf_path_|, respectively. If Kerberos is not yet fully set up, calls
  // ConnectToKerberosFilesChangedSignal.
  void WriteFiles(const std::string& krb5_ccache,
                  const std::string& krb5_conf,
                  SetupKerberosCallback callback);

  // Writes |kerberos_file| to |path|. First writes into a temporary file
  // and then replaces the existing one. Returns true if the write succeeds,
  // false if it fails. The parent directory of |path| must exist.
  bool WriteFile(const std::string& path, const std::string& kerberos_file);

  // Connects to the 'KerberosFilesChanged' D-Bus signal. Called by
  // `WriteFiles()` on initial setup.
  void ConnectToKerberosFilesChangedSignal(SetupKerberosCallback callback);

  // Callback for 'KerberosFilesChanged' D-Bus signal.
  void OnKerberosFilesChanged(dbus::Signal* signal);

  // Called after connecting to 'KerberosFilesChanged' signal. Verifies that the
  // signal connected successfully.
  void OnKerberosFilesChangedSignalConnected(SetupKerberosCallback callback,
                                             const std::string& interface_name,
                                             const std::string& signal_name,
                                             bool success);

  // Remove Kerberos credential files.
  void RemoveFiles(SetupKerberosCallback callback);

  // Remove a file at a given `path`. Returns `true` if the remove succeeds,
  // and `false` if it fails.
  bool RemoveFile(const std::string& path);

  bool is_kerberos_setup_ = false;
  const std::string krb5_conf_path_;
  const std::string krb5_ccache_path_;
  std::string account_identifier_;

  std::unique_ptr<KerberosArtifactClientInterface> client_;

  const bool allow_credentials_update_ = false;
};

}  // namespace smbprovider

#endif  // SMBPROVIDER_KERBEROS_ARTIFACT_SYNCHRONIZER_H_

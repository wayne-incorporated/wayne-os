// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SMBFS_KERBEROS_ARTIFACT_SYNCHRONIZER_H_
#define SMBFS_KERBEROS_ARTIFACT_SYNCHRONIZER_H_

#include <memory>
#include <string>

#include <authpolicy/proto_bindings/active_directory_info.pb.h>
#include <base/files/file_path.h>
#include <base/functional/callback.h>

#include "smbfs/kerberos_artifact_client_interface.h"

namespace dbus {

class Signal;

}  // namespace dbus

namespace smbfs {

// KerberosArtifactSynchronizer manages a Kerberos user's kr5conf and krb5ccache
// files. It takes ownership of a KerberosArtifactClientInterface on
// construction. SetupKerberos fetches a users Kerberos files from AuthPolicy
// and writes a copy to the tempfs. The Kerberos files are kept
// up-to-date by connecting to AuthPolicy's D-Bus signal.
class KerberosArtifactSynchronizer {
 public:
  using SetupKerberosCallback = base::OnceCallback<void(bool setup_success)>;

  KerberosArtifactSynchronizer(
      const base::FilePath& krb5_conf_path,
      const base::FilePath& krb5_ccache_path,
      const std::string& account_identifier,
      std::unique_ptr<KerberosArtifactClientInterface> client);
  KerberosArtifactSynchronizer(const KerberosArtifactSynchronizer&) = delete;
  KerberosArtifactSynchronizer& operator=(const KerberosArtifactSynchronizer&) =
      delete;

  // Sets up Kerberos for user with |account_identifier_|. User must be ChromAD.
  // |callback| is run with the result. May only be called once per instance.
  void SetupKerberos(SetupKerberosCallback callback);

 private:
  // Calls GetUserKerberosFiles on |client_|.
  void GetFiles(SetupKerberosCallback callback);

  // Response handler for GetUserKerberosFiles.
  void OnGetFilesResponse(SetupKerberosCallback callback,
                          bool success,
                          const std::string& krb5_ccache_data,
                          const std::string& krb5_conf_data);

  // Writes |krb5_ccache_data| and |krb5_conf_data| to |krb5_ccache_path_| and
  // |krb5_conf_path_| respectively and runs |callback|.
  void WriteFiles(const std::string& krb5_ccache_data,
                  const std::string& krb5_conf_data,
                  SetupKerberosCallback callback);

  // Writes |kerberos_file| to |path|. First writes into a temporary file
  // and then replaces the existing one. Returns true if the write succeeds,
  // false if it fails. The parent directory of |path| must exist.
  bool WriteFile(const base::FilePath& path, const std::string& kerberos_file);

  // Connects to the 'UserKerberosFilesChanged' D-Bus signal. Runs as a callback
  // to GetFiles().
  void ConnectToKerberosFilesChangedSignal(SetupKerberosCallback callback,
                                           bool success);

  // Callback for 'UserKerberosFilesChanged' D-Bus signal.
  void OnKerberosFilesChanged(dbus::Signal* signal);

  // Called after connecting to 'UserKerberosFilesChanged' signal. Verifies that
  // the signal connected successfully.
  void OnKerberosFilesChangedSignalConnected(SetupKerberosCallback callback,
                                             const std::string& interface_name,
                                             const std::string& signal_name,
                                             bool success);

  const base::FilePath krb5_conf_path_;
  const base::FilePath krb5_ccache_path_;
  const std::string account_identifier_;

  const std::unique_ptr<KerberosArtifactClientInterface> client_;
  bool setup_called_ = false;
};

}  // namespace smbfs

#endif  // SMBFS_KERBEROS_ARTIFACT_SYNCHRONIZER_H_

// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "smbfs/kerberos_artifact_synchronizer.h"

#include <utility>

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <dbus/message.h>

namespace smbfs {

KerberosArtifactSynchronizer::KerberosArtifactSynchronizer(
    const base::FilePath& krb5_conf_path,
    const base::FilePath& krb5_ccache_path,
    const std::string& account_identifier,
    std::unique_ptr<KerberosArtifactClientInterface> client)
    : krb5_conf_path_(krb5_conf_path),
      krb5_ccache_path_(krb5_ccache_path),
      account_identifier_(account_identifier),
      client_(std::move(client)) {}

void KerberosArtifactSynchronizer::SetupKerberos(
    SetupKerberosCallback callback) {
  DCHECK(!setup_called_);
  setup_called_ = true;

  GetFiles(base::BindOnce(
      &KerberosArtifactSynchronizer::ConnectToKerberosFilesChangedSignal,
      base::Unretained(this), std::move(callback)));
}

void KerberosArtifactSynchronizer::GetFiles(SetupKerberosCallback callback) {
  DCHECK(callback);
  client_->GetUserKerberosFiles(
      account_identifier_,
      base::BindOnce(&KerberosArtifactSynchronizer::OnGetFilesResponse,
                     base::Unretained(this), std::move(callback)));
}

void KerberosArtifactSynchronizer::OnGetFilesResponse(
    SetupKerberosCallback callback,
    bool success,
    const std::string& krb5_ccache_data,
    const std::string& krb5_conf_data) {
  if (!success) {
    std::move(callback).Run(false /* setup_success */);
    return;
  }

  WriteFiles(krb5_ccache_data, krb5_conf_data, std::move(callback));
}

void KerberosArtifactSynchronizer::WriteFiles(
    const std::string& krb5_ccache_data,
    const std::string& krb5_conf_data,
    SetupKerberosCallback callback) {
  DCHECK(callback);
  bool success = !krb5_ccache_data.empty() && !krb5_conf_data.empty() &&
                 WriteFile(krb5_conf_path_, krb5_conf_data) &&
                 WriteFile(krb5_ccache_path_, krb5_ccache_data);

  LOG_IF(ERROR, !success)
      << "KerberosArtifactSynchronizer: failed to write Kerberos Files";
  std::move(callback).Run(success);
}

void KerberosArtifactSynchronizer::ConnectToKerberosFilesChangedSignal(
    SetupKerberosCallback callback, bool success) {
  if (!success) {
    std::move(callback).Run(false /* setup_success */);
    return;
  }

  client_->ConnectToKerberosFilesChangedSignal(
      base::BindRepeating(&KerberosArtifactSynchronizer::OnKerberosFilesChanged,
                          base::Unretained(this)),
      base::BindOnce(
          &KerberosArtifactSynchronizer::OnKerberosFilesChangedSignalConnected,
          base::Unretained(this), std::move(callback)));
}

void KerberosArtifactSynchronizer::OnKerberosFilesChanged(
    dbus::Signal* signal) {
  DCHECK(signal);

  GetFiles(base::DoNothing());
}

void KerberosArtifactSynchronizer::OnKerberosFilesChangedSignalConnected(
    SetupKerberosCallback callback,
    const std::string& interface_name,
    const std::string& signal_name,
    bool success) {
  DCHECK(success);

  std::move(callback).Run(true /* setup_success */);
}

bool KerberosArtifactSynchronizer::WriteFile(const base::FilePath& path,
                                             const std::string& blob) {
  if (base::WriteFile(path, blob.c_str(), blob.size()) != blob.size()) {
    LOG(ERROR) << "Failed to write file " << path.value();
    return false;
  }
  return true;
}

}  // namespace smbfs

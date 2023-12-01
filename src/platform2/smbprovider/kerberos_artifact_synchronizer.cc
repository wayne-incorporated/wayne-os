// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "smbprovider/kerberos_artifact_synchronizer.h"

#include <string>
#include <utility>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/important_file_writer.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <dbus/authpolicy/dbus-constants.h>
#include <dbus/message.h>

#include "smbprovider/kerberos_artifact_client_interface.h"

namespace smbprovider {

KerberosArtifactSynchronizer::KerberosArtifactSynchronizer(
    const std::string& krb5_conf_path,
    const std::string& krb5_ccache_path,
    std::unique_ptr<KerberosArtifactClientInterface> client,
    bool allow_credentials_update)
    : krb5_conf_path_(krb5_conf_path),
      krb5_ccache_path_(krb5_ccache_path),
      client_(std::move(client)),
      allow_credentials_update_(allow_credentials_update) {}

void KerberosArtifactSynchronizer::SetupKerberos(
    const std::string& account_identifier, SetupKerberosCallback callback) {
  if (!allow_credentials_update_) {
    if (account_identifier.empty()) {
      LOG(ERROR) << "Kerberos account identifier is empty";
      std::move(callback).Run(false /* success */);
      return;
    }
    if (!account_identifier_.empty() &&
        account_identifier_ != account_identifier) {
      LOG(ERROR) << "Kerberos is already set up for a different user";
      std::move(callback).Run(false /* success */);
      return;
    }
  }

  if (is_kerberos_setup_ && account_identifier_ == account_identifier) {
    LOG(WARNING) << "Kerberos already set up the user";
    std::move(callback).Run(true /* success */);
    return;
  }

  account_identifier_ = account_identifier;

  if (account_identifier_.empty()) {
    if (is_kerberos_setup_) {
      // Empty account identifier means there is no ticket available.
      // If Kerberos was already set up, remove existing credential files.
      RemoveFiles(std::move(callback));
    } else {
      // Credential files were not created yet, so just return with success.
      std::move(callback).Run(true /* success */);
    }
    return;
  }

  GetFiles(std::move(callback));
}

void KerberosArtifactSynchronizer::GetFiles(SetupKerberosCallback callback) {
  client_->GetKerberosFiles(
      account_identifier_,
      base::BindOnce(&KerberosArtifactSynchronizer::OnGetFilesResponse,
                     base::Unretained(this), std::move(callback)));
}

void KerberosArtifactSynchronizer::OnGetFilesResponse(
    SetupKerberosCallback callback,
    bool success,
    const std::string& krb5_ccache,
    const std::string& krb5_conf) {
  DCHECK(callback);

  if (!success) {
    LOG(ERROR) << "KerberosArtifactSynchronizer failed to get Kerberos files";
    std::move(callback).Run(false /* setup_success */);
    return;
  }

  WriteFiles(krb5_ccache, krb5_conf, std::move(callback));
}

void KerberosArtifactSynchronizer::WriteFiles(const std::string& krb5_ccache,
                                              const std::string& krb5_conf,
                                              SetupKerberosCallback callback) {
  DCHECK(callback);

  bool success = WriteFile(krb5_conf_path_, krb5_conf) &&
                 WriteFile(krb5_ccache_path_, krb5_ccache);

  if (is_kerberos_setup_) {
    // Signal is already setup.
    if (!success) {
      LOG(ERROR) << "KerberosArtifactSynchronizer: failed to write updated "
                    "Kerberos Files";
      std::move(callback).Run(false /* setup_success */);
      return;
    }
    // If credentials update is allowed, this happens if we call setup more
    // than once to update credentials or GetFiles is triggered by
    // KerberosFilesChanged signal. Otherwise, if credentials update is not
    // allowed, this is rare case where the browser restarted and
    // SetupKerberos() was called twice in quick succession. If
    // |is_kerberos_setup_| is true, then the first call to SetupKerberos()
    // succeeded, so treat this as a success.
    std::move(callback).Run(true /* setup_success */);
    return;
  }

  if (!success) {
    // Failed to write the Kerberos files so return error to caller.
    LOG(ERROR) << "KerberosArtifactSynchronizer: failed to write initial "
                  "Kerberos Files";
    std::move(callback).Run(false /* setup_success */);
    return;
  }

  // Sets is_kerberos_setup_ to true on successful signal connection.
  ConnectToKerberosFilesChangedSignal(std::move(callback));
}

void KerberosArtifactSynchronizer::ConnectToKerberosFilesChangedSignal(
    SetupKerberosCallback callback) {
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

  // Call GetFiles with empty callback, since after files are retrieved and
  // stored there is no further action needed. Normally we would use
  // base::DoNothing, but it's not working with a parameter.
  // TODO(tomdobro): switch to base::DoNothing once libchrome is updated.
  auto files_stored_callback = [](bool /* setup_success */) {};
  GetFiles(base::BindOnce(files_stored_callback));
}

void KerberosArtifactSynchronizer::OnKerberosFilesChangedSignalConnected(
    SetupKerberosCallback callback,
    const std::string& interface_name,
    const std::string& signal_name,
    bool success) {
  DCHECK(success);

  if (is_kerberos_setup_) {
    // If SetupKerberos() was called twice in quick succession (i.e. if the
    // browser restarted on login), it's possible for this change signal to be
    // registered twice. The change handler will be run twice, but this
    // shouldn't be an issue.
    LOG(ERROR) << "Duplicate Kerberos file change signals registered";
  }
  is_kerberos_setup_ = true;
  std::move(callback).Run(true /* setup_success */);
}

bool KerberosArtifactSynchronizer::WriteFile(const std::string& path,
                                             const std::string& blob) {
  const base::FilePath file_path(path);
  if (!base::ImportantFileWriter::WriteFileAtomically(file_path, blob)) {
    LOG(ERROR) << "Failed to write file " << file_path.value();
    return false;
  }
  return true;
}

void KerberosArtifactSynchronizer::RemoveFiles(SetupKerberosCallback callback) {
  bool success = RemoveFile(krb5_conf_path_) && RemoveFile(krb5_ccache_path_);
  LOG_IF(ERROR, !success)
      << "KerberosArtifactSynchronizer failed to remove Kerberos files";
  std::move(callback).Run(success);
}

bool KerberosArtifactSynchronizer::RemoveFile(const std::string& path) {
  if (!base::DeleteFile(base::FilePath(path))) {
    LOG(ERROR) << "Failed to delete file " << path;
    return false;
  }
  return true;
}

}  // namespace smbprovider

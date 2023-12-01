// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "smbfs/mojo_session.h"

#include <unistd.h>

#include <utility>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <mojo/public/cpp/bindings/pending_receiver.h>
#include <mojo/public/cpp/bindings/pending_remote.h>
#include <mojo/public/cpp/bindings/receiver.h>

#include "smbfs/authpolicy_client.h"
#include "smbfs/fuse_session.h"
#include "smbfs/kerberos_artifact_synchronizer.h"
#include "smbfs/kerberos_client.h"
#include "smbfs/smb_filesystem.h"
#include "smbfs/smbfs.h"
#include "smbfs/smbfs_impl.h"

namespace smbfs {
namespace {

constexpr char kKerberosConfDir[] = ".krb";
constexpr char kKrb5ConfFile[] = "krb5.conf";
constexpr char kCCacheFile[] = "ccache";
constexpr char kKrbTraceFile[] = "krb_trace.txt";
constexpr char kDaemonStoreDirectory[] = "/run/daemon-store/smbfs";

}  // namespace

MojoSession::MojoSession(
    scoped_refptr<dbus::Bus> bus,
    const base::FilePath& temp_dir,
    fuse_chan* chan,
    mojo::PendingReceiver<mojom::SmbFsBootstrap> bootstrap_receiver,
    uid_t uid,
    gid_t gid,
    base::OnceClosure shutdown_callback)
    : bus_(std::move(bus)),
      temp_dir_(temp_dir),
      chan_(chan),
      uid_(uid),
      gid_(gid),
      shutdown_callback_(std::move(shutdown_callback)),
      bootstrap_impl_(std::make_unique<SmbFsBootstrapImpl>(
          std::move(bootstrap_receiver),
          base::BindRepeating(&MojoSession::CreateSmbFilesystem,
                              base::Unretained(this)),
          this,
          base::FilePath(kDaemonStoreDirectory))) {
  DCHECK(!temp_dir_.empty());
  DCHECK(chan_);
  DCHECK(shutdown_callback_);

  // Setup locations of Kerberos configuration files.
  base::File::Error error;
  bool success = base::CreateDirectoryAndGetError(
      temp_dir_.Append(kKerberosConfDir), &error);
  CHECK(success) << "Failed to create kerberos configuration directory: "
                 << base::File::ErrorToString(error);

  PCHECK(setenv("KRB5_CONFIG",
                KerberosConfFilePath(kKrb5ConfFile).value().c_str(),
                1 /* overwrite */) == 0);
  PCHECK(setenv("KRB5CCNAME", KerberosConfFilePath(kCCacheFile).value().c_str(),
                1 /* overwrite */) == 0);
  PCHECK(setenv("KRB5_TRACE",
                KerberosConfFilePath(kKrbTraceFile).value().c_str(),
                1 /* overwrite */) == 0);

  bootstrap_impl_->Start(base::BindOnce(&MojoSession::OnBootstrapComplete,
                                        base::Unretained(this)));
}

MojoSession::~MojoSession() = default;

base::FilePath MojoSession::KerberosConfFilePath(const std::string& file_name) {
  return temp_dir_.Append(kKerberosConfDir).Append(file_name);
}

void MojoSession::SetupKerberos(
    mojom::KerberosConfigPtr kerberos_config,
    base::OnceCallback<void(bool success)> callback) {
  DCHECK(!kerberos_sync_);
  DCHECK(kerberos_config);

  std::unique_ptr<KerberosArtifactClientInterface> client;
  switch (kerberos_config->source) {
    case mojom::KerberosConfig::Source::kActiveDirectory:
      client = std::make_unique<AuthPolicyClient>(bus_);
      break;
    case mojom::KerberosConfig::Source::kKerberos:
      client = std::make_unique<KerberosClient>(bus_);
      break;
  }

  DCHECK(client);
  kerberos_sync_ = std::make_unique<KerberosArtifactSynchronizer>(
      KerberosConfFilePath(kKrb5ConfFile), KerberosConfFilePath(kCCacheFile),
      kerberos_config->identity, std::move(client));
  kerberos_sync_->SetupKerberos(std::move(callback));
}

void MojoSession::OnPasswordFilePathSet(const base::FilePath& path) {
  password_file_path_ = path;
}

std::unique_ptr<SmbFilesystem> MojoSession::CreateSmbFilesystem(
    SmbFilesystem::Options options) {
  options.uid = uid_;
  options.gid = gid_;
  options.use_kerberos = kerberos_sync_.get();
  return std::make_unique<SmbFilesystem>(this, std::move(options));
}

void MojoSession::OnBootstrapComplete(
    std::unique_ptr<SmbFilesystem> fs,
    mojo::PendingReceiver<mojom::SmbFs> smbfs_receiver,
    mojo::PendingRemote<mojom::SmbFsDelegate> delegate) {
  if (!fs) {
    LOG(ERROR) << "Connection error during Mojo bootstrap.";
    DoShutdown();
    return;
  }

  DCHECK(!fuse_session_);
  DCHECK(chan_);

  smbfs_impl_ = std::make_unique<SmbFsImpl>(
      fs->GetWeakPtr(), std::move(smbfs_receiver), password_file_path_);
  smbfs_delegate_ =
      mojo::Remote<smbfs::mojom::SmbFsDelegate>(std::move(delegate));
  smbfs_delegate_.set_disconnect_handler(
      base::BindOnce(&MojoSession::DoShutdown, base::Unretained(this)));

  fuse_session_ = std::make_unique<FuseSession>(std::move(fs), chan_);
  chan_ = nullptr;
  CHECK(fuse_session_->Start(
      base::BindOnce(&MojoSession::DoShutdown, base::Unretained(this))));
}

void MojoSession::DoShutdown() {
  if (!shutdown_callback_) {
    return;
  }

  std::move(shutdown_callback_).Run();
}

void MojoSession::RequestCredentials(RequestCredentialsCallback callback) {
  DCHECK(smbfs_delegate_);
  smbfs_delegate_->RequestCredentials(
      base::BindOnce(&MojoSession::OnRequestCredentialsDone,
                     base::Unretained(this), std::move(callback)));
}

void MojoSession::OnRequestCredentialsDone(RequestCredentialsCallback callback,
                                           mojom::CredentialsPtr credentials) {
  if (!credentials) {
    std::move(callback).Run(nullptr);
    return;
  }

  std::unique_ptr<SmbCredential> smb_cred = std::make_unique<SmbCredential>(
      credentials->workgroup, credentials->username, nullptr);
  if (credentials->password) {
    smb_cred->password = std::move(credentials->password.value());
  }
  std::move(callback).Run(std::move(smb_cred));
}

}  // namespace smbfs

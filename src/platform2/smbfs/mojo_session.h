// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SMBFS_MOJO_SESSION_H_
#define SMBFS_MOJO_SESSION_H_

#include <fuse_lowlevel.h>
#include <sys/types.h>

#include <memory>
#include <string>

#include <base/files/file_path.h>
#include <base/functional/callback.h>
#include <dbus/bus.h>
#include <mojo/public/cpp/bindings/pending_receiver.h>
#include <mojo/public/cpp/bindings/pending_remote.h>
#include <mojo/public/cpp/bindings/remote.h>

#include "smbfs/smb_filesystem.h"
#include "smbfs/smbfs_bootstrap_impl.h"

namespace smbfs {

class FuseSession;
class KerberosArtifactSynchronizer;
class SmbFsImpl;
struct Options;

// MojoSession maintains the state of a SMB filesystem initialised over a Mojo
// IPC connection. It is responsible for responding to the setup request (via
// a mojom::SmbFsBootstrap implementation), synchronising with Kerberos,
// owning/running the FUSE session, and owning the Mojo interfaces to the
// browser.
class MojoSession : public SmbFsBootstrapImpl::Delegate,
                    public SmbFilesystem::Delegate {
 public:
  MojoSession(scoped_refptr<dbus::Bus> bus,
              const base::FilePath& temp_dir,
              fuse_chan* chan,
              mojo::PendingReceiver<mojom::SmbFsBootstrap> bootstrap_receiver,
              uid_t uid,
              gid_t gid,
              base::OnceClosure shutdown_callback);
  MojoSession(const MojoSession&) = delete;
  MojoSession& operator=(const MojoSession&) = delete;

  virtual ~MojoSession();

 private:
  // SmbFsBootstrapImpl::Delegate overrides.
  void SetupKerberos(mojom::KerberosConfigPtr kerberos_config,
                     base::OnceCallback<void(bool success)> callback) override;
  void OnPasswordFilePathSet(const base::FilePath& path) override;

  // SmbFilesystem::Delegate overrides.
  void RequestCredentials(RequestCredentialsCallback callback) override;

  // Callback for mojom::SmbFsDelegate::RequestCredentials().
  void OnRequestCredentialsDone(RequestCredentialsCallback callback,
                                mojom::CredentialsPtr credentials);

  // Returns the full path to the given kerberos configuration file.
  base::FilePath KerberosConfFilePath(const std::string& file_name);

  // Callback for SmbFsBootstrapImpl::Start().
  void OnBootstrapComplete(std::unique_ptr<SmbFilesystem> fs,
                           mojo::PendingReceiver<mojom::SmbFs> smbfs_receiver,
                           mojo::PendingRemote<mojom::SmbFsDelegate> delegate);

  // Factory function for creating an SmbFilesystem.
  std::unique_ptr<SmbFilesystem> CreateSmbFilesystem(
      SmbFilesystem::Options options);

  // Runs |shutdown_callback_|.
  void DoShutdown();

  scoped_refptr<dbus::Bus> const bus_;
  const base::FilePath temp_dir_;
  fuse_chan* chan_;
  const uid_t uid_;
  const gid_t gid_;
  base::OnceClosure shutdown_callback_;
  std::unique_ptr<SmbFsBootstrapImpl> bootstrap_impl_;

  base::FilePath password_file_path_;
  std::unique_ptr<FuseSession> fuse_session_;
  std::unique_ptr<KerberosArtifactSynchronizer> kerberos_sync_;
  std::unique_ptr<SmbFsImpl> smbfs_impl_;
  mojo::Remote<mojom::SmbFsDelegate> smbfs_delegate_;
};

}  // namespace smbfs

#endif  // SMBFS_MOJO_SESSION_H_

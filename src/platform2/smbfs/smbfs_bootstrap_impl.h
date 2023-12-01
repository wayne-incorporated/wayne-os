// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SMBFS_SMBFS_BOOTSTRAP_IMPL_H_
#define SMBFS_SMBFS_BOOTSTRAP_IMPL_H_

#include <memory>
#include <string>

#include <base/files/file_path.h>
#include <base/functional/callback.h>
#include <mojo/public/cpp/bindings/pending_receiver.h>
#include <mojo/public/cpp/bindings/pending_remote.h>
#include <mojo/public/cpp/bindings/receiver.h>

#include "smbfs/mojom/smbfs.mojom.h"
#include "smbfs/smb_filesystem.h"

namespace smbfs {

class Filesystem;
struct SmbCredential;

// Implements mojom::SmbFsBootstrap to mount an SMB share.
class SmbFsBootstrapImpl : public mojom::SmbFsBootstrap {
 public:
  // Delegate interface used for actions that need to persist after the
  // bootstrap process has completed.
  class Delegate {
   public:
    // Sets up Kerberos authentication.
    virtual void SetupKerberos(
        mojom::KerberosConfigPtr kerberos_config,
        base::OnceCallback<void(bool success)> callback) = 0;

    // Observer for when the password file path has been determined. The file
    // at |path| may not exist at this point, but it will exist if bootstrap
    // completes successfully.
    virtual void OnPasswordFilePathSet(const base::FilePath& path) = 0;
  };

  // Factory function to create an SmbFilesystem instance.
  using SmbFilesystemFactory =
      base::RepeatingCallback<std::unique_ptr<SmbFilesystem>(
          SmbFilesystem::Options)>;

  using BootstrapCompleteCallback = base::OnceCallback<void(
      std::unique_ptr<SmbFilesystem> fs,
      mojo::PendingReceiver<mojom::SmbFs> receiver,
      mojo::PendingRemote<mojom::SmbFsDelegate> delegate)>;

  SmbFsBootstrapImpl(mojo::PendingReceiver<mojom::SmbFsBootstrap> receiver,
                     SmbFilesystemFactory smb_filesystem_factory,
                     Delegate* delegate,
                     const base::FilePath& daemon_store_root);
  SmbFsBootstrapImpl(const SmbFsBootstrapImpl&) = delete;
  SmbFsBootstrapImpl& operator=(const SmbFsBootstrapImpl&) = delete;

  ~SmbFsBootstrapImpl() override;

  // Start the bootstrap process and run |callback| when finished or the Mojo
  // channel is disconnected. If the bootstrap process completed successfully,
  // |callback| will be called with a valid SmbFilesystem object. If the Mojo
  // channel is disconnected, |callback| will be run with nullptr.
  void Start(BootstrapCompleteCallback callback);

 private:
  // mojom::SmbFsBootstrap overrides.
  void MountShare(mojom::MountOptionsPtr options,
                  mojo::PendingRemote<mojom::SmbFsDelegate> smbfs_delegate,
                  MountShareCallback callback) override;

  // Callback to continue MountShare after setting up credentials
  // (username/password, or kerberos).
  void OnCredentialsSetup(
      mojom::MountOptionsPtr options,
      mojo::PendingRemote<mojom::SmbFsDelegate> smbfs_delegate,
      MountShareCallback callback,
      std::unique_ptr<SmbCredential> credential,
      bool use_kerberos,
      bool setup_success);

  // Mojo connection error handler.
  void OnMojoConnectionError();

  // Return the daemon store directory for the user profile |username_hash|.
  base::FilePath GetUserDaemonStoreDirectory(
      const std::string& username_hash) const;

  mojo::Receiver<mojom::SmbFsBootstrap> receiver_;
  base::OnceClosure disconnect_callback_;

  const SmbFilesystemFactory smb_filesystem_factory_;
  Delegate* const delegate_;
  const base::FilePath daemon_store_root_;
  BootstrapCompleteCallback completion_callback_;
};

}  // namespace smbfs

#endif  // SMBFS_SMBFS_BOOTSTRAP_IMPL_H_

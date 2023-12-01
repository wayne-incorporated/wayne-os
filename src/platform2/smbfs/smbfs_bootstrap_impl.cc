// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "smbfs/smbfs_bootstrap_impl.h"

#include <utility>
#include <vector>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/strings/strcat.h>
#include <base/strings/string_number_conversions.h>
#include <brillo/secure_blob.h>
#include <crypto/hmac.h>
#include <libpasswordprovider/password.h>
#include <mojo/public/cpp/bindings/remote.h>
#include <mojo/public/cpp/system/platform_handle.h>

#include "smbfs/smb_credential.h"
#include "smbfs/smb_filesystem.h"

namespace smbfs {
namespace {

mojom::MountError ConnectErrorToMountError(SmbFilesystem::ConnectError error) {
  switch (error) {
    case SmbFilesystem::ConnectError::kNotFound:
      return mojom::MountError::kNotFound;
    case SmbFilesystem::ConnectError::kAccessDenied:
      return mojom::MountError::kAccessDenied;
    case SmbFilesystem::ConnectError::kSmb1Unsupported:
      return mojom::MountError::kInvalidProtocol;
    default:
      return mojom::MountError::kUnknown;
  }
}

base::FilePath MakePasswordFileName(const std::string& share_path,
                                    const std::string& username,
                                    const std::string& workgroup,
                                    const std::vector<uint8_t>& salt) {
  // Normally, this could produce overlapping strings. eg. with
  // username/workgroup: "abc"/"def" and "a"/"bcdef". However, the salt ensures
  // the final filename is unique even if two mounts produce the same
  // |raw_name|.
  const std::string raw_name = base::StrCat({share_path, username, workgroup});
  crypto::HMAC hmac(crypto::HMAC::SHA256);
  CHECK(hmac.Init(salt.data(), salt.size()));

  const size_t hash_len = hmac.DigestLength();
  std::unique_ptr<unsigned char[]> raw_hash =
      std::make_unique<unsigned char[]>(hash_len);
  CHECK(hmac.Sign(raw_name, raw_hash.get(), hash_len));
  return base::FilePath(base::HexEncode(raw_hash.get(), hash_len));
}

brillo::SecureVector ObfuscatePassword(
    const password_provider::Password& password,
    const std::vector<uint8_t>& salt) {
  brillo::SecureVector obfuscated(password.GetRaw(),
                                  password.GetRaw() + password.size());
  // Obfuscate the password using the salt.
  for (size_t i = 0; i < obfuscated.size(); i++) {
    obfuscated[i] ^= salt[i % salt.size()];
  }
  return obfuscated;
}

bool SavePasswordToFile(const base::FilePath& file_path,
                        const brillo::SecureVector& obfuscated_password) {
  base::File password_file(
      file_path, base::File::FLAG_CREATE_ALWAYS | base::File::FLAG_WRITE);
  if (!password_file.IsValid()) {
    LOG(ERROR) << "Unable to open password file for write with error: "
               << password_file.error_details();
    return false;
  }

  int written = password_file.WriteAtCurrentPos(
      reinterpret_cast<const char*>(obfuscated_password.data()),
      obfuscated_password.size());
  return written == obfuscated_password.size();
}

std::unique_ptr<password_provider::Password> ReadPasswordFromFile(
    const base::FilePath& file_path, const std::vector<uint8_t>& salt) {
  base::File password_file(file_path,
                           base::File::FLAG_OPEN | base::File::FLAG_READ);
  if (!password_file.IsValid()) {
    LOG(ERROR) << "Unable to open password file with error: "
               << password_file.error_details();
    return nullptr;
  }

  brillo::SecureVector tmp_password(password_file.GetLength());
  int read = password_file.ReadAtCurrentPos(
      reinterpret_cast<char*>(tmp_password.data()), password_file.GetLength());
  if (read != password_file.GetLength()) {
    LOG(ERROR) << "Unexpected password file read length: " << read;
    return nullptr;
  }

  if (!salt.empty()) {
    for (size_t i = 0; i < tmp_password.size(); i++) {
      tmp_password[i] ^= salt[i % salt.size()];
    }
  }

  int fds[2];
  CHECK(base::CreateLocalNonBlockingPipe(fds));
  base::ScopedFD read_fd(fds[0]);
  base::ScopedFD write_fd(fds[1]);
  CHECK(base::WriteFileDescriptor(write_fd.get(), tmp_password));
  return password_provider::Password::CreateFromFileDescriptor(
      read_fd.get(), tmp_password.size());
}

}  // namespace

SmbFsBootstrapImpl::SmbFsBootstrapImpl(
    mojo::PendingReceiver<mojom::SmbFsBootstrap> receiver,
    SmbFilesystemFactory smb_filesystem_factory,
    Delegate* delegate,
    const base::FilePath& daemon_store_root)
    : receiver_(this, std::move(receiver)),
      smb_filesystem_factory_(smb_filesystem_factory),
      delegate_(delegate),
      daemon_store_root_(daemon_store_root) {
  DCHECK(smb_filesystem_factory_);
  DCHECK(delegate_);
  DCHECK(!daemon_store_root_.empty());
  receiver_.set_disconnect_handler(base::BindOnce(
      &SmbFsBootstrapImpl::OnMojoConnectionError, base::Unretained(this)));
}

SmbFsBootstrapImpl::~SmbFsBootstrapImpl() = default;

void SmbFsBootstrapImpl::Start(BootstrapCompleteCallback callback) {
  DCHECK(!completion_callback_);
  completion_callback_ = std::move(callback);
}

void SmbFsBootstrapImpl::MountShare(
    mojom::MountOptionsPtr options,
    mojo::PendingRemote<mojom::SmbFsDelegate> smbfs_delegate,
    MountShareCallback callback) {
  if (!completion_callback_) {
    LOG(ERROR) << "Mojo bootstrap not active";
    std::move(callback).Run(mojom::MountError::kUnknown,
                            mojo::PendingRemote<smbfs::mojom::SmbFs>());
    return;
  }

  if (options->share_path.find("smb://") != 0) {
    // TODO(amistry): More extensive URL validation.
    LOG(ERROR) << "Invalid share path: " << options->share_path;
    std::move(callback).Run(mojom::MountError::kInvalidUrl,
                            mojo::PendingRemote<smbfs::mojom::SmbFs>());
    return;
  }

  std::unique_ptr<SmbCredential> credential = std::make_unique<SmbCredential>(
      options->workgroup, options->username, nullptr);
  if (options->kerberos_config) {
    delegate_->SetupKerberos(
        std::move(options->kerberos_config),
        base::BindOnce(&SmbFsBootstrapImpl::OnCredentialsSetup,
                       base::Unretained(this), std::move(options),
                       std::move(smbfs_delegate), std::move(callback),
                       std::move(credential), true /* use_kerberos */));
    return;
  }

  if (options->password) {
    credential->password = std::move(options->password.value());
  }

  OnCredentialsSetup(std::move(options), std::move(smbfs_delegate),
                     std::move(callback), std::move(credential),
                     false /* use_kerberos */, true /* setup_success */);
}

void SmbFsBootstrapImpl::OnCredentialsSetup(
    mojom::MountOptionsPtr options,
    mojo::PendingRemote<mojom::SmbFsDelegate> smbfs_delegate,
    MountShareCallback callback,
    std::unique_ptr<SmbCredential> credential,
    bool use_kerberos,
    bool setup_success) {
  DCHECK(credential);

  if (!setup_success) {
    std::move(callback).Run(mojom::MountError::kUnknown,
                            mojo::PendingRemote<smbfs::mojom::SmbFs>());
    return;
  }

  base::FilePath pass_file_path;
  brillo::SecureVector obfuscated_password;
  if (!use_kerberos && options->credential_storage_options &&
      !credential->username.empty()) {
    CHECK_GE(options->credential_storage_options->salt.size(),
             mojom::CredentialStorageOptions::kMinSaltLength);
    const base::FilePath pass_file_name = MakePasswordFileName(
        options->share_path, credential->username, credential->workgroup,
        options->credential_storage_options->salt);
    pass_file_path = GetUserDaemonStoreDirectory(
                         options->credential_storage_options->account_hash)
                         .Append(pass_file_name);
    delegate_->OnPasswordFilePathSet(pass_file_path);

    if (credential->password) {
      // We obfuscate the password now because |credential| is moved into the
      // SmbFilesystem and is unavailable when we know the connection is
      // successful.
      obfuscated_password = ObfuscatePassword(
          *credential->password, options->credential_storage_options->salt);
    } else {
      credential->password = ReadPasswordFromFile(
          pass_file_path, options->credential_storage_options->salt);
    }
  }

  SmbFilesystem::Options smb_options;
  smb_options.share_path = options->share_path;
  smb_options.credentials = std::move(credential);
  smb_options.allow_ntlm = options->allow_ntlm;
  auto fs = smb_filesystem_factory_.Run(std::move(smb_options));
  // Don't use the resolved address if Kerberos is set up. Kerberos requires the
  // full hostname to obtain auth tickets.
  if (options->resolved_host && !use_kerberos) {
    if (options->resolved_host->address_bytes.size() != 4) {
      LOG(ERROR) << "Invalid IP address size: "
                 << options->resolved_host->address_bytes.size();
      std::move(callback).Run(mojom::MountError::kInvalidOptions,
                              mojo::PendingRemote<smbfs::mojom::SmbFs>());
      return;
    }
    fs->SetResolvedAddress(options->resolved_host->address_bytes);
  }
  if (!options->skip_connect) {
    SmbFilesystem::ConnectError error = fs->EnsureConnected();
    if (error != SmbFilesystem::ConnectError::kOk) {
      LOG(ERROR) << "Unable to connect to SMB share " << options->share_path
                 << ": " << error;
      std::move(callback).Run(ConnectErrorToMountError(error),
                              mojo::PendingRemote<smbfs::mojom::SmbFs>());
      return;
    }
  }

  // Now that the share connection was successful, we can save the password.
  if (!obfuscated_password.empty()) {
    DCHECK(!pass_file_path.empty());
    CHECK(SavePasswordToFile(pass_file_path, obfuscated_password));
  }

  mojo::PendingRemote<mojom::SmbFs> smbfs;
  std::move(completion_callback_)
      .Run(std::move(fs), smbfs.InitWithNewPipeAndPassReceiver(),
           std::move(smbfs_delegate));

  std::move(callback).Run(mojom::MountError::kOk, std::move(smbfs));
}

void SmbFsBootstrapImpl::OnMojoConnectionError() {
  if (completion_callback_) {
    std::move(completion_callback_)
        .Run(nullptr,
             mojo::PendingRemote<smbfs::mojom::SmbFs>()
                 .InitWithNewPipeAndPassReceiver(),
             mojo::PendingRemote<smbfs::mojom::SmbFsDelegate>());
  }
}

base::FilePath SmbFsBootstrapImpl::GetUserDaemonStoreDirectory(
    const std::string& username_hash) const {
  CHECK(!username_hash.empty());
  return daemon_store_root_.Append(username_hash);
}

}  // namespace smbfs

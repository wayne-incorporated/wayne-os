// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "smbfs/smb_filesystem.h"
#include "smbfs/smbfs_impl.h"

#include <utility>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>

namespace smbfs {

SmbFsImpl::SmbFsImpl(base::WeakPtr<SmbFilesystem> fs,
                     mojo::PendingReceiver<mojom::SmbFs> receiver,
                     const base::FilePath& password_file_path)
    : fs_(fs),
      receiver_(this, std::move(receiver)),
      password_file_path_(password_file_path) {
  DCHECK(fs_);
}

SmbFsImpl::~SmbFsImpl() = default;

void SmbFsImpl::RemoveSavedCredentials(
    RemoveSavedCredentialsCallback callback) {
  if (password_file_path_.empty()) {
    std::move(callback).Run(true /* success */);
    return;
  }

  bool success = base::DeleteFile(password_file_path_);
  LOG_IF(WARNING, !success) << "Unable to erase credential file";
  std::move(callback).Run(success);
}

void SmbFsImpl::DeleteRecursively(const base::FilePath& path,
                                  DeleteRecursivelyCallback callback) {
  CHECK(path.IsAbsolute());
  CHECK(!path.ReferencesParent());

  fs_->DeleteRecursively(path, std::move(callback));
}

}  // namespace smbfs

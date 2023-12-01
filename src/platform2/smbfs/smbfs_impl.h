// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SMBFS_SMBFS_IMPL_H_
#define SMBFS_SMBFS_IMPL_H_

#include <string>

#include <base/files/file_path.h>
#include <base/memory/weak_ptr.h>
#include <mojo/public/cpp/bindings/pending_receiver.h>
#include <mojo/public/cpp/bindings/receiver.h>

#include "smbfs/mojom/smbfs.mojom.h"

namespace smbfs {

class SmbFilesystem;

// Implementation of the mojom::SmbFs Mojo interface to provide SMB share
// control to the browser.
class SmbFsImpl : public mojom::SmbFs {
 public:
  explicit SmbFsImpl(base::WeakPtr<SmbFilesystem> fs,
                     mojo::PendingReceiver<mojom::SmbFs> receiver,
                     const base::FilePath& password_file_path);

  SmbFsImpl() = delete;
  SmbFsImpl(const SmbFsImpl&) = delete;
  SmbFsImpl& operator=(const SmbFsImpl&) = delete;

  ~SmbFsImpl() override;

 private:
  // mojom::SmbFs overrides.
  void RemoveSavedCredentials(RemoveSavedCredentialsCallback callback) override;
  void DeleteRecursively(const base::FilePath& path,
                         DeleteRecursivelyCallback callback) override;

  base::WeakPtr<SmbFilesystem> fs_;
  mojo::Receiver<mojom::SmbFs> receiver_;
  const base::FilePath password_file_path_;
};

}  // namespace smbfs

#endif  // SMBFS_SMBFS_IMPL_H_

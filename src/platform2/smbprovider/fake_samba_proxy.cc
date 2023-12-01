// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "smbprovider/fake_samba_proxy.h"

#include <utility>

#include <base/check.h>
#include <base/logging.h>

namespace smbprovider {

SambaInterface::SambaInterfaceId FakeSambaProxy::count_ = 0;

FakeSambaProxy::FakeSambaProxy(FakeSambaInterface* fake_samba_interface)
    : fake_samba_interface_(fake_samba_interface) {
  DCHECK(fake_samba_interface_);
}

int32_t FakeSambaProxy::OpenDirectory(const std::string& directory_path,
                                      int32_t* dir_id) {
  return fake_samba_interface_->OpenDirectory(directory_path, dir_id);
}

int32_t FakeSambaProxy::CloseDirectory(int32_t dir_id) {
  return fake_samba_interface_->CloseDirectory(dir_id);
}

int32_t FakeSambaProxy::GetDirectoryEntry(int32_t dir_id,
                                          const struct smbc_dirent** dirent) {
  return fake_samba_interface_->GetDirectoryEntry(dir_id, dirent);
}

int32_t FakeSambaProxy::GetDirectoryEntryWithMetadata(
    int32_t dir_id, const struct libsmb_file_info** file_info) {
  return fake_samba_interface_->GetDirectoryEntryWithMetadata(dir_id,
                                                              file_info);
}

int32_t FakeSambaProxy::GetEntryStatus(const std::string& entry_path,
                                       struct stat* stat) {
  return fake_samba_interface_->GetEntryStatus(entry_path, stat);
}

SambaInterface::SambaInterfaceId FakeSambaProxy::GetSambaInterfaceId() {
  return samba_interface_id_;
}

SambaInterface::WeakPtr FakeSambaProxy::AsWeakPtr() {
  return weak_factory_.GetWeakPtr();
}

int32_t FakeSambaProxy::OpenFile(const std::string& file_path,
                                 int32_t flags,
                                 int32_t* file_id) {
  return fake_samba_interface_->OpenFile(file_path, flags, file_id);
}

int32_t FakeSambaProxy::CloseFile(int32_t file_id) {
  return fake_samba_interface_->CloseFile(file_id);
}

int32_t FakeSambaProxy::ReadFile(int32_t file_id,
                                 uint8_t* buffer,
                                 size_t buffer_size,
                                 size_t* bytes_read) {
  return fake_samba_interface_->ReadFile(file_id, buffer, buffer_size,
                                         bytes_read);
}

int32_t FakeSambaProxy::Seek(int32_t file_id, int64_t offset) {
  return fake_samba_interface_->Seek(file_id, offset);
}

int32_t FakeSambaProxy::Unlink(const std::string& file_path) {
  return fake_samba_interface_->Unlink(file_path);
}

int32_t FakeSambaProxy::RemoveDirectory(const std::string& dir_path) {
  return fake_samba_interface_->RemoveDirectory(dir_path);
}

int32_t FakeSambaProxy::CreateFile(const std::string& file_path,
                                   int32_t* file_id) {
  return fake_samba_interface_->CreateFile(file_path, file_id);
}

int32_t FakeSambaProxy::Truncate(int32_t file_id, size_t size) {
  return fake_samba_interface_->Truncate(file_id, size);
}

int32_t FakeSambaProxy::WriteFile(int32_t file_id,
                                  const uint8_t* buffer,
                                  size_t buffer_size) {
  return fake_samba_interface_->WriteFile(file_id, buffer, buffer_size);
}

int32_t FakeSambaProxy::CreateDirectory(const std::string& directory_path) {
  return fake_samba_interface_->CreateDirectory(directory_path);
}

int32_t FakeSambaProxy::MoveEntry(const std::string& source_path,
                                  const std::string& target_path) {
  return fake_samba_interface_->MoveEntry(source_path, target_path);
}

int32_t FakeSambaProxy::CopyFile(const std::string& source_path,
                                 const std::string& target_path) {
  return fake_samba_interface_->CopyFile(source_path, target_path);
}

int32_t FakeSambaProxy::SpliceFile(int32_t source_fd,
                                   int32_t target_fd,
                                   off_t length,
                                   off_t* bytes_written) {
  return fake_samba_interface_->SpliceFile(source_fd, target_fd, length,
                                           bytes_written);
}

}  // namespace smbprovider

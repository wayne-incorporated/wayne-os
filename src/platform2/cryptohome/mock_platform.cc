// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/mock_platform.h"

#include "cryptohome/fake_platform.h"

using testing::_;
using testing::Invoke;
using testing::NiceMock;
using testing::Return;

namespace cryptohome {

MockPlatform::MockPlatform()
    : mock_process_(new NiceMock<brillo::ProcessMock>()),
      fake_platform_(new FakePlatform()) {
  ON_CALL(*this, Rename(_, _))
      .WillByDefault(Invoke(fake_platform_.get(), &FakePlatform::Rename));
  ON_CALL(*this, Copy(_, _))
      .WillByDefault(Invoke(fake_platform_.get(), &FakePlatform::Copy));
  ON_CALL(*this, TouchFileDurable(_))
      .WillByDefault(
          Invoke(fake_platform_.get(), &FakePlatform::TouchFileDurable));
  ON_CALL(*this, DeleteFile(_))
      .WillByDefault(Invoke(fake_platform_.get(), &FakePlatform::DeleteFile));
  ON_CALL(*this, DeletePathRecursively(_))
      .WillByDefault(
          Invoke(fake_platform_.get(), &FakePlatform::DeletePathRecursively));
  ON_CALL(*this, DeleteFileDurable(_))
      .WillByDefault(
          Invoke(fake_platform_.get(), &FakePlatform::DeleteFileDurable));
  ON_CALL(*this, DeleteFileSecurely(_))
      .WillByDefault(
          Invoke(fake_platform_.get(), &FakePlatform::DeleteFileSecurely));
  ON_CALL(*this, EnumerateDirectoryEntries(_, _, _))
      .WillByDefault(Invoke(fake_platform_.get(),
                            &FakePlatform::EnumerateDirectoryEntries));
  ON_CALL(*this, GetFileEnumerator(_, _, _))
      .WillByDefault(
          Invoke(fake_platform_.get(), &FakePlatform::GetFileEnumerator));
  ON_CALL(*this, IsDirectoryEmpty(_))
      .WillByDefault(
          Invoke(fake_platform_.get(), &FakePlatform::IsDirectoryEmpty));
  ON_CALL(*this, FileExists(_))
      .WillByDefault(Invoke(fake_platform_.get(), &FakePlatform::FileExists));
  ON_CALL(*this, Access(_, _))
      .WillByDefault(Invoke(fake_platform_.get(), &FakePlatform::Access));
  ON_CALL(*this, DirectoryExists(_))
      .WillByDefault(
          Invoke(fake_platform_.get(), &FakePlatform::DirectoryExists));
  ON_CALL(*this, CreateDirectoryAndGetError(_, _))
      .WillByDefault(Invoke(fake_platform_.get(),
                            &FakePlatform::CreateDirectoryAndGetError));
  ON_CALL(*this, CreateDirectory(_))
      .WillByDefault(
          Invoke(fake_platform_.get(), &FakePlatform::CreateDirectory));
  ON_CALL(*this, CreateSparseFile(_, _))
      .WillByDefault(
          Invoke(fake_platform_.get(), &FakePlatform::CreateSparseFile));

  ON_CALL(*this, SyncFile(_))
      .WillByDefault(Invoke(fake_platform_.get(), &FakePlatform::SyncFile));
  ON_CALL(*this, SyncDirectory(_))
      .WillByDefault(
          Invoke(fake_platform_.get(), &FakePlatform::SyncDirectory));
  ON_CALL(*this, Sync())
      .WillByDefault(Invoke(fake_platform_.get(), &FakePlatform::Sync));

  ON_CALL(*this, CreateSymbolicLink(_, _))
      .WillByDefault(
          Invoke(fake_platform_.get(), &FakePlatform::CreateSymbolicLink));
  ON_CALL(*this, ReadLink(_, _))
      .WillByDefault(Invoke(fake_platform_.get(), &FakePlatform::ReadLink));

  ON_CALL(*this, SetFileTimes(_, _, _, _))
      .WillByDefault(Invoke(fake_platform_.get(), &FakePlatform::SetFileTimes));
  ON_CALL(*this, SendFile(_, _, _, _))
      .WillByDefault(Invoke(fake_platform_.get(), &FakePlatform::SendFile));

  ON_CALL(*this, InitializeFile(_, _, _))
      .WillByDefault(
          Invoke(fake_platform_.get(), &FakePlatform::InitializeFile));
  ON_CALL(*this, LockFile(_))
      .WillByDefault(Invoke(fake_platform_.get(), &FakePlatform::LockFile));

  ON_CALL(*this, ReadFile(_, _))
      .WillByDefault(Invoke(fake_platform_.get(), &FakePlatform::ReadFile));
  ON_CALL(*this, ReadFileToString(_, _))
      .WillByDefault(
          Invoke(fake_platform_.get(), &FakePlatform::ReadFileToString));
  ON_CALL(*this, ReadFileToSecureBlob(_, _))
      .WillByDefault(
          Invoke(fake_platform_.get(), &FakePlatform::ReadFileToSecureBlob));

  ON_CALL(*this, WriteFile(_, _))
      .WillByDefault(Invoke(fake_platform_.get(), &FakePlatform::WriteFile));
  ON_CALL(*this, WriteSecureBlobToFile(_, _))
      .WillByDefault(
          Invoke(fake_platform_.get(), &FakePlatform::WriteSecureBlobToFile));
  ON_CALL(*this, WriteFileAtomic(_, _, _))
      .WillByDefault(
          Invoke(fake_platform_.get(), &FakePlatform::WriteFileAtomic));
  ON_CALL(*this, WriteSecureBlobToFileAtomic(_, _, _))
      .WillByDefault(Invoke(fake_platform_.get(),
                            &FakePlatform::WriteSecureBlobToFileAtomic));
  ON_CALL(*this, WriteFileAtomicDurable(_, _, _))
      .WillByDefault(
          Invoke(fake_platform_.get(), &FakePlatform::WriteFileAtomicDurable));
  ON_CALL(*this, WriteSecureBlobToFileAtomicDurable(_, _, _))
      .WillByDefault(Invoke(fake_platform_.get(),
                            &FakePlatform::WriteSecureBlobToFileAtomicDurable));
  ON_CALL(*this, WriteStringToFile(_, _))
      .WillByDefault(
          Invoke(fake_platform_.get(), &FakePlatform::WriteStringToFile));
  ON_CALL(*this, WriteStringToFileAtomicDurable(_, _, _))
      .WillByDefault(Invoke(fake_platform_.get(),
                            &FakePlatform::WriteStringToFileAtomicDurable));
  ON_CALL(*this, WriteArrayToFile(_, _, _))
      .WillByDefault(
          Invoke(fake_platform_.get(), &FakePlatform::WriteArrayToFile));

  ON_CALL(*this, OpenFile(_, _))
      .WillByDefault(Invoke(fake_platform_.get(), &FakePlatform::OpenFile));
  ON_CALL(*this, CloseFile(_))
      .WillByDefault(Invoke(fake_platform_.get(), &FakePlatform::CloseFile));

  ON_CALL(*this, GetFileSize(_, _))
      .WillByDefault(Invoke(fake_platform_.get(), &FakePlatform::GetFileSize));
  ON_CALL(*this, Stat(_, _))
      .WillByDefault(Invoke(fake_platform_.get(), &FakePlatform::Stat));

  ON_CALL(*this, HasExtendedFileAttribute(_, _))
      .WillByDefault(Invoke(fake_platform_.get(),
                            &FakePlatform::HasExtendedFileAttribute));
  ON_CALL(*this, ListExtendedFileAttributes(_, _))
      .WillByDefault(Invoke(fake_platform_.get(),
                            &FakePlatform::ListExtendedFileAttributes));
  ON_CALL(*this, GetExtendedFileAttributeAsString(_, _, _))
      .WillByDefault(Invoke(fake_platform_.get(),
                            &FakePlatform::GetExtendedFileAttributeAsString));
  ON_CALL(*this, GetExtendedFileAttribute(_, _, _, _))
      .WillByDefault(Invoke(fake_platform_.get(),
                            &FakePlatform::GetExtendedFileAttribute));
  ON_CALL(*this, SetExtendedFileAttribute(_, _, _, _))
      .WillByDefault(Invoke(fake_platform_.get(),
                            &FakePlatform::SetExtendedFileAttribute));
  ON_CALL(*this, RemoveExtendedFileAttribute(_, _))
      .WillByDefault(Invoke(fake_platform_.get(),
                            &FakePlatform::RemoveExtendedFileAttribute));
  ON_CALL(*this, GetExtFileAttributes(_, _))
      .WillByDefault(
          Invoke(fake_platform_.get(), &FakePlatform::GetExtFileAttributes));
  ON_CALL(*this, SetExtFileAttributes(_, _))
      .WillByDefault(
          Invoke(fake_platform_.get(), &FakePlatform::SetExtFileAttributes));
  ON_CALL(*this, HasNoDumpFileAttribute(_))
      .WillByDefault(
          Invoke(fake_platform_.get(), &FakePlatform::HasNoDumpFileAttribute));
  ON_CALL(*this, GetQuotaProjectId(_, _))
      .WillByDefault(
          Invoke(fake_platform_.get(), &FakePlatform::GetQuotaProjectId));
  ON_CALL(*this, SetQuotaProjectId(_, _))
      .WillByDefault(
          Invoke(fake_platform_.get(), &FakePlatform::SetQuotaProjectId));

  ON_CALL(*this, GetOwnership(_, _, _, _))
      .WillByDefault(Invoke(fake_platform_.get(), &FakePlatform::GetOwnership));
  ON_CALL(*this, SetOwnership(_, _, _, _))
      .WillByDefault(Invoke(fake_platform_.get(), &FakePlatform::SetOwnership));
  ON_CALL(*this, SafeDirChown(_, _, _))
      .WillByDefault(Invoke(fake_platform_.get(), &FakePlatform::SafeDirChown));
  ON_CALL(*this, GetPermissions(_, _))
      .WillByDefault(
          Invoke(fake_platform_.get(), &FakePlatform::GetPermissions));
  ON_CALL(*this, SetPermissions(_, _))
      .WillByDefault(
          Invoke(fake_platform_.get(), &FakePlatform::SetPermissions));
  ON_CALL(*this, SafeDirChmod(_, _))
      .WillByDefault(Invoke(fake_platform_.get(), &FakePlatform::SafeDirChmod));
  ON_CALL(*this, SafeCreateDirAndSetOwnershipAndPermissions(_, _, _, _))
      .WillByDefault(
          Invoke(fake_platform_.get(),
                 &FakePlatform::SafeCreateDirAndSetOwnershipAndPermissions));
  ON_CALL(*this, GetLoopDeviceManager())
      .WillByDefault(
          Invoke(fake_platform_.get(), &FakePlatform::GetLoopDeviceManager));
  ON_CALL(*this, GetLogicalVolumeManager())
      .WillByDefault(
          Invoke(fake_platform_.get(), &FakePlatform::GetLogicalVolumeManager));

  ON_CALL(*this, AmountOfFreeDiskSpace(_))
      .WillByDefault(
          Invoke(fake_platform_.get(), &FakePlatform::AmountOfFreeDiskSpace));
  ON_CALL(*this, StatVFS(_, _))
      .WillByDefault(Invoke(fake_platform_.get(), &FakePlatform::StatVFS));

  ON_CALL(*this, Mount(_, _, _, _, _))
      .WillByDefault(Invoke(fake_platform_.get(), &FakePlatform::Mount));
  ON_CALL(*this, Bind(_, _, _, _))
      .WillByDefault(Invoke(fake_platform_.get(), &FakePlatform::Bind));
  ON_CALL(*this, Unmount(_, _, _))
      .WillByDefault(Invoke(fake_platform_.get(), &FakePlatform::Unmount));
  ON_CALL(*this, LazyUnmount(_))
      .WillByDefault(Invoke(fake_platform_.get(), &FakePlatform::LazyUnmount));
  ON_CALL(*this, GetLoopDeviceMounts(_))
      .WillByDefault(
          Invoke(fake_platform_.get(), &FakePlatform::GetLoopDeviceMounts));
  ON_CALL(*this, GetMountsBySourcePrefix(_, _))
      .WillByDefault(
          Invoke(fake_platform_.get(), &FakePlatform::GetMountsBySourcePrefix));
  ON_CALL(*this, IsDirectoryMounted(_))
      .WillByDefault(
          Invoke(fake_platform_.get(), &FakePlatform::IsDirectoryMounted));
  ON_CALL(*this, AreDirectoriesMounted(_))
      .WillByDefault(
          Invoke(fake_platform_.get(), &FakePlatform::AreDirectoriesMounted));

  ON_CALL(*this, GetCurrentTime())
      .WillByDefault(Return(base::Time::NowFromSystemTime()));
  ON_CALL(*this, ReportFilesystemDetails(_, _))
      .WillByDefault(CallReportFilesystemDetails());
  ON_CALL(*this, FindFilesystemDevice(_, _))
      .WillByDefault(CallFindFilesystemDevice());
  ON_CALL(*this, ComputeDirectoryDiskUsage(_))
      .WillByDefault(CallComputeDirectoryDiskUsage());
  ON_CALL(*this, SetupProcessKeyring()).WillByDefault(Return(true));
  ON_CALL(*this, GetDirCryptoKeyState(_))
      .WillByDefault(Return(dircrypto::KeyState::NO_KEY));
  ON_CALL(*this, CreateProcessInstance())
      .WillByDefault(Invoke(this, &MockPlatform::MockCreateProcessInstance));
  ON_CALL(*this, CreateUnguessableToken())
      .WillByDefault(
          Invoke(fake_platform_.get(), &FakePlatform::CreateUnguessableToken));
}

MockPlatform::~MockPlatform() {}

}  // namespace cryptohome

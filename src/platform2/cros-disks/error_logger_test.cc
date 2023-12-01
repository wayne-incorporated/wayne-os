// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <sstream>
#include <string>

#include <dbus/cros-disks/dbus-constants.h>
#include <gtest/gtest.h>

namespace cros_disks {
namespace {

template <typename T>
std::string ToString(T t) {
  std::ostringstream out;
  out << t << std::flush;
  return out.str();
}

TEST(ErrorLogger, DeviceType) {
  EXPECT_EQ(ToString(DeviceType::kUnknown), "Unknown");
  EXPECT_EQ(ToString(DeviceType::kUSB), "USB");
  EXPECT_EQ(ToString(DeviceType::kSD), "SD");
  EXPECT_EQ(ToString(DeviceType::kOpticalDisc), "OpticalDisc");
  EXPECT_EQ(ToString(DeviceType::kMobile), "Mobile");
  EXPECT_EQ(ToString(DeviceType::kDVD), "DVD");
  EXPECT_EQ(ToString(DeviceType(987654)), "DeviceType(987654)");
}

TEST(ErrorLogger, FormatError) {
  EXPECT_EQ(ToString(FormatError::kSuccess), "Success");
  EXPECT_EQ(ToString(FormatError::kUnknownError), "UnknownError");
  EXPECT_EQ(ToString(FormatError::kInternalError), "InternalError");
  EXPECT_EQ(ToString(FormatError::kInvalidDevicePath), "InvalidDevicePath");
  EXPECT_EQ(ToString(FormatError::kDeviceBeingFormatted),
            "DeviceBeingFormatted");
  EXPECT_EQ(ToString(FormatError::kUnsupportedFilesystem),
            "UnsupportedFilesystem");
  EXPECT_EQ(ToString(FormatError::kFormatProgramNotFound),
            "FormatProgramNotFound");
  EXPECT_EQ(ToString(FormatError::kFormatProgramFailed), "FormatProgramFailed");
  EXPECT_EQ(ToString(FormatError::kDeviceNotAllowed), "DeviceNotAllowed");
  EXPECT_EQ(ToString(FormatError::kInvalidOptions), "InvalidOptions");
  EXPECT_EQ(ToString(FormatError::kLongName), "LongName");
  EXPECT_EQ(ToString(FormatError::kInvalidCharacter), "InvalidCharacter");
  EXPECT_EQ(ToString(FormatError(987654)), "FormatError(987654)");
}

TEST(ErrorLogger, MountError) {
  EXPECT_EQ(ToString(MountError::kSuccess), "Success");
  EXPECT_EQ(ToString(MountError::kUnknownError), "UnknownError");
  EXPECT_EQ(ToString(MountError::kInternalError), "InternalError");
  EXPECT_EQ(ToString(MountError::kInvalidArgument), "InvalidArgument");
  EXPECT_EQ(ToString(MountError::kInvalidPath), "InvalidPath");
  EXPECT_EQ(ToString(MountError::kPathAlreadyMounted), "PathAlreadyMounted");
  EXPECT_EQ(ToString(MountError::kPathNotMounted), "PathNotMounted");
  EXPECT_EQ(ToString(MountError::kDirectoryCreationFailed),
            "DirectoryCreationFailed");
  EXPECT_EQ(ToString(MountError::kInvalidMountOptions), "InvalidMountOptions");
  EXPECT_EQ(ToString(MountError::kInvalidUnmountOptions),
            "InvalidUnmountOptions");
  EXPECT_EQ(ToString(MountError::kInsufficientPermissions),
            "InsufficientPermissions");
  EXPECT_EQ(ToString(MountError::kMountProgramNotFound),
            "MountProgramNotFound");
  EXPECT_EQ(ToString(MountError::kMountProgramFailed), "MountProgramFailed");
  EXPECT_EQ(ToString(MountError::kNeedPassword), "NeedPassword");
  EXPECT_EQ(ToString(MountError::kInProgress), "InProgress");
  EXPECT_EQ(ToString(MountError::kCancelled), "Cancelled");
  EXPECT_EQ(ToString(MountError::kBusy), "Busy");
  EXPECT_EQ(ToString(MountError::kInvalidDevicePath), "InvalidDevicePath");
  EXPECT_EQ(ToString(MountError::kUnknownFilesystem), "UnknownFilesystem");
  EXPECT_EQ(ToString(MountError::kUnsupportedFilesystem),
            "UnsupportedFilesystem");
  EXPECT_EQ(ToString(MountError::kInvalidArchive), "InvalidArchive");
  EXPECT_EQ(ToString(MountError(987654)), "MountError(987654)");
}

TEST(ErrorLogger, PartitionError) {
  EXPECT_EQ(ToString(PartitionError::kSuccess), "Success");
  EXPECT_EQ(ToString(PartitionError::kUnknownError), "UnknownError");
  EXPECT_EQ(ToString(PartitionError::kInternalError), "InternalError");
  EXPECT_EQ(ToString(PartitionError::kInvalidDevicePath), "InvalidDevicePath");
  EXPECT_EQ(ToString(PartitionError::kDeviceBeingPartitioned),
            "DeviceBeingPartitioned");
  EXPECT_EQ(ToString(PartitionError::kProgramNotFound), "ProgramNotFound");
  EXPECT_EQ(ToString(PartitionError::kProgramFailed), "ProgramFailed");
  EXPECT_EQ(ToString(PartitionError::kDeviceNotAllowed), "DeviceNotAllowed");
  EXPECT_EQ(ToString(PartitionError(987654)), "PartitionError(987654)");
}

TEST(ErrorLogger, RenameError) {
  EXPECT_EQ(ToString(RenameError::kSuccess), "Success");
  EXPECT_EQ(ToString(RenameError::kUnknownError), "UnknownError");
  EXPECT_EQ(ToString(RenameError::kInternalError), "InternalError");
  EXPECT_EQ(ToString(RenameError::kInvalidDevicePath), "InvalidDevicePath");
  EXPECT_EQ(ToString(RenameError::kDeviceBeingRenamed), "DeviceBeingRenamed");
  EXPECT_EQ(ToString(RenameError::kUnsupportedFilesystem),
            "UnsupportedFilesystem");
  EXPECT_EQ(ToString(RenameError::kRenameProgramNotFound),
            "RenameProgramNotFound");
  EXPECT_EQ(ToString(RenameError::kRenameProgramFailed), "RenameProgramFailed");
  EXPECT_EQ(ToString(RenameError::kDeviceNotAllowed), "DeviceNotAllowed");
  EXPECT_EQ(ToString(RenameError::kLongName), "LongName");
  EXPECT_EQ(ToString(RenameError::kInvalidCharacter), "InvalidCharacter");
  EXPECT_EQ(ToString(RenameError(987654)), "RenameError(987654)");
}

}  // namespace
}  // namespace cros_disks

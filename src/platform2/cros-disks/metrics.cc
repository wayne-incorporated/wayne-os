// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cros-disks/metrics.h"

#include <algorithm>

#include <base/containers/fixed_flat_map.h>
#include <base/logging.h>
#include <base/strings/strcat.h>
#include <base/strings/string_util.h>

namespace cros_disks {

Metrics::ArchiveType Metrics::GetArchiveType(base::StringPiece path) {
  struct Entry {
    base::StringPiece ext;
    ArchiveType type;
  };

  static const Entry entries[] = {
      {".tar.bz", kArchiveTarBzip2},   //
      {".tar.bz2", kArchiveTarBzip2},  //
      {".tar.gz", kArchiveTarGzip},    //
      {".tar.lz", kArchiveTarLz},      //
      {".tar.lzma", kArchiveTarLzma},  //
      {".tar.xz", kArchiveTarXz},      //
      {".tar.z", kArchiveTarZ},        //
      {".tar.zst", kArchiveTarZst},    //
      {".7z", kArchive7z},             //
      {".bz", kArchiveBzip2},          //
      {".bz2", kArchiveBzip2},         //
      {".crx", kArchiveCrx},           //
      {".gz", kArchiveGzip},           //
      {".iso", kArchiveIso},           //
      {".lz", kArchiveLz},             //
      {".lzma", kArchiveLzma},         //
      {".rar", kArchiveRar},           //
      {".tar", kArchiveTar},           //
      {".taz", kArchiveTarZ},          //
      {".tb2", kArchiveTarBzip2},      //
      {".tbz", kArchiveTarBzip2},      //
      {".tbz2", kArchiveTarBzip2},     //
      {".tgz", kArchiveTarGzip},       //
      {".tlz", kArchiveTarLzma},       //
      {".tlzma", kArchiveTarLzma},     //
      {".txz", kArchiveTarXz},         //
      {".tz", kArchiveTarZ},           //
      {".tz2", kArchiveTarBzip2},      //
      {".tzst", kArchiveTarZst},       //
      {".xz", kArchiveXz},             //
      {".z", kArchiveZ},               //
      {".zip", kArchiveZip},           //
      {".zst", kArchiveZst},           //
  };

  for (const auto [ext, type] : entries) {
    if (base::EndsWith(path, ext, base::CompareCase::INSENSITIVE_ASCII))
      return type;
  }

  return kArchiveUnknown;
}

// Strips the prefix "fuse." or "fuseblk." from a filesystem type.
static base::StringPiece StripPrefix(base::StringPiece fs_type) {
  for (const base::StringPiece prefix : {"fuse.", "fuseblk."}) {
    if (base::StartsWith(fs_type, prefix)) {
      fs_type.remove_prefix(prefix.size());
      break;
    }
  }

  return fs_type;
}

Metrics::FilesystemType Metrics::GetFilesystemType(
    const base::StringPiece fs_type) {
  static const auto map =
      base::MakeFixedFlatMap<base::StringPiece, FilesystemType>({
          {"", kFilesystemUnknown},         //
          {"exfat", kFilesystemExFAT},      //
          {"ext2", kFilesystemExt2},        //
          {"ext3", kFilesystemExt3},        //
          {"ext4", kFilesystemExt4},        //
          {"hfsplus", kFilesystemHFSPlus},  //
          {"iso9660", kFilesystemISO9660},  //
          {"ntfs", kFilesystemNTFS},        //
          {"udf", kFilesystemUDF},          //
          {"vfat", kFilesystemVFAT},        //
      });
  const auto it = map.find(StripPrefix(fs_type));
  return it != map.end() ? it->second : kFilesystemOther;
}

void Metrics::RecordArchiveType(const base::FilePath& path) {
  if (!metrics_library_.SendEnumToUMA("CrosDisks.ArchiveType",
                                      GetArchiveType(path.value()),
                                      kArchiveMaxValue))
    LOG(ERROR) << "Cannot send archive type to UMA";
}

void Metrics::RecordFilesystemType(const base::StringPiece fs_type) {
  if (!metrics_library_.SendEnumToUMA("CrosDisks.FilesystemType",
                                      GetFilesystemType(fs_type),
                                      kFilesystemMaxValue))
    LOG(ERROR) << "Cannot send filesystem type to UMA";
}

void Metrics::RecordMountError(base::StringPiece fs_type, const error_t error) {
  // Group all the FUSE-related filesystems under the name "fuse".
  const base::StringPiece prefix = "fuse";
  if (base::StartsWith(fs_type, prefix))
    fs_type = prefix;

  if (!metrics_library_.SendSparseToUMA(
          base::StrCat({"CrosDisks.MountError.", fs_type}), error))
    LOG(ERROR) << "Cannot send mount error to UMA";
}

void Metrics::RecordUnmountError(const base::StringPiece fs_type,
                                 const error_t error) {
  if (!metrics_library_.SendSparseToUMA(
          base::StrCat({"CrosDisks.UnmountError.", StripPrefix(fs_type)}),
          error))
    LOG(ERROR) << "Cannot send unmount error to UMA";
}

void Metrics::RecordDaemonError(const base::StringPiece program_name,
                                const int error) {
  std::string name(program_name);
  std::replace(name.begin(), name.end(), '.', '-');
  if (!metrics_library_.SendSparseToUMA(
          base::StrCat({"CrosDisks.PrematureTermination.", name}), error))
    LOG(ERROR) << "Cannot send FUSE daemon error to UMA";
}

void Metrics::RecordReadOnlyFileSystem(const base::StringPiece fs_type) {
  if (!metrics_library_.SendEnumToUMA("CrosDisks.ReadOnlyFileSystemAfterError",
                                      GetFilesystemType(fs_type),
                                      kFilesystemMaxValue))
    LOG(ERROR) << "Cannot send filesystem type to UMA";
}

void Metrics::RecordDeviceMediaType(DeviceType device_media_type) {
  if (!metrics_library_.SendEnumToUMA("CrosDisks.DeviceMediaType",
                                      device_media_type))
    LOG(ERROR) << "Cannot send device media type to UMA";
}

void Metrics::RecordFuseMounterErrorCode(const base::StringPiece mounter_name,
                                         const int error_code) {
  if (!metrics_library_.SendSparseToUMA(
          base::StrCat({"CrosDisks.Fuse.", mounter_name}), error_code))
    LOG(ERROR) << "Cannot send FUSE mounter error code to UMA";
}

}  // namespace cros_disks

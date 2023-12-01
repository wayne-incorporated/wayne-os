// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/container/obb-mounter/volume.h"

#include <endian.h>
#include <linux/msdos_fs.h>

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

#include <base/functional/callback.h>
#include <base/logging.h>

#include "arc/container/obb-mounter/util.h"

namespace fat {

namespace {

// Converts a msdos_dir_entry to a DirectoryEntry.
void MsdosDirEntryToDirectoryEntry(FatType fat_type,
                                   const msdos_dir_entry& in,
                                   Volume::DirectoryEntry* out) {
  out->is_directory = in.attr & ATTR_DIR;
  out->file_size = le32toh(in.size);
  out->start_cluster = le16toh(in.start);
  out->last_modification.date = le16toh(in.date);
  out->last_modification.time = le16toh(in.time);
  if (fat_type == FatType::FAT_32) {
    out->start_cluster += (le16toh(in.starthi) << 16);
  }
}

}  // namespace

base::Time Volume::Time::ToBaseTime() const {
  base::Time::Exploded exploded = {};
  exploded.year = 1980 + ((date >> 9) & 0x7f);
  exploded.month = (date >> 5) & 0x0f;
  exploded.day_of_month = date & 0x1f;
  exploded.hour = (time >> 11) & 0x1f;
  exploded.minute = (time >> 5) & 0x3f;
  exploded.second = (time & 0x1f) * 2;

  base::Time base_time;
  if (!base::Time::FromLocalExploded(exploded, &base_time)) {
    // In some cases, probably on DST switching timing, FromLocalExploded
    // may fail. In such a failure case, FromLocalExploded will return
    // base::Time(0) as its result, so this function still use it
    // with logging for the further investigation.
    LOG(ERROR) << "Time::FromLocalExploded failed with date: " << date
               << ", time: " << time;
  }
  return base_time;
}

Volume::FileReader::FileReader(Volume* volume,
                               int64_t start_cluster,
                               int64_t file_size)
    : volume_(volume),
      start_cluster_(start_cluster),
      file_size_(file_size),
      current_offset_(0),
      current_cluster_(start_cluster_) {}

Volume::FileReader::~FileReader() {}

int64_t Volume::FileReader::Read(char* buf, int64_t size, int64_t offset) {
  int64_t total = 0;
  const int64_t end_offset = std::min(offset + size, file_size_);
  while (offset + total < end_offset) {
    if (!Seek(offset + total)) {
      LOG(ERROR) << "Failed to seek.";
      return -1;
    }
    const int64_t cluster_size =
        volume_->bytes_per_sector_ * volume_->sectors_per_cluster_;
    const int64_t read_size =
        std::min(cluster_size - (current_offset_ % cluster_size),
                 end_offset - current_offset_);
    const int64_t position =
        volume_->GetSectorPosition(
            volume_->GetClusterStartSector(current_cluster_)) +
        current_offset_ % cluster_size;
    const int64_t read_bytes =
        volume_->image_file_.Read(position, buf + total, read_size);
    if (read_bytes == 0) {
      break;
    } else if (read_bytes < 0) {
      LOG(ERROR) << "Failed to read.";
      return -1;
    }
    total += read_bytes;
  }
  return total;
}

bool Volume::FileReader::Seek(int64_t offset) {
  if (offset < current_offset_) {
    // To move backward, we have to restart from the beginning.
    current_offset_ = 0;
    current_cluster_ = start_cluster_;
  }
  // Follow the cluster chain until we reach the target cluster.
  const int64_t cluster_size =
      volume_->bytes_per_sector_ * volume_->sectors_per_cluster_;
  const int64_t n_steps =
      offset / cluster_size - current_offset_ / cluster_size;
  for (int64_t i = 0; i < n_steps; ++i) {
    current_cluster_ = ReadFileAllocationTable(
        &volume_->image_file_, volume_->fat_type_,
        volume_->GetSectorPosition(volume_->fat_start_sector_),
        current_cluster_);
    if (current_cluster_ == kInvalidValue) {
      LOG(ERROR) << "Failed to track the cluster chain.";
      current_offset_ = 0;
      current_cluster_ = start_cluster_;
      return false;
    }
  }
  current_offset_ = offset;
  return true;
}

Volume::Volume() {}

Volume::~Volume() {}

bool Volume::Initialize(base::File image_file) {
  image_file_ = std::move(image_file);

  // The first sector is the boot sector.
  fat_boot_sector boot_sector = {};
  if (image_file_.Read(0, reinterpret_cast<char*>(&boot_sector),
                       sizeof(boot_sector)) != sizeof(boot_sector)) {
    LOG(ERROR) << "Failed to read the boot sector.";
    return false;
  }
  bytes_per_sector_ = GetUnalignedLE16(boot_sector.sector_size);
  if (bytes_per_sector_ <= 0 || bytes_per_sector_ % sizeof(msdos_dir_entry)) {
    LOG(ERROR) << "Invalid sector size " << bytes_per_sector_;
    return false;
  }
  sectors_per_cluster_ = boot_sector.sec_per_clus;
  if (sectors_per_cluster_ <= 0) {
    LOG(ERROR) << "Invalid cluster size " << sectors_per_cluster_;
    return false;
  }
  // A volume can contain multiple file allocation tables (FATs) for robustness.
  int n_fats = boot_sector.fats;
  if (n_fats <= 0) {
    LOG(ERROR) << "Invalid # of FATs " << n_fats;
    return false;
  }
  int64_t sectors_per_fat = le16toh(boot_sector.fat_length);
  bool is_fat32 = false;
  if (sectors_per_fat == 0) {  // This volume should be FAT32.
    is_fat32 = true;
    sectors_per_fat = le32toh(boot_sector.fat32.length);
  }
  if (sectors_per_fat <= 0) {
    LOG(ERROR) << "Invalid FAT size " << sectors_per_fat;
    return false;
  }
  int64_t total_sectors = GetUnalignedLE16(boot_sector.sectors);
  if (total_sectors == 0) {
    total_sectors = le32toh(boot_sector.total_sect);
  }
  // File allocation tables (FATs) after the reserved sectors (including the
  // boot sector).
  fat_start_sector_ = le16toh(boot_sector.reserved);
  if (fat_start_sector_ < 1) {
    LOG(ERROR) << "Invalid FAT start sector " << fat_start_sector_;
    return false;
  }
  if (is_fat32) {
    // FAT32 explicitly specifies the position of the root dir.
    data_start_sector_ = fat_start_sector_ + n_fats * sectors_per_fat;
    root_dir_start_sector_ =
        GetClusterStartSector(le32toh(boot_sector.fat32.root_cluster));
    if (root_dir_start_sector_ < data_start_sector_ ||
        total_sectors <= root_dir_start_sector_) {
      LOG(ERROR) << "Invalid root dir start sector " << root_dir_start_sector_;
      return false;
    }
  } else {
    // FAT12/16 puts the root dir between the FATs and the data region.
    root_dir_start_sector_ = fat_start_sector_ + n_fats * sectors_per_fat;
    int n_root_dir_entries = GetUnalignedLE16(boot_sector.dir_entries);
    int size = sizeof(msdos_dir_entry) * n_root_dir_entries;
    if (size % bytes_per_sector_) {
      LOG(ERROR) << "Invalid # of root directory entries.";
      return false;
    }
    data_start_sector_ = root_dir_start_sector_ + size / bytes_per_sector_;
  }
  // Data region after the FATs and the FAT12/16 root dir.
  int64_t data_sectors = total_sectors - data_start_sector_;
  if (data_sectors < 0) {
    LOG(ERROR) << "Invalid # of data sectors " << data_sectors;
    return false;
  }
  if (is_fat32) {
    fat_type_ = FatType::FAT_32;
  } else {
    // Use the # of cluster to determine the FAT type.
    int64_t n_clusters = data_sectors / sectors_per_cluster_;
    if (n_clusters > MAX_FAT12) {
      fat_type_ = FatType::FAT_16;
    } else {
      fat_type_ = FatType::FAT_12;
    }
  }
  return true;
}

bool Volume::ReadDirectory(int64_t start_sector,
                           const ReadDirectoryCallback& callback) {
  std::vector<char> dir_entry_buf(bytes_per_sector_);
  std::u16string long_name_buf;
  for (int64_t pos = 0, sector = start_sector;
       pos < FAT_MAX_DIR_SIZE && sector != kInvalidValue;
       pos += bytes_per_sector_, sector = GetNextSector(sector)) {
    // Read the sector.
    if (image_file_.Read(GetSectorPosition(sector), dir_entry_buf.data(),
                         dir_entry_buf.size()) !=
        static_cast<int>(dir_entry_buf.size())) {
      LOG(ERROR) << "Failed to read sector " << sector;
      return false;
    }
    // Visit each directory entry.
    for (size_t offset = 0; offset < dir_entry_buf.size();
         offset += sizeof(msdos_dir_entry)) {
      const auto& dir_entry = *reinterpret_cast<const msdos_dir_entry*>(
          dir_entry_buf.data() + offset);
      switch (dir_entry.name[0]) {
        case 0:  // Terminate.
          return true;
        case DELETED_FLAG:  // This entry is unused.
          continue;
      }
      if (dir_entry.attr == ATTR_EXT) {
        // This is a long file name slot for the coming directory entry.
        AppendLongFileNameCharactersReversed(
            reinterpret_cast<const msdos_dir_slot&>(dir_entry), &long_name_buf);
        continue;
      }
      // This is a directory entry.
      // long_name_buf holds characters in the reversed order.
      std::reverse(long_name_buf.begin(), long_name_buf.end());
      // Find 0 and truncate at it if found.
      auto it = std::find(long_name_buf.begin(), long_name_buf.end(), 0);
      if (it != long_name_buf.end()) {
        long_name_buf.resize(it - long_name_buf.begin());
      }
      if (long_name_buf.empty()) {
        // Ignoring entries without long names.
        // TODO(hashimoto): Use short name if long name is not available?

        // A non-root directory contains "." and ".." without long names,
        // but we ignore them intentionally.
        static const char kDot[MSDOS_NAME + 1] = ".          ";
        static const char kDotDot[MSDOS_NAME + 1] = "..         ";
        const bool expected = memcmp(kDot, dir_entry.name, MSDOS_NAME) == 0 ||
                              memcmp(kDotDot, dir_entry.name, MSDOS_NAME) == 0;
        // Log only when ignoring unexpected entries.
        LOG_IF(WARNING, !expected)
            << "Ignoring: "
            << std::string(dir_entry.name, dir_entry.name + MSDOS_NAME);
        continue;
      }
      DirectoryEntry entry;
      MsdosDirEntryToDirectoryEntry(fat_type_, dir_entry, &entry);
      if (!callback.Run(
              base::StringPiece16(long_name_buf.data(), long_name_buf.size()),
              entry)) {
        return true;
      }
    }
  }
  return true;
}

int64_t Volume::GetNextSector(int64_t sector) {
  if (sector >= data_start_sector_) {
    // We're in the data region. Follow the cluster chain.
    const int64_t cluster = GetCluster(sector);
    const int64_t cluster_end_sector =
        GetClusterStartSector(cluster) + sectors_per_cluster_;
    if (sector + 1 >= cluster_end_sector) {
      // Move to the next cluster.
      const int64_t next_cluster = ReadFileAllocationTable(
          &image_file_, fat_type_, GetSectorPosition(fat_start_sector_),
          cluster);
      if (next_cluster == kInvalidValue) {
        return kInvalidValue;
      }
      return GetClusterStartSector(next_cluster);
    }
    // Move ahead in the current cluster.
    return sector + 1;
  }
  if (sector >= root_dir_start_sector_) {
    // We're in the FAT16 root directory region.
    if (sector + 1 >= data_start_sector_) {  // Reached the end.
      return kInvalidValue;
    }
    return sector + 1;
  }
  // Invalid argument.
  return kInvalidValue;
}

}  // namespace fat

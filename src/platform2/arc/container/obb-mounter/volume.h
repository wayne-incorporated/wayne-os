// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_CONTAINER_OBB_MOUNTER_VOLUME_H_
#define ARC_CONTAINER_OBB_MOUNTER_VOLUME_H_

#include <linux/msdos_fs.h>

#include <base/files/file.h>
#include <base/functional/callback_forward.h>
#include <base/strings/string_piece.h>
#include <base/time/time.h>

namespace fat {

const int64_t kInvalidValue = -1;

enum class FatType {
  FAT_12,
  FAT_16,
  FAT_32,
};

// Volume is a class to access a FAT volume.
//
// Structure of a FAT volume:
// [ Boot sector + Reserved sectors ]
// [ File allocation tables (FATs)  ]
// [ Root directory (FAT12/16 only, FAT32 root dir is in the data region) ]
// [ Data region ]
class Volume {
 public:
  // Time in FAT's format.
  struct Time {
    uint16_t time = 0;
    uint16_t date = 0;

    // Converts the values to base::Time.
    base::Time ToBaseTime() const;
  };

  // Metadata of a file or a directory stored under a directory.
  struct DirectoryEntry {
    bool is_directory = false;
    int64_t file_size = 0;
    int64_t start_cluster = 0;  // The first cluster of the contents.
    Time last_modification;
  };

  using ReadDirectoryCallback = base::RepeatingCallback<bool(
      const base::StringPiece16& name, const DirectoryEntry& entry)>;

  // Object to read the contents of a file.
  class FileReader {
   public:
    FileReader(Volume* volume, int64_t start_cluster, int64_t file_size);
    FileReader(const FileReader&) = delete;
    FileReader& operator=(const FileReader&) = delete;

    ~FileReader();

    // Reads the given number of bytes from the given offset and returns the
    // number of bytes read, or -1 on error.
    int64_t Read(char* buf, int64_t size, int64_t offset);

   private:
    // Updates current_offset_ and current_cluster_ with the given offset value.
    bool Seek(int64_t offset);

    Volume* volume_;
    const int64_t start_cluster_;  // Start cluster of the file being read.
    const int64_t file_size_;      // Size of the file being read.
    int64_t current_offset_;       // Current offset within the file being read.
    int64_t current_cluster_;      // Current cluster in the image file.
  };

  Volume();
  Volume(const Volume&) = delete;
  Volume& operator=(const Volume&) = delete;

  ~Volume();

  // Reads the boot sector from the image and initializes member variables.
  bool Initialize(base::File image_file);

  // Returns the sector where the root directory starts.
  int64_t root_dir_start_sector() const { return root_dir_start_sector_; }

  // Returns the given cluster's first sector.
  int64_t GetClusterStartSector(int64_t cluster) const {
    if (cluster < FAT_START_ENT)
      return kInvalidValue;
    return data_start_sector_ +
           (cluster - FAT_START_ENT) * sectors_per_cluster_;
  }

  // Reads the directory from the given sector and calls the callback with each
  // file/directory found under it. When the callback returns false, returns
  // true immediately without processing the remaining entries.
  bool ReadDirectory(int64_t start_sector,
                     const ReadDirectoryCallback& callback);

 private:
  // Returns the position of the give sector in the image file.
  int64_t GetSectorPosition(int64_t sector) const {
    return sector * bytes_per_sector_;
  }

  // Returns the cluster to which the given sector belongs.
  int64_t GetCluster(int64_t sector) const {
    if (sector < data_start_sector_) {
      return kInvalidValue;
    }
    return (sector - data_start_sector_) / sectors_per_cluster_ + FAT_START_ENT;
  }

  // Returns the next sector to read after the given sector. If there is an
  // error, or reached EOF, returns kInvalidValue.
  int64_t GetNextSector(int64_t sector);

  base::File image_file_;
  int bytes_per_sector_ = 0;     // Size of a sector. Usually this is 512.
  int sectors_per_cluster_ = 0;  // Size of a cluster.
  // The sector from which the FAT (file allocation table) starts.
  int64_t fat_start_sector_ = 0;
  // The sector from which the root dir starts.
  int64_t root_dir_start_sector_ = 0;
  // The sector from which the data region starts.
  int64_t data_start_sector_ = 0;
  FatType fat_type_ = FatType::FAT_12;  // The type of this FAT volume.
};

}  // namespace fat

#endif  // ARC_CONTAINER_OBB_MOUNTER_VOLUME_H_

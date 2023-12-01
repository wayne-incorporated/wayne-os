// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef UREADAHEAD_DIFF_UREADAHEAD_DIFF_H_
#define UREADAHEAD_DIFF_UREADAHEAD_DIFF_H_

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <memory>
#include <string>
#include <vector>

namespace ureadahead_diff {

// Constants and definitions from ureadhead/src/pack.*
#define PACK_PATH_MAX 255

enum PackFlags {
  PACK_ROTATIONAL = 0x01,
};

// Keep it as declared in pack.h. Default alignment must be used.
struct PackPath {
  int group;
  ino_t ino;
  char path[PACK_PATH_MAX + 1];

  bool operator==(const PackPath& other) const;
  bool operator!=(const PackPath& other) const;
};

// Keep it as declared in pack.h. Default alignment must be used.
struct PackBlock {
  size_t pathidx;
  off_t offset;
  off_t length;
  off_t physical;

  bool operator==(const PackBlock& other) const;
  bool operator!=(const PackBlock& other) const;
};

// Represents individual file in ureadahead pack file.
class FileEntry {
 public:
  explicit FileEntry(const PackPath& pack_path);
  ~FileEntry();

  FileEntry(const FileEntry&) = delete;
  FileEntry& operator=(const FileEntry&) = delete;

  // Builds |FileEntry| based on provided read requests. Each request is
  // std::pair of offset and length of the each read operation.
  void BuildFromReadRequests(const std::vector<PackBlock>& read_requests);

  // Returns read request that is calculated from |read_map_|. |pathidx|
  // specifies the global index for this file.
  std::vector<PackBlock> GetReadRequests(size_t pathidx) const;

  // Returns true if file does not have any read block.
  bool IsEmpty() const;

  // Calculates difference of two files. It puts the common part into |common|
  // and leaves difference in |file1| and |file2] correspondingly. Note, that
  // sizes of read requests might be different and |common| will have the size
  // of minimum of read requests sizes of |file1| and |file2|.
  static void CalculateDifference(FileEntry* file1,
                                  FileEntry* file2,
                                  FileEntry* common);

  const PackPath& pack_path() const { return pack_path_; }

 private:
  using ReadMap = std::vector<bool>;

  const PackPath pack_path_;

  // Each bit in the collections corresponds one page of file.
  ReadMap read_map_;
};

// Represents ureadahead pack.
class Pack {
 public:
  // Source pack specifies the source pack and output specifies pack that
  // contains difference.
  Pack();
  ~Pack();

  Pack(const Pack&) = delete;
  Pack& operator=(const Pack&) = delete;

  // Returns the number of files in the pack.
  size_t GetFileCount() const;

  // Returns file by index.
  FileEntry* GetFile(size_t index);

  // Adds file to the pack.
  void AddFile(std::unique_ptr<FileEntry> file);

  // Finds the file in this pack that corresponds to the provided |other_file|
  // which may belong to the different pack. Returns nullptr if match is not
  // found.
  FileEntry* FindFile(FileEntry* other_file);

  // Reads ureadahead pack from |path|.
  bool Read(const std::string& path);

  // Writes pack to the |path|.
  bool Write(const std::string& path) const;

  // Removes all files that do not have read operations.
  void TrimEmptyFiles();

  // Calculates difference of two packs. It puts the common part into |common|
  // and leaves difference in |pack1| and |pack2] correspondingly.
  static void CalculateDifference(Pack* pack1, Pack* pack2, Pack* common);

 private:
  bool Read(int fd);
  bool Write(int fd) const;

  // Mapped from ureadahead's struct pack_file.
  dev_t dev_ = 0;

  std::vector<std::unique_ptr<FileEntry>> files_;
};

}  // namespace ureadahead_diff

#endif  // UREADAHEAD_DIFF_UREADAHEAD_DIFF_H_

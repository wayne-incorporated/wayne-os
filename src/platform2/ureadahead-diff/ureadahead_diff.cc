// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ureadahead-diff/ureadahead_diff.h"

#include <fcntl.h>

#include <algorithm>
#include <utility>

#include <base/files/file_util.h>
#include <base/files/scoped_file.h>

namespace ureadahead_diff {

namespace {

bool ReadBuffer(int fd, void* data, size_t size) {
  return base::ReadFromFD(fd, reinterpret_cast<char*>(data), size);
}

bool WriteBuffer(int fd, const void* data, size_t size) {
  return base::WriteFileDescriptor(fd, reinterpret_cast<const char*>(data),
                                   size);
}

}  // namespace

bool PackPath::operator==(const PackPath& other) const {
  return group == other.group && ino == other.ino && !strcmp(path, other.path);
}
bool PackPath::operator!=(const PackPath& other) const {
  return !(*this == other);
}

bool PackBlock::operator==(const PackBlock& other) const {
  return pathidx == other.pathidx && offset == other.offset &&
         length == other.length && physical == other.physical;
}

bool PackBlock::operator!=(const PackBlock& other) const {
  return !(*this == other);
}

FileEntry::FileEntry(const PackPath& pack_path) : pack_path_(pack_path) {}

FileEntry::~FileEntry() = default;

void FileEntry::BuildFromReadRequests(
    const std::vector<PackBlock>& read_requests) {
  const size_t page_size = sysconf(_SC_PAGESIZE);

  size_t max_offset = 0;
  for (const auto& request : read_requests) {
    max_offset =
        std::max(max_offset, (request.offset + request.length) / page_size);
  }

  // Clear just in case we have something pending.
  read_map_.clear();
  read_map_.resize(max_offset, false);
  for (const auto& request : read_requests) {
    const off_t offset = request.offset / page_size;
    for (size_t i = 0; i < request.length / page_size; ++i)
      read_map_[i + offset] = true;
  }
}

std::vector<PackBlock> FileEntry::GetReadRequests(size_t pathidx) const {
  const size_t page_size = sysconf(_SC_PAGESIZE);

  size_t index = 0;
  std::vector<PackBlock> pack_blocks;
  PackBlock pack_block;
  pack_block.physical = -1;
  pack_block.pathidx = pathidx;
  while (true) {
    // Skip next empty pages.
    while (index < read_map_.size() && !read_map_[index])
      ++index;
    if (index >= read_map_.size())
      break;
    // Find continues range.
    pack_block.offset = page_size * index;
    ++index;
    while (index < read_map_.size() && read_map_[index])
      ++index;
    pack_block.length = (page_size * index - pack_block.offset);
    pack_blocks.emplace_back(pack_block);
  }
  return pack_blocks;
}

bool FileEntry::IsEmpty() const {
  for (bool value : read_map_) {
    if (value)
      return false;
  }
  return true;
}

// static
void FileEntry::CalculateDifference(FileEntry* file1,
                                    FileEntry* file2,
                                    FileEntry* common) {
  const size_t size =
      std::min(file1->read_map_.size(), file2->read_map_.size());
  // Clear just in case we have something pending.
  common->read_map_.clear();
  common->read_map_.resize(size);
  for (size_t i = 0; i < size; ++i) {
    if (file1->read_map_[i] && file2->read_map_[i]) {
      file1->read_map_[i] = false;
      file2->read_map_[i] = false;
      common->read_map_[i] = true;
    }
  }
}

Pack::Pack() = default;
Pack::~Pack() = default;

size_t Pack::GetFileCount() const {
  return files_.size();
}

FileEntry* Pack::GetFile(size_t index) {
  return files_[index].get();
}

void Pack::AddFile(std::unique_ptr<FileEntry> file) {
  files_.emplace_back(std::move(file));
}

FileEntry* Pack::FindFile(FileEntry* other_file) {
  for (auto& file : files_) {
    if (file->pack_path() == other_file->pack_path())
      return file.get();
  }
  return nullptr;
}

bool Pack::Read(const std::string& path) {
  base::ScopedFD fd(open(path.c_str(), O_RDONLY | O_CLOEXEC));
  if (!fd.is_valid())
    return false;
  return Read(fd.get());
}

bool Pack::Write(const std::string& path) const {
  base::ScopedFD fd(
      open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644));
  if (!fd.is_valid())
    return false;
  return Write(fd.get());
}

void Pack::TrimEmptyFiles() {
  auto it = files_.begin();
  while (it != files_.end()) {
    if ((*it)->IsEmpty())
      it = files_.erase(it);
    else
      ++it;
  }
}

// static
void Pack::CalculateDifference(Pack* pack1, Pack* pack2, Pack* common) {
  for (size_t i = 0; i < pack1->GetFileCount(); ++i) {
    FileEntry* const file1 = pack1->GetFile(i);
    FileEntry* const file2 = pack2->FindFile(file1);
    if (!file2)
      continue;
    std::unique_ptr<FileEntry> common_file =
        std::make_unique<FileEntry>(file1->pack_path());
    FileEntry::CalculateDifference(file1, file2, common_file.get());
    common->AddFile(std::move(common_file));
  }

  pack1->TrimEmptyFiles();
  pack2->TrimEmptyFiles();
  common->TrimEmptyFiles();
}

bool Pack::Read(int fd) {
  files_.clear();

  char header[8];
  if (!ReadBuffer(fd, header, sizeof(header)))
    return false;

  if (header[0] != 'u' || header[1] != 'r' || header[2] != 'a' ||
      header[3] != 2 ||                 /* version */
      (header[4] & ~PACK_ROTATIONAL) || /* flags */
      // Last 3 are reserved and must be 0.
      header[5] || header[6] || header[7]) {
    return false;
  }

  // Rotational ureadahead pack is not used and not supported.
  if (header[4] & PACK_ROTATIONAL)
    return false;

  time_t created;
  size_t num_groups;
  if (!ReadBuffer(fd, &dev_, sizeof(dev_)) ||
      !ReadBuffer(fd, &created, sizeof(created)) ||
      !ReadBuffer(fd, &num_groups, sizeof(num_groups))) {
    return false;
  }

  // ureadahead pack with groups is not used and not supported.
  if (num_groups)
    return false;

  size_t num_paths;
  if (!ReadBuffer(fd, &num_paths, sizeof(num_paths)))
    return false;

  for (size_t i = 0; i < num_paths; ++i) {
    PackPath pack_path;
    if (!ReadBuffer(fd, &pack_path, sizeof(pack_path)) ||
        pack_path.group != -1) {
      return false;
    }
    // Validate 0 - terminated.
    if (strnlen(pack_path.path, PACK_PATH_MAX) == PACK_PATH_MAX)
      return false;
    files_.emplace_back(std::make_unique<FileEntry>(pack_path));
  }

  size_t num_blocks;
  if (!ReadBuffer(fd, &num_blocks, sizeof(num_blocks)))
    return false;

  std::vector<std::vector<PackBlock>> read_requests_per_file_index(
      files_.size());
  for (size_t i = 0; i < num_blocks; ++i) {
    PackBlock pack_block;
    if (!ReadBuffer(fd, &pack_block, sizeof(pack_block)) ||
        pack_block.pathidx >= read_requests_per_file_index.size() ||
        // pack_block.physical must be -1 for SSD
        pack_block.physical != -1) {
      return false;
    }
    read_requests_per_file_index[pack_block.pathidx].emplace_back(pack_block);
  }
  // Flash read requests for the each file.
  for (size_t i = 0; i < read_requests_per_file_index.size(); ++i)
    files_[i]->BuildFromReadRequests(read_requests_per_file_index[i]);

  // Check if anything else is left for sanity.
  char temp;
  if (ReadBuffer(fd, &temp, sizeof(temp)))
    return false;

  return true;
}

bool Pack::Write(int fd) const {
  char header[8] = {'u',           'r', 'a', 2 /* version */,
                    0 /* flags */, 0,   0,   0 /* reserved */};

  time_t created;
  time(&created);
  const size_t num_groups = 0;
  if (!WriteBuffer(fd, header, sizeof(header)) ||
      !WriteBuffer(fd, &dev_, sizeof(dev_)) ||
      !WriteBuffer(fd, &created, sizeof(created)) ||
      !WriteBuffer(fd, &num_groups, sizeof(num_groups))) {
    return false;
  }

  const size_t num_paths = files_.size();
  if (!WriteBuffer(fd, &num_paths, sizeof(num_paths)))
    return false;

  for (size_t i = 0; i < num_paths; ++i) {
    if (!WriteBuffer(fd, &files_[i]->pack_path(), sizeof(PackPath)))
      return false;
  }

  std::vector<PackBlock> pack_blocks;
  for (size_t i = 0; i < num_paths; ++i) {
    const std::vector<PackBlock> file_pack_blocks =
        files_[i]->GetReadRequests(i);
    pack_blocks.insert(pack_blocks.end(), file_pack_blocks.begin(),
                       file_pack_blocks.end());
  }

  // Flash blocks for the whole pack.
  const size_t num_blocks = pack_blocks.size();
  if (!WriteBuffer(fd, &num_blocks, sizeof(num_blocks)))
    return false;

  for (size_t i = 0; i < num_blocks; ++i) {
    if (!WriteBuffer(fd, &pack_blocks[i], sizeof(PackBlock)))
      return false;
  }

  return true;
}

}  // namespace ureadahead_diff

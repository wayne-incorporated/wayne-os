// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "croslog/file_map_reader.h"

#include <algorithm>
#include <unistd.h>

#include "croslog/log_line_reader.h"

#include <base/check.h>
#include <base/check_op.h>
#include <base/logging.h>

namespace croslog {

namespace {

// Size of chunk: 4 MB. This must be multiple of the page size.
// This is not constant for testing.
static uint64_t g_chunk_size_in_bytes = 4 * 1024 * 1024;
// Number of chunks to be allocated: 128 MB.
// This is not constant for testing.
static uint64_t g_allocate_chunk_size = 32;
// A dummy empty buffer. Used as an empty buffer.
static const uint8_t kEmptyBuffer[] = {};

std::pair<uint64_t, uint64_t> CalculateAppropriateBufferRange(
    uint64_t request_pos, uint64_t request_length, uint64_t file_size) {
  // Ensure the request parameters are valid. The caller must take care of it.
  DCHECK_LE(request_pos + request_length, file_size);

  // Assumption of this logic: the requested length is small enough to avoid
  // request size from overruning of the allocated buffer range.
  // The current limit is |g_chunk_size_in_bytes|, and this value is the limit
  // in the case of g_allocate_chunk_size == 2. This can be larger when
  // |g_allocate_chunk_size| > 2 (but currently it is not supported).
  DCHECK_LE(request_length, g_chunk_size_in_bytes);
  // Assumption of this logic: |g_allocate_chunk_size| must be larger than 2 to
  // allocate a buffer across two chunks.
  DCHECK_LE(2u, g_allocate_chunk_size);
  // Assumption of this logic: |g_allocate_chunk_size| must be multiple of the
  // page size, otherwise mmap fails.
  DCHECK_EQ(0, g_chunk_size_in_bytes % sysconf(_SC_PAGE_SIZE));

  // Calculate the aligned range of buffer with margins after and before.
  // Each margin is about ((g_allocate_chunk_size / 2) * g_chunk_size_in_bytes)
  // MB.
  uint64_t buffer_length = g_allocate_chunk_size * g_chunk_size_in_bytes;
  uint64_t buffer_start_pos =
      request_pos - (request_pos % g_chunk_size_in_bytes);

  // Add a margin before the requested range.
  buffer_start_pos -=
      std::min(buffer_start_pos,
               (g_allocate_chunk_size / 2 - 1) * g_chunk_size_in_bytes);

  // Adjust the length not to overrun the file size.
  if ((buffer_start_pos + buffer_length) > file_size)
    buffer_length = file_size - buffer_start_pos;

  // Ensure the calculated range is valid.
  DCHECK_LE(buffer_start_pos, request_pos);
  DCHECK_LE(request_pos + request_length, buffer_start_pos + buffer_length);

  return std::make_pair(buffer_start_pos, buffer_length);
}

}  // anonymous namespace

// ============================================================================
// FileMapReaderDelegate declaration:

// Delegate to implement the logic to map the file or something compatible.
class FileMapReaderDelegate {
 public:
  virtual ~FileMapReaderDelegate() = default;

  // Returns the current file size on the file system.
  virtual int64_t GetCurrentFileSize() = 0;

  // Do mmap and returns the allocated memory. Allocated memory is bigger than
  // the requested size with mergins and includes the requested range.
  // - On error, nullptr is returned
  // - On success, an allocated memory is owned by the delegate
  // An allocated memory is released on next DoMap call or dtor.
  virtual std::pair<const uint8_t*, uint64_t> DoMap(int64_t request_pos,
                                                    int64_t request_length) = 0;
};

// ============================================================================
// FileMapReaderDelegateImpl implementation:

class FileMapReaderDelegateImpl : public FileMapReaderDelegate {
 public:
  explicit FileMapReaderDelegateImpl(base::File file)
      : file_(std::move(file)) {}
  FileMapReaderDelegateImpl(const FileMapReaderDelegateImpl&) = delete;
  FileMapReaderDelegateImpl& operator=(const FileMapReaderDelegateImpl&) =
      delete;

  ~FileMapReaderDelegateImpl() override = default;

  int64_t GetCurrentFileSize() override { return file_.GetLength(); }

  std::pair<const uint8_t*, uint64_t> DoMap(int64_t request_pos,
                                            int64_t request_length) override {
    DCHECK_GE(request_pos, 0);
    DCHECK_GE(request_length, 0);

    if (request_length == 0) {
      // Returning an empty buffer without (re)mmapping, since mmap of an empty
      // file fails.
      mmap_.reset();
      return std::make_pair(static_cast<const uint8_t*>(kEmptyBuffer), 0);
    }

    // Checks if the given range is invalid. It must be verified in the caller.
    // Or probably a TOCTOU race has been happened until that check. In this
    // case, the mmap bellow will fail.
    DCHECK_LE(request_pos + request_length, file_.GetLength());

    // Maps the file.
    base::MemoryMappedFile::Region mmap_region;
    mmap_region.offset = request_pos;
    mmap_region.size = request_length;

    mmap_ = std::make_unique<base::MemoryMappedFile>();
    bool mmap_result = mmap_->Initialize(file_.Duplicate(), mmap_region);
    if (!mmap_result) {
      LOG(ERROR) << "Doing mmap failed.";
      // Returning an empty buffer without (re)mmapping, since mmap of an empty
      // file fails.
      mmap_.reset();
      return std::make_pair(nullptr, 0);
    }

    return std::make_pair(mmap_->data(), mmap_->length());
  }

 private:
  base::File file_;
  std::unique_ptr<base::MemoryMappedFile> mmap_;
};

// ============================================================================
// FileMapReaderDelegateImplMemoryReader implementation:

// This class maps and reads the logs on memory buffer. Used only in tests.
class FileMapReaderDelegateImplMemoryReader : public FileMapReaderDelegate {
 public:
  FileMapReaderDelegateImplMemoryReader(const uint8_t* buffer, uint64_t length)
      : buffer_(buffer), buffer_length_(length) {}

  int64_t GetCurrentFileSize() override { return buffer_length_; }
  FileMapReaderDelegateImplMemoryReader(
      const FileMapReaderDelegateImplMemoryReader&) = delete;
  FileMapReaderDelegateImplMemoryReader& operator=(
      const FileMapReaderDelegateImplMemoryReader&) = delete;

  std::pair<const uint8_t*, uint64_t> DoMap(int64_t request_pos,
                                            int64_t request_length) override {
    DCHECK_GE(request_pos, 0);
    DCHECK_GE(request_length, 0);

    int64_t buffer_remaining_length =
        std::max(buffer_length_ - request_pos, INT64_C(0));
    return std::make_pair(buffer_ + request_pos,
                          std::min(request_length, buffer_remaining_length));
  }

 private:
  const uint8_t* const buffer_ = nullptr;
  const int64_t buffer_length_ = 0;
};

// ============================================================================
// FileMapReader::MappedBuffer implementation:

FileMapReader::MappedBuffer::MappedBuffer(const uint8_t* buffer,
                                          uint64_t buffer_start,
                                          uint64_t buffer_length)
    : buffer_(buffer),
      buffer_start_(buffer_start),
      buffer_length_(buffer_length) {}

FileMapReader::MappedBuffer::~MappedBuffer() = default;

std::pair<const uint8_t*, uint64_t> FileMapReader::MappedBuffer::GetBuffer(
    uint64_t start_pos, uint64_t length) const {
  DCHECK(valid());
  DCHECK_LE(buffer_start_, start_pos);
  DCHECK_LE(start_pos + length, buffer_start_ + buffer_length_);

  const uint8_t* buffer = buffer_ + (start_pos - buffer_start_);
  const uint64_t buffer_remaining_length =
      buffer_length_ - (start_pos - buffer_start_);
  return std::make_pair(buffer, std::min(length, buffer_remaining_length));
}

// ============================================================================
// FileMapReader implementation:

// static
std::unique_ptr<FileMapReader> FileMapReader::CreateReader(base::File file) {
  return std::make_unique<FileMapReader>(
      std::make_unique<FileMapReaderDelegateImpl>(std::move(file)));
}

// static
uint64_t FileMapReader::GetChunkSizeInBytes() {
  return g_chunk_size_in_bytes;
}

// static
std::unique_ptr<FileMapReader>
FileMapReader::CreateFileMapReaderDelegateImplMemoryReaderForTest(
    const uint8_t* buffer, uint64_t length) {
  return std::make_unique<FileMapReader>(
      std::make_unique<FileMapReaderDelegateImplMemoryReader>(buffer, length));
}

// static
void FileMapReader::SetBlockSizesForTest(uint64_t chunk_size_in_bytes,
                                         uint32_t allocate_chunks) {
  CHECK_EQ(0, chunk_size_in_bytes % sysconf(_SC_PAGE_SIZE));
  CHECK_LE(2u, allocate_chunks);

  g_chunk_size_in_bytes = chunk_size_in_bytes;
  g_allocate_chunk_size = allocate_chunks;
}

FileMapReader::FileMapReader(std::unique_ptr<FileMapReaderDelegate> delegate)
    : delegate_(std::move(delegate)),
      file_size_(delegate_->GetCurrentFileSize()) {
  CHECK_GE(file_size_, 0);
}

FileMapReader::~FileMapReader() = default;

void FileMapReader::ApplyFileSizeExpansion() {
  const int64_t current_file_size = delegate_->GetCurrentFileSize();
  CHECK_GE(current_file_size, 0);
  if (current_file_size == file_size_)
    return;

  // We assume the log files never shrink.
  CHECK_LT(file_size_, current_file_size);

  file_size_ = current_file_size;
}

std::unique_ptr<FileMapReader::MappedBuffer> FileMapReader::MapBuffer(
    uint64_t request_pos, uint64_t request_length) {
  DCHECK_LE(request_pos + request_length, file_size_);

  // Ensure that the previous mapped buffer has already been freed.
  DCHECK(!instantiated_mapped_buffer_);

  // Reuse the previous mapped buffer if the request range is contained by the
  // previous mapped range.
  if ((buffer_ != nullptr) && (buffer_start_ <= request_pos) &&
      ((request_pos + request_length) <= (buffer_start_ + buffer_length_))) {
    return CreateMappedBuffer();
  }

  // Just check if the log files never shrink just in case. But we don't update
  // the file size here even if it's updated, for logic simplicity.
  CHECK_LE(file_size_, delegate_->GetCurrentFileSize());

  // Calculate the aligned range with enough margin.
  const std::pair<uint64_t, uint64_t> region =
      CalculateAppropriateBufferRange(request_pos, request_length, file_size_);

  const uint64_t buffer_start_pos = region.first;
  const std::pair<const uint8_t*, uint64_t> buffer =
      delegate_->DoMap(buffer_start_pos, region.second);
  buffer_ = buffer.first;
  buffer_start_ = buffer_start_pos;
  buffer_length_ = buffer.second;

  // Checks if mmap failed. It fails when the file was shrunk from the
  // previous file size check.
  if (buffer.first != nullptr) {
    // mmap succeeds.
    DCHECK_LE(buffer_start_, request_pos);
    DCHECK_LE(request_pos + request_length, buffer_start_ + buffer_length_);
  }

  return CreateMappedBuffer();
}

std::unique_ptr<FileMapReader::MappedBuffer>
FileMapReader::CreateMappedBuffer() {
  // Ensure that the previous mapped buffer has already been freed.
  // Note: The current implementation allows only one mapped buffer at the same
  // time.
  DCHECK(!instantiated_mapped_buffer_);

  // Doesn't use std::make_unique due to the private constructor.
  auto mapped_buffer = std::unique_ptr<MappedBuffer>(
      new MappedBuffer(buffer_, buffer_start_, buffer_length_));
  instantiated_mapped_buffer_ = mapped_buffer->weak_factory_.GetWeakPtr();
  return mapped_buffer;
}

}  // namespace croslog

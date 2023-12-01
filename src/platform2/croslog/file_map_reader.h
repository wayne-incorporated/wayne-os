// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CROSLOG_FILE_MAP_READER_H_
#define CROSLOG_FILE_MAP_READER_H_

#include <memory>
#include <string>
#include <utility>

#include "base/files/file.h"
#include "base/files/file_path.h"
#include "base/files/memory_mapped_file.h"
#include "base/memory/weak_ptr.h"
#include "base/observer_list.h"
#include "base/observer_list_types.h"

#include "croslog/file_change_watcher.h"
#include "croslog/log_entry.h"
#include "croslog/log_parser.h"

#include <base/check.h>
#include <base/check_op.h>

namespace croslog {

class FileMapReaderDelegate;

// A class to read a large file with chunks.
// How to use:
// - Call CreateReader(base::File) method to instantiate the class
// - Call MapBuffer(pos, len) method to map the specified region from the file
// - Use the methods of MappedBuffer class to access the content of the file.
// Requisites:
// - This class assumes the file is written with "append-only" mode and is never
//   truncated or shrunk. If the file size shrinks, the crash may happen.
//   (file rotation is not a problem because the renamed old log keeps its FD.)
class FileMapReader {
 public:
  // A class to access to the mapped buffer. Access to buffer should be done
  // through this class and be safe during the lifetime of the instance.
  class MappedBuffer {
   public:
    ~MappedBuffer();

    // Returns the specified range of the buffer. The caller must be sure that
    // the specified range is within the range passed to MapBuffer().
    std::pair<const uint8_t*, uint64_t> GetBuffer(
        uint64_t request_pos, uint64_t request_length) const;

    // Returns the character (byte) at the specified position.
    // This is inline since this is frequently called.
    inline uint8_t GetChar(uint64_t position) const {
      DCHECK(valid());
      DCHECK(buffer_start_ <= position);
      DCHECK(position < (buffer_start_ + buffer_length_));
      return buffer_[position - buffer_start_];
    }

    // Returns true if the mmap succeeded and the mapped buffer is valid.
    bool valid() const { return buffer_ != nullptr; }

   private:
    friend class FileMapReader;

    MappedBuffer(const uint8_t* buffer_,
                 uint64_t buffer_start_,
                 uint64_t buffer_length_);
    MappedBuffer(const MappedBuffer&) = delete;
    MappedBuffer& operator=(const MappedBuffer&) = delete;

    const uint8_t* const buffer_ = nullptr;
    const uint64_t buffer_start_ = 0;
    const uint64_t buffer_length_ = 0;

    base::WeakPtrFactory<MappedBuffer> weak_factory_{this};
  };

  // Creates an instance and returns it.
  static std::unique_ptr<FileMapReader> CreateReader(base::File file);

  // Retrieves the chunk size. The value may change on tests.
  static uint64_t GetChunkSizeInBytes();

  // Static methods for test:
  static std::unique_ptr<FileMapReader>
  CreateFileMapReaderDelegateImplMemoryReaderForTest(const uint8_t* buffer,
                                                     uint64_t length);
  static void SetBlockSizesForTest(uint64_t chunk_size_in_bytes,
                                   uint32_t allocate_chunks);

  // ctor and dtor
  explicit FileMapReader(std::unique_ptr<FileMapReaderDelegate> delegate);
  FileMapReader(const FileMapReader&) = delete;
  FileMapReader& operator=(const FileMapReader&) = delete;

  ~FileMapReader();

  // Should be called when the file size is expanded.
  void ApplyFileSizeExpansion();

  // Maps the specified range of the buffer from the file. The mapped buffer
  // can be accessed using the returned object.
  // Only one MappedBuffer instance can be alive at the same time due to the
  // current implementation limitation. Please ensure that the previous one was
  // freed before calling this.
  // On failure of mmap, the returned mapped buffer is invalid.
  std::unique_ptr<MappedBuffer> MapBuffer(uint64_t request_pos,
                                          uint64_t request_length);

  // Returns the cached file size of the target file. The cache is updated
  // when RequestRemap() is called.
  inline int64_t GetFileSize() const {
    DCHECK_GE(file_size_, 0);
    return file_size_;
  }

 private:
  // Utility method to create a mapped buffer.
  std::unique_ptr<FileMapReader::MappedBuffer> CreateMappedBuffer();

  // Delegate to actually map a buffer of file (or memory).
  std::unique_ptr<FileMapReaderDelegate> delegate_;

  const uint8_t* buffer_ = nullptr;
  uint64_t buffer_start_ = 0;
  uint64_t buffer_length_ = 0;
  int64_t file_size_;

  base::WeakPtr<MappedBuffer> instantiated_mapped_buffer_;
};

}  // namespace croslog

#endif  // CROSLOG_FILE_MAP_READER_H_

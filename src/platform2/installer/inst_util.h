// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef INSTALLER_INST_UTIL_H_
#define INSTALLER_INST_UTIL_H_

#include <iostream>
#include <string>
#include <vector>

#include <base/files/file_path.h>

extern const char kEnvIsInstall[];
extern const char kEnvIsFactoryInstall[];
extern const char kEnvIsRecoveryInstall[];

// Index of a partition entry in the GPT.
//
// GPT partition indices start at 1.
//
// Note that the order of partition entries in the GPT does not
// necessarily correspond to the order of the partition's actual data.
class PartitionNum {
 public:
  static const PartitionNum KERN_A;
  static const PartitionNum ROOT_A;
  static const PartitionNum KERN_B;
  static const PartitionNum ROOT_B;
  static const PartitionNum KERN_C;
  static const PartitionNum ROOT_C;
  static const PartitionNum EFI_SYSTEM;

  explicit PartitionNum(uint32_t num) : num_(num) {}

  // Returns true if the partition is KERN_A, KERN_B, or KERN_C.
  bool IsKernel() const;

  // Returns true if the partition is ROOT_A, ROOT_B, or ROOT_C.
  bool IsRoot() const;

  // Get the partition number as a |uint32_t|.
  uint32_t Value() const { return num_; }

  // Convert the partition number to a string.
  std::string ToString() const;

  bool operator==(const PartitionNum& other) const;

 private:
  uint32_t num_ = 0;
};

std::ostream& operator<<(std::ostream& os, const PartitionNum& partition);

// A class to automatically remove directories/files with nftw().
// The removal is done at object destruction time and hence no error will be
// boubled up. If need to, use release() and handle the deletion yourself.
class ScopedPathRemover {
 public:
  explicit ScopedPathRemover(const base::FilePath& root) : root_(root) {}
  virtual ~ScopedPathRemover();

  ScopedPathRemover(const ScopedPathRemover& other) = delete;
  void operator=(const ScopedPathRemover& other) = delete;

  // Return the root path and no longer remove it.
  base::FilePath Release();

 private:
  base::FilePath root_;
};

// Find a pointer to the first element of a statically sized array.
template <typename T, size_t N>
T* begin(T (&ra)[N]) {
  return ra + 0;
}

// Find a pointer to the element after the end of a statically sized array.
template <typename T, size_t N>
T* end(T (&ra)[N]) {
  return ra + N;
}

// Start a timer (there can only be one active).
void LoggingTimerStart();

// Log how long since LoggingTimerStart was last called.
void LoggingTimerFinish();

// This is a place holder to invoke the backing scripts. Once all scripts have
// been rewritten as library calls this command should be deleted.
int RunCommand(const std::vector<std::string>& cmdline);

// Write |content| to |fd| fully. This function will call write() as many times
// as needed to ensure that |content| is fully written. Return false on error.
bool WriteFullyToFileDescriptor(const std::string& content, int fd);

bool LsbReleaseValue(const base::FilePath& file,
                     const std::string& key,
                     std::string* result);

// Given root partition dev node (such as /dev/sda3, /dev/mmcblk0p3,
// /dev/ubiblock3_0), return the block dev (/dev/sda, /dev/mmcblk0, /dev/mtd0).
base::FilePath GetBlockDevFromPartitionDev(const base::FilePath& partition_dev);

// Given root partition dev node (such as /dev/sda3, /dev/mmcblk0p3,
// /dev/ubiblock3_0), return the partition number (3).
PartitionNum GetPartitionFromPartitionDev(const base::FilePath& partition_dev);

// Given block dev node (/dev/sda, /dev/mmcblk0, /dev/mtd0) and a partition
// number (such as 3), return a new dev node pointing to the partition
// (/dev/sda3, /dev/mmcblk0p3, /dev/ubiblock3_0). On NAND media, the partitions
// can change widely, though they have the same block /dev/mtd0:
//   * Root partitions ubiblockX_0
//   * Kernel partitions mtdX
//   * Stateful and OEM partitions ubiX_0
base::FilePath MakePartitionDev(const base::FilePath& partition_dev,
                                PartitionNum partition);

// rm *pack from /dirname
bool RemovePackFiles(const base::FilePath& dirname);

// Create an empty file
bool Touch(const base::FilePath& filename);

// Replace the first instance of pattern in the file with value.
bool ReplaceInFile(const std::string& pattern,
                   const std::string& value,
                   const base::FilePath& path);

// Replace all instances of pattern in target with value
void ReplaceAll(std::string* target,
                const std::string& pattern,
                const std::string& value);

// Mark ext2 (3 or 4???) filesystem RW
bool MakeFileSystemRw(const base::FilePath& dev_name);

// Conveniently invoke the external dump_kernel_config library
std::string DumpKernelConfig(const base::FilePath& kernel_dev);

// ExtractKernelNamedArg(DumpKernelConfig(..), "root") -> /dev/dm-0
// This understands quoted values. dm -> "a b c, foo=far" (strips quotes)
std::string ExtractKernelArg(const std::string& kernel_config,
                             const std::string& tag);

// Take a kernel style argument list and modify a single argument
// value. Quotes will be added to the value if needed.
bool SetKernelArg(const std::string& tag,
                  const std::string& value,
                  std::string* kernel_config);

// IsReadonly determines if the name devices should be treated as
// read-only. This is based on the device name being prefixed with
// "/dev/dm". This catches both cases where verity may be /dev/dm-0
// or /dev/dm-1.
bool IsReadonly(const base::FilePath& device);

// Sets |result| with the current running kernel information like name, version,
// etc.
bool GetKernelInfo(std::string* result);

#endif  // INSTALLER_INST_UTIL_H_

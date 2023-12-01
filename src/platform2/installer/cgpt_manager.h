// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef INSTALLER_CGPT_MANAGER_H_
#define INSTALLER_CGPT_MANAGER_H_

#include <iostream>
#include <optional>
#include <string>

#include <base/files/file_path.h>

#include <vboot/gpt.h>

#include "installer/inst_util.h"

// This file defines a simple C++ wrapper class interface for the cgpt methods.

// These are the possible error codes that can be returned by the CgptManager.
enum class [[nodiscard]] CgptErrorCode {
  kSuccess = 0,
  kNotInitialized = 1,
  kUnknownError = 2,
  kInvalidArgument = 3,
};

std::ostream& operator<<(std::ostream& os, const CgptErrorCode& error);

// Range of sectors on disk.
struct SectorRange {
  // First sector.
  uint64_t start = 0;

  // Number of sectors.
  uint64_t count = 0;
};

// CgptManagerInterface provices methods to manipulate the Guid
// Partition Table as needed for ChromeOS scenarios.
//
// A concrete implementation is provided by `CgptManager`, and a mock
// for unit tests is provided in `mock_cgpt_manager.h`.
class CgptManagerInterface {
 public:
  // Destructor. Automatically closes any opened device.
  virtual ~CgptManagerInterface() {}

  // Opens the given device_name (e.g. "/dev/sdc") and initializes
  // with the Guid Partition Table of that device. This is the first method
  // that should be called on this class.  Otherwise those methods will
  // return kNotInitialized.
  // Returns kSuccess or an appropriate error code.
  // This device is automatically closed when this object is destructed.
  virtual CgptErrorCode Initialize(const base::FilePath& device_name) = 0;

  // Performs any necessary write-backs so that the GPT structs are written to
  // the device. This method is called in the destructor but its error code is
  // not checked. Therefore, it is best to call Finalize yourself and check the
  // returned code.
  virtual CgptErrorCode Finalize() = 0;

  // Sets the "successful" attribute of the given kernelPartition to 0 or 1
  // based on the value of is_successful being true (1) or false(0)
  // Returns kSuccess or an appropriate error code.
  virtual CgptErrorCode SetSuccessful(PartitionNum partition_number,
                                      bool is_successful) = 0;

  // Sets the "NumTriesLeft" attribute of the given kernelPartition to
  // the given num_tries_left value.
  // Returns kSuccess or an appropriate error code.
  virtual CgptErrorCode SetNumTriesLeft(PartitionNum partition_number,
                                        int num_tries_left) = 0;

  // Sets the "Priority" attribute of the given kernelPartition to
  // the given priority value.
  // Returns kSuccess or an appropriate error code.
  virtual CgptErrorCode SetPriority(PartitionNum partition_number,
                                    uint8_t priority) = 0;

  // Populates the unique_id parameter with the Guid that uniquely identifies
  // the given partition_number.
  // Returns kSuccess or an appropriate error code.
  virtual CgptErrorCode GetPartitionUniqueId(PartitionNum partition_number,
                                             Guid* unique_id) const = 0;

  // Sets the "Priority" attribute of a partition to make it higher than all
  // other partitions. If necessary, the priorities of other partitions are
  // reduced to ensure no other partition has a higher priority.
  //
  // It preserves the relative ordering among the remaining partitions and
  // doesn't touch the partitions whose priorities are zero.
  //
  // Returns kSuccess or an appropriate error code.
  virtual CgptErrorCode SetHighestPriority(PartitionNum partition_number) = 0;

  // Get the sectors used by the partition.
  // Returns kCgptSuccess or an appropriate error code.
  virtual CgptErrorCode GetSectorRange(PartitionNum partition_number,
                                       SectorRange& sectors) const = 0;

  // Set the sectors used by the partition. If |start| or |count| is
  // |std::nullopt|, the corresponding partition value will not be
  // updated. At least one of them must be set.
  // Returns kCgptSuccess or an appropriate error code.
  virtual CgptErrorCode SetSectorRange(PartitionNum partition_number,
                                       std::optional<uint64_t> start,
                                       std::optional<uint64_t> count) = 0;

  // In some circumstances devices will have a damaged GPT  (at least
  // b/257478857, possibly other cases). This tries to fix it.
  //
  // Returns kSuccess or an appropriate error code.
  virtual CgptErrorCode RepairPartitionTable() = 0;

  // Get the device path (e.g. "/dev/sda") that was passed in to |Initialize|.
  virtual const base::FilePath& DeviceName() const = 0;
};

class CgptManager : public CgptManagerInterface {
 public:
  // Default constructor. The Initialize method must be called before
  // any other method can be called on this class.
  CgptManager();

  ~CgptManager() override;

  CgptErrorCode Initialize(const base::FilePath& device_name) override;
  CgptErrorCode Finalize() override;
  CgptErrorCode SetSuccessful(PartitionNum partition_number,
                              bool is_successful) override;
  CgptErrorCode SetNumTriesLeft(PartitionNum partition_number,
                                int num_tries_left) override;
  CgptErrorCode SetPriority(PartitionNum partition_number,
                            uint8_t priority) override;
  CgptErrorCode GetPartitionUniqueId(PartitionNum partition_number,
                                     Guid* unique_id) const override;
  CgptErrorCode SetHighestPriority(PartitionNum partition_number) override;
  CgptErrorCode GetSectorRange(PartitionNum partition_number,
                               SectorRange& sectors) const override;
  CgptErrorCode SetSectorRange(PartitionNum partition_number,
                               std::optional<uint64_t> start,
                               std::optional<uint64_t> count) override;
  CgptErrorCode RepairPartitionTable() override;
  const base::FilePath& DeviceName() const override;

 private:
  // The device name that is passed to Initialize.
  base::FilePath device_name_;
  // The size of that device in case we store GPT structs off site (such as on
  // NOR flash). Zero if we store GPT structs on the same device.
  uint64_t device_size_;
  bool is_initialized_;

  CgptManager(const CgptManager&);
  void operator=(const CgptManager&);
};

#endif  // INSTALLER_CGPT_MANAGER_H_

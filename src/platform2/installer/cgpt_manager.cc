// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "installer/cgpt_manager.h"

#include <linux/major.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>
#include <vector>

#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>

#include "installer/inst_util.h"

extern "C" {
#include <vboot/vboot_host.h>
}

using std::string;

namespace {

// Create a temp file, read GPT structs from NOR flash to that file, and return
// true on success. On success, |file_name| contains the path to the temp file.
bool ReadGptFromNor(base::FilePath* file_name) {
  char tmp_name[] = "/tmp/cgptmanagerXXXXXX";
  int fd = mkstemp(tmp_name);
  if (fd < 0) {
    PLOG(ERROR) << "Cannot create temp file to store GPT structs read from NOR";
    return false;
  }
  // Extra parens to work around the compiler parser.
  ScopedPathRemover remover((base::FilePath(tmp_name)));
  // Close fd so that flashrom can write to the file right after.
  close(fd);
  if (RunCommand({"/usr/sbin/flashrom", "-i", string("RW_GPT:") + tmp_name,
                  "-r"}) != 0) {
    return false;
  }
  // Keep the temp file.
  *file_name = remover.Release();
  return true;
}

// Write |data| to NOR flash at FMAP |region|. Return true on success.
bool WriteToNor(const string& data, const string& region) {
  char tmp_name[] = "/tmp/cgptmanagerXXXXXX";
  base::ScopedFD fd(mkstemp(tmp_name));
  if (!fd.is_valid()) {
    PLOG(ERROR) << "Cannot create temp file to write to NOR flash";
    return false;
  }

  // Extra parens to work around the compiler parser.
  ScopedPathRemover remover((base::FilePath(tmp_name)));
  if (!WriteFullyToFileDescriptor(data, fd.get())) {
    LOG(ERROR) << "Cannot write data to temp file " << tmp_name;
    return false;
  }

  // Close fd so that flashrom can open it right after.
  fd.reset();

  std::vector<string> cmd{"/usr/sbin/flashrom", "-i", region + ":" + tmp_name,
                          "-w", "--noverify-all"};
  if (RunCommand(cmd) != 0) {
    LOG(ERROR) << "Cannot write " << tmp_name << " to " << region << " section";
    return false;
  }

  return true;
}

// Write GPT data in |file_name| file to NOR flash. This function writes the
// content in two halves, one to RW_GPT_PRIMARY, and another to RW_GPT_SECONDARY
// sections. Return negative on failure, 0 on success, a positive integer means
// that many parts failed. Due to the way GPT works, we usually could recover
// from one failure.
int WriteGptToNor(const base::FilePath& file_name) {
  string gpt_data;
  if (!base::ReadFileToString(file_name, &gpt_data)) {
    LOG(ERROR) << "Cannot read from " << file_name;
    return -1;
  }

  int ret = 0;
  if (!WriteToNor(gpt_data.substr(0, gpt_data.length() / 2),
                  "RW_GPT_PRIMARY")) {
    ret++;
  }
  if (!WriteToNor(gpt_data.substr(gpt_data.length() / 2), "RW_GPT_SECONDARY")) {
    ret++;
  }

  switch (ret) {
    case 0: {
      break;
    }
    case 1: {
      LOG(ERROR) << "Failed to write one part";
      break;
    }
    case 2: {
      LOG(ERROR) << "Cannot write either part to flashrom";
      break;
    }
    default: {
      LOG(ERROR) << "Unexpected number of write failures (" << ret << ")";
      break;
    }
  }
  return ret;
}

// Set or clear |is_mtd| depending on if |block_dev| points to an MTD device.
bool IsMtd(const base::FilePath& block_dev, bool* is_mtd) {
  struct stat stat_buf;
  if (stat(block_dev.value().c_str(), &stat_buf) != 0) {
    PLOG(ERROR) << "Failed to stat " << block_dev;
    return false;
  }
  *is_mtd = (major(stat_buf.st_rdev) == MTD_CHAR_MAJOR);
  return true;
}

// Return the size of MTD device |block_dev| in |ret|.
bool GetMtdSize(const base::FilePath& block_dev, uint64_t* ret) {
  base::FilePath size_file = base::FilePath("/sys/class/mtd/")
                                 .Append(block_dev.BaseName())
                                 .Append("size");
  string size_string;
  if (!base::ReadFileToString(size_file, &size_string)) {
    LOG(ERROR) << "Cannot read MTD size from " << size_file;
    return false;
  }

  uint64_t size;
  char* end;
  size = strtoull(size_string.c_str(), &end, 10);
  if (*end != '\x0A') {
    PLOG(ERROR) << "Cannot convert " << size_string << " into decimal";
    return false;
  }

  *ret = size;
  return true;
}

}  // namespace

// This file implements the C++ wrapper methods over the C cgpt methods.

std::ostream& operator<<(std::ostream& os, const CgptErrorCode& error) {
  switch (error) {
    case CgptErrorCode::kSuccess:
      os << "CgptErrorCode::kSuccess";
      break;
    case CgptErrorCode::kNotInitialized:
      os << "CgptErrorCode::kNotInitialized";
      break;
    case CgptErrorCode::kUnknownError:
      os << "CgptErrorCode::kUnknownError";
      break;
    case CgptErrorCode::kInvalidArgument:
      os << "CgptErrorCode::kInvalidArgument";
      break;
  }
  return os;
}

CgptManager::CgptManager() : device_size_(0), is_initialized_(false) {}

CgptManager::~CgptManager() {
  CgptErrorCode result = Finalize();
  if (result != CgptErrorCode::kSuccess &&
      result != CgptErrorCode::kNotInitialized) {
    LOG(ERROR) << "Finalize failed: " << result;
  }
}

CgptErrorCode CgptManager::Initialize(const base::FilePath& device_name) {
  device_name_ = device_name;
  bool is_mtd;
  if (!IsMtd(device_name, &is_mtd)) {
    LOG(ERROR) << "Cannot determine if " << device_name << " is an MTD device";
    return CgptErrorCode::kNotInitialized;
  }
  if (is_mtd) {
    LOG(INFO) << device_name << " is an MTD device";
    if (!GetMtdSize(device_name, &device_size_)) {
      LOG(ERROR) << "But we do not know its size";
      return CgptErrorCode::kNotInitialized;
    }
    if (!ReadGptFromNor(&device_name_)) {
      LOG(ERROR) << "Failed to read GPT structs from NOR flash";
      return CgptErrorCode::kNotInitialized;
    }
  }
  is_initialized_ = true;
  return CgptErrorCode::kSuccess;
}

CgptErrorCode CgptManager::Finalize() {
  if (!is_initialized_) {
    return CgptErrorCode::kNotInitialized;
  }

  if (device_size_) {
    if (WriteGptToNor(device_name_) != 0) {
      return CgptErrorCode::kUnknownError;
    }
    if (unlink(device_name_.value().c_str()) != 0) {
      PLOG(ERROR) << "Cannot remove temp file " << device_name_;
    }
  }

  device_size_ = 0;
  is_initialized_ = false;
  return CgptErrorCode::kSuccess;
}

CgptErrorCode CgptManager::SetSuccessful(PartitionNum partition_number,
                                         bool is_successful) {
  if (!is_initialized_)
    return CgptErrorCode::kNotInitialized;

  CgptAddParams params;
  memset(&params, 0, sizeof(params));

  params.drive_name = const_cast<char*>(device_name_.value().c_str());
  params.drive_size = device_size_;
  params.partition = partition_number.Value();

  params.successful = is_successful;
  params.set_successful = true;

  int retval = CgptSetAttributes(&params);
  if (retval != CGPT_OK)
    return CgptErrorCode::kUnknownError;

  return CgptErrorCode::kSuccess;
}

CgptErrorCode CgptManager::SetNumTriesLeft(PartitionNum partition_number,
                                           int numTries) {
  if (!is_initialized_)
    return CgptErrorCode::kNotInitialized;

  CgptAddParams params;
  memset(&params, 0, sizeof(params));

  params.drive_name = const_cast<char*>(device_name_.value().c_str());
  params.drive_size = device_size_;
  params.partition = partition_number.Value();

  params.tries = numTries;
  params.set_tries = true;

  int retval = CgptSetAttributes(&params);
  if (retval != CGPT_OK)
    return CgptErrorCode::kUnknownError;

  return CgptErrorCode::kSuccess;
}

CgptErrorCode CgptManager::SetPriority(PartitionNum partition_number,
                                       uint8_t priority) {
  if (!is_initialized_)
    return CgptErrorCode::kNotInitialized;

  CgptAddParams params;
  memset(&params, 0, sizeof(params));

  params.drive_name = const_cast<char*>(device_name_.value().c_str());
  params.drive_size = device_size_;
  params.partition = partition_number.Value();

  params.priority = priority;
  params.set_priority = true;

  int retval = CgptSetAttributes(&params);
  if (retval != CGPT_OK)
    return CgptErrorCode::kUnknownError;

  return CgptErrorCode::kSuccess;
}

CgptErrorCode CgptManager::GetPartitionUniqueId(PartitionNum partition_number,
                                                Guid* unique_id) const {
  if (!is_initialized_)
    return CgptErrorCode::kNotInitialized;

  if (!unique_id)
    return CgptErrorCode::kInvalidArgument;

  CgptAddParams params;
  memset(&params, 0, sizeof(params));

  params.drive_name = const_cast<char*>(device_name_.value().c_str());
  params.drive_size = device_size_;
  params.partition = partition_number.Value();

  int retval = CgptGetPartitionDetails(&params);
  if (retval != CGPT_OK)
    return CgptErrorCode::kUnknownError;

  *unique_id = params.unique_guid;
  return CgptErrorCode::kSuccess;
}

CgptErrorCode CgptManager::SetHighestPriority(PartitionNum partition_number) {
  if (!is_initialized_)
    return CgptErrorCode::kNotInitialized;

  CgptPrioritizeParams params;
  memset(&params, 0, sizeof(params));

  params.drive_name = const_cast<char*>(device_name_.value().c_str());
  params.drive_size = device_size_;
  params.set_partition = partition_number.Value();
  // The internal implementation in CgptPrioritize automatically computes the
  // right priority number if we supply 0 for the max_priority argument.
  params.max_priority = 0;

  int retval = CgptPrioritize(&params);
  if (retval != CGPT_OK)
    return CgptErrorCode::kUnknownError;

  return CgptErrorCode::kSuccess;
}

CgptErrorCode CgptManager::GetSectorRange(PartitionNum partition_number,
                                          SectorRange& sectors) const {
  if (!is_initialized_)
    return CgptErrorCode::kNotInitialized;

  CgptAddParams params;
  memset(&params, 0, sizeof(params));
  params.drive_name = const_cast<char*>(device_name_.value().c_str());
  params.drive_size = device_size_;
  params.partition = partition_number.Value();

  int retval = CgptGetPartitionDetails(&params);
  if (retval != CGPT_OK)
    return CgptErrorCode::kUnknownError;

  sectors.start = params.begin;
  sectors.count = params.size;
  return CgptErrorCode::kSuccess;
}

CgptErrorCode CgptManager::SetSectorRange(PartitionNum partition_number,
                                          std::optional<uint64_t> start,
                                          std::optional<uint64_t> count) {
  if (!is_initialized_)
    return CgptErrorCode::kNotInitialized;

  CgptAddParams params;
  memset(&params, 0, sizeof(params));

  params.drive_name = const_cast<char*>(device_name_.value().c_str());
  params.drive_size = device_size_;
  params.partition = partition_number.Value();

  // At least one of the inputs must have a value.
  if (!start.has_value() && !count.has_value())
    return CgptErrorCode::kInvalidArgument;

  if (start.has_value()) {
    params.begin = start.value();
    params.set_begin = true;
  }
  if (count.has_value()) {
    params.size = count.value();
    params.set_size = true;
  }

  int retval = CgptAdd(&params);
  if (retval != CGPT_OK)
    return CgptErrorCode::kUnknownError;

  return CgptErrorCode::kSuccess;
}

CgptErrorCode CgptManager::RepairPartitionTable() {
  if (!is_initialized_)
    return CgptErrorCode::kNotInitialized;

  CgptRepairParams params;
  memset(&params, 0, sizeof(params));

  params.drive_name = const_cast<char*>(device_name_.value().c_str());
  params.drive_size = device_size_;
  // This prints the result of the validity check.
  params.verbose = true;

  int retval = CgptRepair(&params);
  if (retval != CGPT_OK)
    return CgptErrorCode::kUnknownError;

  return CgptErrorCode::kSuccess;
}

const base::FilePath& CgptManager::DeviceName() const {
  return device_name_;
}

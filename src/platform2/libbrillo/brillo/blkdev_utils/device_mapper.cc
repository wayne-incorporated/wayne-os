// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <brillo/blkdev_utils/device_mapper.h>

#include <libdevmapper.h>
#include <algorithm>
#include <utility>

#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_tokenizer.h>
#include <base/strings/stringprintf.h>
#include <brillo/blkdev_utils/device_mapper_task.h>
#include <brillo/secure_blob.h>

namespace brillo {

// Use a tokenizer to parse string data stored in SecureBlob.
// The tokenizer does not store internal state so it should be
// okay to use with SecureBlobs.
// DO NOT USE .toker() as that leaks contents of the SecureBlob.
using SecureBlobTokenizer =
    base::StringTokenizerT<std::string, SecureBlob::const_iterator>;

DevmapperTable::DevmapperTable(uint64_t start,
                               uint64_t size,
                               const std::string& type,
                               const SecureBlob& parameters)
    : start_(start), size_(size), type_(type), parameters_(parameters) {}

SecureBlob DevmapperTable::ToSecureBlob() {
  SecureBlob table_blob(base::StringPrintf("%" PRIu64 " %" PRIu64 " %s ",
                                           start_, size_, type_.c_str()));

  return SecureBlob::Combine(table_blob, parameters_);
}

DevmapperTable DevmapperTable::CreateTableFromSecureBlob(
    const SecureBlob& table) {
  uint64_t start, size;
  std::string type;
  DevmapperTable invalid_table(0, 0, "", SecureBlob());

  SecureBlobTokenizer tokenizer(table.begin(), table.end(), " ");

  // First parameter is start.
  if (!tokenizer.GetNext() ||
      !base::StringToUint64(
          std::string(tokenizer.token_begin(), tokenizer.token_end()), &start))
    return invalid_table;

  // Second parameter is size of the dm device.
  if (!tokenizer.GetNext() ||
      !base::StringToUint64(
          std::string(tokenizer.token_begin(), tokenizer.token_end()), &size))
    return invalid_table;

  // Third parameter is type of dm device.
  if (!tokenizer.GetNext())
    return invalid_table;

  type = std::string(tokenizer.token_begin(), tokenizer.token_end());

  // The remaining string is the parameters.
  if (!tokenizer.GetNext())
    return invalid_table;

  // The remaining part is the parameters passed to the device.
  SecureBlob target = SecureBlob(tokenizer.token_begin(), table.end());

  return DevmapperTable(start, size, type, target);
}

SecureBlob DevmapperTable::CryptGetKey() {
  SecureBlobTokenizer tokenizer(parameters_.begin(), parameters_.end(), " ");

  // First field is the cipher.
  if (!tokenizer.GetNext())
    return SecureBlob();

  // The key is stored in the second field.
  if (!tokenizer.GetNext())
    return SecureBlob();

  SecureBlob key(tokenizer.token_begin(), tokenizer.token_end());

  return key;
}

// In order to not leak the encryption key to non-SecureBlob managed memory,
// create the parameter blobs in three parts and combine.
SecureBlob DevmapperTable::CryptCreateParameters(
    const std::string& cipher,
    const SecureBlob& encryption_key,
    const int iv_offset,
    const base::FilePath& device,
    int device_offset,
    bool allow_discard) {
  // First field is the cipher.
  SecureBlob parameter_parts[3];

  parameter_parts[0] = SecureBlob(cipher + " ");
  parameter_parts[1] = encryption_key;
  parameter_parts[2] = SecureBlob(base::StringPrintf(
      " %d %s %d%s", iv_offset, device.value().c_str(), device_offset,
      (allow_discard ? " 1 allow_discards" : "")));

  SecureBlob parameters;
  for (auto param_part : parameter_parts)
    parameters = SecureBlob::Combine(parameters, param_part);

  return parameters;
}

std::unique_ptr<DevmapperTask> CreateDevmapperTask(int type) {
  return std::make_unique<DevmapperTaskImpl>(type);
}

DeviceMapper::DeviceMapper()
    : DeviceMapper(base::BindRepeating(&CreateDevmapperTask)) {}

DeviceMapper::DeviceMapper(const DevmapperTaskFactory& factory)
    : dm_task_factory_(factory) {}

bool DeviceMapper::Setup(const std::string& name, const DevmapperTable& table) {
  auto task = dm_task_factory_.Run(DM_DEVICE_CREATE);

  if (!task->SetName(name)) {
    LOG(ERROR) << "Setup: SetName failed.";
    return false;
  }

  if (!task->AddTarget(table.GetStart(), table.GetSize(), table.GetType(),
                       table.GetParameters())) {
    LOG(ERROR) << "Setup: AddTarget failed";
    return false;
  }

  if (!task->Run(true /* udev sync */)) {
    LOG(ERROR) << "Setup: Run failed.";
    return false;
  }

  return true;
}

bool DeviceMapper::Remove(const std::string& name, bool deferred) {
  auto task = dm_task_factory_.Run(DM_DEVICE_REMOVE);

  if (!task->SetName(name)) {
    LOG(ERROR) << "Remove: SetName failed.";
    return false;
  }

  if (deferred && !task->SetDeferredRemove()) {
    LOG(ERROR) << "Remove: SetDeferredRemoval failed.";
    return false;
  }

  if (!task->Run(true /* udev_sync */)) {
    LOG(ERROR) << "Remove: Teardown failed.";
    return false;
  }

  return true;
}

DevmapperTable DeviceMapper::GetTable(const std::string& name) {
  auto task = dm_task_factory_.Run(DM_DEVICE_TABLE);
  uint64_t start, size;
  std::string type;
  SecureBlob parameters;

  if (!task->SetName(name)) {
    LOG(ERROR) << "GetTable: SetName failed.";
    return DevmapperTable(0, 0, "", SecureBlob());
  }

  if (!task->Run()) {
    LOG(ERROR) << "GetTable: Run failed.";
    return DevmapperTable(0, 0, "", SecureBlob());
  }

  task->GetNextTarget(&start, &size, &type, &parameters);

  return DevmapperTable(start, size, type, parameters);
}

bool DeviceMapper::WipeTable(const std::string& name) {
  auto size_task = dm_task_factory_.Run(DM_DEVICE_TABLE);

  if (!size_task->SetName(name)) {
    LOG(ERROR) << "WipeTable: SetName failed.";
    return false;
  }

  if (!size_task->Run()) {
    LOG(ERROR) << "WipeTable: RunTask failed.";
    return false;
  }

  // Arguments for fetching dm target.
  bool ret = false;
  uint64_t start = 0, size = 0;
  std::string type;
  SecureBlob parameters;

  // Get maximum size of the device to be wiped.
  do {
    ret = size_task->GetNextTarget(&start, &size, &type, &parameters);
    // Setup wipe task.
    auto wipe_task = dm_task_factory_.Run(DM_DEVICE_RELOAD);

    if (!wipe_task->SetName(name)) {
      LOG(ERROR) << "WipeTable: SetName failed.";
      return false;
    }

    if (!wipe_task->AddTarget(0, size, type, parameters)) {
      LOG(ERROR) << "WipeTable: AddTarget failed.";
      return false;
    }

    if (!wipe_task->Run()) {
      LOG(ERROR) << "WipeTable: RunTask failed.";
      return false;
    }
  } while (ret);

  return true;
}

DeviceMapperVersion DeviceMapper::GetTargetVersion(const std::string& target) {
  auto version_task = dm_task_factory_.Run(DM_DEVICE_GET_TARGET_VERSION);

  if (!version_task->SetName(target)) {
    LOG(ERROR) << "GetTargetVersion: SetName failed.";
    return {0, 0, 0};
  }

  if (!version_task->Run()) {
    LOG(ERROR) << "GetTargetVersion: RunTask failed.";
    return {0, 0, 0};
  }

  return version_task->GetVersion();
}

}  // namespace brillo

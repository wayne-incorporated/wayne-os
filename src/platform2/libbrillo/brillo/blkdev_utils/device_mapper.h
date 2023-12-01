// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// brillo::DeviceMapper acts as the interface for any userspace application that
// needs to create/remove/perform operations on device-mapper targets. The
// interface uses the device-mapper target's name as an identifier to denote
// the device the operation will be performed on.

#ifndef LIBBRILLO_BRILLO_BLKDEV_UTILS_DEVICE_MAPPER_H_
#define LIBBRILLO_BRILLO_BLKDEV_UTILS_DEVICE_MAPPER_H_

#include <functional>
#include <memory>
#include <string>

#include <base/files/file_path.h>
#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <brillo/blkdev_utils/device_mapper_task.h>

namespace brillo {

// DevmapperTable manages device parameters. Contains helper
// functions to parse results from dmsetup. Since the table parameters
// may contain sensitive data eg. dm-crypt keys, we use SecureBlobs for
// the table parameters and as the table output format.

class BRILLO_EXPORT DevmapperTable {
 public:
  // Create table from table parameters.
  // Useful for setting up devices.
  DevmapperTable(uint64_t start,
                 uint64_t size,
                 const std::string& type,
                 const SecureBlob& parameters);

  ~DevmapperTable() = default;

  // Returns the table as a SecureBlob.
  SecureBlob ToSecureBlob();

  // Getters for table components.
  uint64_t GetStart() const { return start_; }
  uint64_t GetSize() const { return size_; }
  std::string GetType() const { return type_; }
  SecureBlob GetParameters() const { return parameters_; }

  // Create table from table blob.
  // Useful for parsing output from dmsetup.
  // Using a static function to surface errors in parsing the blob.
  static DevmapperTable CreateTableFromSecureBlob(const SecureBlob& table);

  // dm-crypt specific functions:
  // ----------------------------
  // Extract key from (crypt) table.
  SecureBlob CryptGetKey();

  // Create crypt parameters .
  // Useful for parsing output from dmsetup.
  // Using a static function to surface errors in parsing the blob.
  static SecureBlob CryptCreateParameters(const std::string& cipher,
                                          const SecureBlob& encryption_key,
                                          const int iv_offset,
                                          const base::FilePath& device,
                                          int device_offset,
                                          bool allow_discard);

 private:
  const uint64_t start_;
  const uint64_t size_;
  const std::string type_;
  const SecureBlob parameters_;
};

// DevmapperTask is an abstract class so we wrap it in a unique_ptr.
using DevmapperTaskFactory =
    base::RepeatingCallback<std::unique_ptr<DevmapperTask>(int)>;

// DeviceMapper handles the creation and removal of dm devices as well as
// general functions associated with device-mapper targets.
class BRILLO_EXPORT DeviceMapper {
 public:
  // Default constructor: sets up real devmapper devices.
  DeviceMapper();

  // Set a non-default dm task factory.
  explicit DeviceMapper(const DevmapperTaskFactory& factory);
  DeviceMapper(const DeviceMapper&) = delete;
  DeviceMapper& operator=(const DeviceMapper&) = delete;

  // Default destructor.
  ~DeviceMapper() = default;

  // Sets up device with table on /dev/mapper/<name>.
  // Parameters
  //   name - Name of the devmapper device.
  //   table - Table for the devmapper device.
  bool Setup(const std::string& name, const DevmapperTable& table);

  // Removes device.
  // Parameters
  //   name - Name of the devmapper device.
  //   deferred - Whether device removal should be deferred.
  bool Remove(const std::string& name, bool deferred = false);

  // Returns table for device.
  // Parameters
  //   name - Name of the devmapper device.
  DevmapperTable GetTable(const std::string& name);

  // Clears table for device.
  // Parameters
  //   name - Name of the devmapper device.
  bool WipeTable(const std::string& name);

  // Gets the version for a device-mapper target type. On failure, the function
  // returns {0, 0, 0}. The target version is intended to be used to check
  // feature support for device-mapper targets in the kernel driver.
  //
  // Parameters
  //   target - Name of the device mapper target.
  DeviceMapperVersion GetTargetVersion(const std::string& target);

 private:
  // Devmapper task factory.
  DevmapperTaskFactory dm_task_factory_;
};

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_BLKDEV_UTILS_DEVICE_MAPPER_H_

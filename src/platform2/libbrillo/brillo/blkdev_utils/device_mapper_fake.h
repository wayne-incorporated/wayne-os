// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_BLKDEV_UTILS_DEVICE_MAPPER_FAKE_H_
#define LIBBRILLO_BRILLO_BLKDEV_UTILS_DEVICE_MAPPER_FAKE_H_

#include <memory>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <brillo/blkdev_utils/device_mapper.h>
#include <brillo/blkdev_utils/device_mapper_fake.h>
#include <brillo/blkdev_utils/device_mapper_task.h>
#include <brillo/secure_blob.h>

namespace brillo {
namespace fake {

// Fake implementation of dm_task primitives.
// ------------------------------------------
// dm_task is an opaque type in libdevmapper so we
// define a minimal struct for DmTask and DmTarget
// to avoid linking in libdevmapper.
struct DmTarget {
  uint64_t start;
  uint64_t size;
  std::string type;
  SecureBlob parameters;
};

struct DmTask {
  int type;
  bool deferred;
  std::string name;
  std::vector<DmTarget> targets;
};

// Fake task factory: creates fake tasks that
// stub task info into a map.
std::unique_ptr<DevmapperTask> CreateDevmapperTask(int type);

class FakeDevmapperTask : public brillo::DevmapperTask {
 public:
  explicit FakeDevmapperTask(int type);
  ~FakeDevmapperTask() override = default;
  bool SetName(const std::string& name) override;
  bool AddTarget(uint64_t start,
                 uint64_t sectors,
                 const std::string& target,
                 const SecureBlob& parameters) override;
  bool GetNextTarget(uint64_t* start,
                     uint64_t* sectors,
                     std::string* target,
                     SecureBlob* parameters) override;
  bool Run(bool udev_sync = true) override;
  DeviceMapperVersion GetVersion() override;
  bool SetDeferredRemove() override;

 private:
  std::unique_ptr<DmTask> task_;
};

}  // namespace fake
}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_BLKDEV_UTILS_DEVICE_MAPPER_FAKE_H_

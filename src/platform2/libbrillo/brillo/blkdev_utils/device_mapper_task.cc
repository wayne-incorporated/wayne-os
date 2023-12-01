// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <brillo/blkdev_utils/device_mapper_task.h>

#include <libdevmapper.h>
#include <string>
#include <utility>

#include <base/logging.h>
#include <brillo/blkdev_utils/device_mapper.h>

namespace brillo {

DevmapperTaskImpl::DevmapperTaskImpl(int type)
    : task_(DmTaskPtr(dm_task_create(type), &dm_task_destroy)) {}

bool DevmapperTaskImpl::SetName(const std::string& name) {
  if (!task_ || !dm_task_set_name(task_.get(), name.c_str())) {
    LOG(ERROR) << "SetName failed";
    return false;
  }
  return true;
}

bool DevmapperTaskImpl::AddTarget(uint64_t start,
                                  uint64_t length,
                                  const std::string& type,
                                  const SecureBlob& parameters) {
  // Strings stored in SecureBlob don't end with '\0'. Unfortunately,
  // this causes accesses beyond the allocated storage space if any
  // of the functions expecting a c-string get passed a SecureBlob.data().
  // Temporarily, assign to a string.
  // TODO(sarthakkukreti): Evaluate creation of a SecureCString to keep
  // string data safe.
  std::string parameters_str = parameters.to_string();
  if (!task_ || !dm_task_add_target(task_.get(), start, length, type.c_str(),
                                    parameters_str.c_str())) {
    LOG(ERROR) << "AddTarget failed";
    return false;
  }
  // Clear the string.
  parameters_str.clear();
  return true;
}

bool DevmapperTaskImpl::GetNextTarget(uint64_t* start,
                                      uint64_t* length,
                                      std::string* type,
                                      SecureBlob* parameters) {
  if (!task_) {
    LOG(ERROR) << "GetNextTarget: invalid task.";
    return false;
  }

  char *type_cstr, *parameters_cstr;
  next_target_ = dm_get_next_target(task_.get(), next_target_, start, length,
                                    &type_cstr, &parameters_cstr);

  if (type_cstr)
    *type = std::string(type_cstr);
  if (parameters_cstr) {
    SecureBlob parameters_blob(parameters_cstr);
    memset(parameters_cstr, 0, parameters_blob.size());
    *parameters = std::move(parameters_blob);
  }

  return (next_target_ != nullptr);
}

bool DevmapperTaskImpl::Run(bool udev_sync) {
  uint32_t cookie = 0;

  if (!task_) {
    LOG(ERROR) << "Invalid task.";
    return false;
  }

  if (udev_sync && !dm_task_set_cookie(task_.get(), &cookie, 0)) {
    LOG(ERROR) << "dm_task_set_cookie failed";
    return false;
  }

  if (!dm_task_run(task_.get())) {
    LOG(ERROR) << "dm_task_run failed";
    return false;
  }

  // Make sure the node exists before continuing.
  // TODO(sarthakkukreti): move to dm_udev_wait_immediate() on uprevving lvm2.
  return udev_sync ? (dm_udev_wait(cookie) != 0) : true;
}

DeviceMapperVersion DevmapperTaskImpl::GetVersion() {
  struct dm_versions* dmt_versions = dm_task_get_versions(task_.get());
  DeviceMapperVersion version;

  version.major = dmt_versions->version[0];
  version.minor = dmt_versions->version[1];
  version.patchlevel = dmt_versions->version[2];

  return version;
}

bool DevmapperTaskImpl::SetDeferredRemove() {
  return dm_task_deferred_remove(task_.get());
}

}  // namespace brillo

// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include <optional>
#include <string>

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>

#include "libmems/common_types.h"
#include "libmems/iio_channel.h"
#include "libmems/iio_context_impl.h"
#include "libmems/iio_device_trigger_impl.h"

namespace {

constexpr char kAddTrigger[] = "add_trigger";

}  // namespace

namespace libmems {

std::optional<int> IioDeviceTriggerImpl::GetIdFromString(const char* id_str) {
  size_t id_len = strlen(id_str);
  if (id_len == strlen(kIioSysfsTrigger) &&
      strncmp(id_str, kIioSysfsTrigger, id_len) == 0) {
    return -1;
  }

  return IioDevice::GetIdAfterPrefix(id_str, kTriggerIdPrefix);
}

std::string IioDeviceTriggerImpl::GetStringFromId(int id) {
  if (id == -1)
    return std::string(kIioSysfsTrigger);
  return base::StringPrintf("trigger%d", id);
}

IioDeviceTriggerImpl::IioDeviceTriggerImpl(IioContextImpl* ctx, iio_device* dev)
    : IioDevice(), context_(ctx), trigger_(dev) {
  CHECK(context_);
  CHECK(trigger_);

  log_prefix_ = base::StringPrintf("Trigger with id: %d and name: %s. ",
                                   GetId(), (GetName() ? GetName() : "null"));
}

IioContext* IioDeviceTriggerImpl::GetContext() const {
  return context_;
}

const char* IioDeviceTriggerImpl::GetName() const {
  return iio_device_get_name(trigger_);
}

int IioDeviceTriggerImpl::GetId() const {
  const char* id_str = iio_device_get_id(trigger_);

  auto id = GetIdFromString(id_str);
  DCHECK(id.has_value());
  return id.value();
}

base::FilePath IioDeviceTriggerImpl::GetPath() const {
  int id = GetId();
  std::string id_str = std::string(kIioSysfsTrigger);
  if (id >= 0)
    id_str = GetStringFromId(id);

  auto path = base::FilePath(kSysDevString).Append(id_str);
  CHECK(base::DirectoryExists(path));
  return path;
}

std::optional<std::string> IioDeviceTriggerImpl::ReadStringAttribute(
    const std::string& name) const {
  char data[kReadAttrBufferSize] = {0};
  ssize_t len =
      iio_device_attr_read(trigger_, name.c_str(), data, sizeof(data));
  if (len < 0) {
    LOG(WARNING) << log_prefix_ << "Attempting to read string attribute "
                 << name << " failed: " << len;
    return std::nullopt;
  }
  return std::string(data, len);
}

std::optional<int64_t> IioDeviceTriggerImpl::ReadNumberAttribute(
    const std::string& name) const {
  long long val = 0;  // NOLINT(runtime/int)
  int error = iio_device_attr_read_longlong(trigger_, name.c_str(), &val);
  if (error) {
    LOG(WARNING) << log_prefix_ << "Attempting to read number attribute "
                 << name << " failed: " << error;
    return std::nullopt;
  }
  return val;
}

std::optional<double> IioDeviceTriggerImpl::ReadDoubleAttribute(
    const std::string& name) const {
  double val = 0;
  int error = iio_device_attr_read_double(trigger_, name.c_str(), &val);
  if (error) {
    LOG(WARNING) << log_prefix_ << "Attempting to read double attribute "
                 << name << " failed: " << error;
    return std::nullopt;
  }
  return val;
}

bool IioDeviceTriggerImpl::WriteNumberAttribute(const std::string& name,
                                                int64_t value) {
  int id = GetId();
  if ((id == -1 && name.compare(kAddTrigger) != 0) ||
      (id != -1 && name.compare(kSamplingFrequencyAttr) != 0)) {
    return false;
  }

  int error = iio_device_attr_write_longlong(trigger_, name.c_str(), value);
  if (error) {
    LOG(WARNING) << log_prefix_ << "Attempting to write number attribute "
                 << name << " failed: " << error;
    return false;
  }
  return true;
}

bool IioDeviceTriggerImpl::WriteDoubleAttribute(const std::string& name,
                                                double value) {
  int id = GetId();
  if ((id == -1 && name.compare(kAddTrigger) != 0) ||
      (id != -1 && name.compare(kSamplingFrequencyAttr) != 0)) {
    return false;
  }

  int error = iio_device_attr_write_double(trigger_, name.c_str(), value);
  if (error) {
    LOG(WARNING) << log_prefix_ << "Attempting to write double attribute "
                 << name << " failed: " << error;
    return false;
  }
  return true;
}

}  // namespace libmems

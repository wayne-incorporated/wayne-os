// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBMEMS_IIO_CONTEXT_IMPL_H_
#define LIBMEMS_IIO_CONTEXT_IMPL_H_

#include <iio.h>

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "libmems/export.h"
#include "libmems/iio_context.h"
#include "libmems/iio_device.h"
#include "libmems/iio_device_impl.h"
#include "libmems/iio_device_trigger_impl.h"

namespace libmems {

class LIBMEMS_EXPORT IioContextImpl : public IioContext {
 public:
  IioContextImpl();
  IioContextImpl(const IioContextImpl&) = delete;
  IioContextImpl& operator=(const IioContextImpl&) = delete;

  ~IioContextImpl() override = default;

  bool IsValid() const override;
  iio_context* GetCurrentContext() const override;

  void Reload() override;
  bool SetTimeout(uint32_t timeout) override;

  std::vector<IioDevice*> GetDevicesByName(const std::string& name) override;
  IioDevice* GetDeviceById(int id) override;
  std::vector<IioDevice*> GetAllDevices() override;

  std::vector<IioDevice*> GetTriggersByName(const std::string& name) override;
  IioDevice* GetTriggerById(int id) override;
  std::vector<IioDevice*> GetAllTriggers() override;

 private:
  using ContextUniquePtr =
      std::unique_ptr<iio_context, decltype(&iio_context_destroy)>;

  template <typename T>
  IioDevice* GetById(int id, std::map<int, std::unique_ptr<T>>* devices_map);
  template <typename T>
  std::vector<IioDevice*> GetByName(
      const std::string& name, std::map<int, std::unique_ptr<T>>* devices_map);
  template <typename T>
  std::vector<IioDevice*> GetAll(
      std::map<int, std::unique_ptr<T>>* devices_map);

  template <typename T>
  void Reload(std::map<int, std::unique_ptr<T>>* devices_map);

  std::vector<ContextUniquePtr> context_;

  // device id to IioDevice
  std::map<int, std::unique_ptr<IioDeviceImpl>> devices_;
  // trigger id to IioDevice
  std::map<int, std::unique_ptr<IioDeviceTriggerImpl>> triggers_;

  // Store the removed devices, whose pointers and memory would still be valid
  // and usable, while the attributes and samples won't be available.
  std::vector<std::unique_ptr<IioDevice>> removed_devices_;
};

}  // namespace libmems

#endif  // LIBMEMS_IIO_CONTEXT_IMPL_H_

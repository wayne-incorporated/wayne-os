// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CECSERVICE_CEC_DEVICE_H_
#define CECSERVICE_CEC_DEVICE_H_

#include <linux/cec.h>

#include <memory>
#include <string>

#include <base/files/file_path.h>
#include <base/functional/callback.h>
#include <base/memory/weak_ptr.h>
#include <chromeos/dbus/service_constants.h>

#include "cecservice/cec_fd.h"

namespace cecservice {

// Object handling interaction with a single /dev/cec* node.
class CecDevice {
 public:
  using GetTvPowerStatusCallback = base::OnceCallback<void(TvPowerStatus)>;

  virtual ~CecDevice() = default;

  // Gets power state of TV.
  virtual void GetTvPowerStatus(GetTvPowerStatusCallback callback) = 0;
  // Sends stand by request to a TV.
  virtual void SetStandBy() = 0;
  // Sends wake up (image view on + active source) messages.
  virtual void SetWakeUp() = 0;
};

// Actual implementation of CecDevice.
class CecDeviceImpl : public CecDevice {
 public:
  // Actual implementation.
  class Impl;

  CecDeviceImpl(std::unique_ptr<CecFd> fd, const base::FilePath& device_path);
  CecDeviceImpl(const CecDeviceImpl&) = delete;
  CecDeviceImpl& operator=(const CecDeviceImpl&) = delete;

  ~CecDeviceImpl() override;

  // Performs object initialization. Returns false if the initialization
  // failed and object is unusable.
  bool Init();

  // CecDevice overrides:
  void GetTvPowerStatus(GetTvPowerStatusCallback callback) override;
  void SetStandBy() override;
  void SetWakeUp() override;

 private:
  // Actual implementation.
  std::unique_ptr<Impl> impl_;
};

// Factory creating CEC device handlers.
class CecDeviceFactory {
 public:
  virtual ~CecDeviceFactory() = default;

  // Creates a new CEC device node handler from a given path. Returns empty ptr
  // on failure.
  virtual std::unique_ptr<CecDevice> Create(
      const base::FilePath& path) const = 0;
};

// Concrete implementation of the CEC device handlers factory.
class CecDeviceFactoryImpl : public CecDeviceFactory {
 public:
  explicit CecDeviceFactoryImpl(const CecFdOpener* cec_fd_opener);
  CecDeviceFactoryImpl(const CecDeviceFactoryImpl&) = delete;
  CecDeviceFactoryImpl& operator=(const CecDeviceFactoryImpl&) = delete;

  ~CecDeviceFactoryImpl() override;

  // CecDeviceFactory overrides.
  std::unique_ptr<CecDevice> Create(const base::FilePath& path) const override;

 private:
  const CecFdOpener* cec_fd_opener_;
};

}  // namespace cecservice

#endif  // CECSERVICE_CEC_DEVICE_H_

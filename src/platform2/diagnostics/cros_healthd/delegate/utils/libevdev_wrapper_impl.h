// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_DELEGATE_UTILS_LIBEVDEV_WRAPPER_IMPL_H_
#define DIAGNOSTICS_CROS_HEALTHD_DELEGATE_UTILS_LIBEVDEV_WRAPPER_IMPL_H_

#include <libevdev/libevdev.h>
#include <memory>
#include <string>

#include "diagnostics/cros_healthd/delegate/utils/libevdev_wrapper.h"

namespace diagnostics {

class LibevdevWrapperImpl final : public LibevdevWrapper {
 public:
  // Creates and returns a libevdev device from the given file descriptor.
  // Returns null on failure.
  static std::unique_ptr<LibevdevWrapper> Create(int fd);

  LibevdevWrapperImpl(const LibevdevWrapperImpl&) = delete;
  LibevdevWrapperImpl& operator=(const LibevdevWrapperImpl&) = delete;
  ~LibevdevWrapperImpl() override;

  // LibevdevWrapper overrides:
  bool HasProperty(unsigned int prop) override;
  bool HasEventType(unsigned int type) override;
  bool HasEventCode(unsigned int type, unsigned int code) override;
  std::string GetName() override;
  int GetIdBustype() override;
  int GetAbsMaximum(unsigned int code) override;
  int GetEventValue(unsigned int type, unsigned int code) override;
  int GetNumSlots() override;
  int FetchSlotValue(unsigned int slot, unsigned int code, int* value) override;
  int NextEvent(unsigned int flags, input_event* ev) override;

 protected:
  explicit LibevdevWrapperImpl(libevdev* dev);

 private:
  libevdev* dev_ = nullptr;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_DELEGATE_UTILS_LIBEVDEV_WRAPPER_IMPL_H_

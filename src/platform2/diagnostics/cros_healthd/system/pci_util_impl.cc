// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <setjmp.h>
#include <stdarg.h>

#include <base/check.h>
#include <base/logging.h>

#include "diagnostics/cros_healthd/system/pci_util_impl.h"

extern "C" {
#include <pci/pci.h>
}

namespace diagnostics {

namespace {
// These buffer sizes are referred from pciutils/lspci.c.
const int kVendorBufferSize = 128;
const int kDeviceBufferSize = 128;
const int kErrorBufferSize = 256;

// The |jmp_buf| for error handling.
jmp_buf error_handle_env;

// HandleError is a error handler for pcilib. It is similar to the default one
// in pcilib but replace |exit()| with |longjmp()| to prevent exiting the whole
// process.
void PCI_NONRET HandleError(char* msg, ...) {
  va_list args;
  char buf[kErrorBufferSize];

  va_start(args, msg);
  vsnprintf(buf, kErrorBufferSize, msg, args);
  va_end(args);

  VLOG(1) << "Error from pcilib: " << buf;

  longjmp(error_handle_env, 1);
}

void HandleWarning(char* msg, ...) {
  va_list args;
  char buf[kErrorBufferSize];

  va_start(args, msg);
  vsnprintf(buf, kErrorBufferSize, msg, args);
  va_end(args);

  VLOG(1) << "Warning from pcilib: " << buf;
}
}  // namespace

PciUtilImpl::PciUtilImpl() {
  pacc_ = pci_alloc();
  CHECK(pacc_);
  pacc_->error = &HandleError;
  pacc_->warning = &HandleWarning;
  if (setjmp(error_handle_env) == 0) {
    pci_init(pacc_);
    return;
  }
  // Handle longjmp from HandleError
  pci_cleanup(pacc_);
  pacc_ = nullptr;
}

PciUtilImpl::~PciUtilImpl() {
  if (pacc_)
    pci_cleanup(pacc_);
}

std::string PciUtilImpl::GetVendorName(uint16_t vendor_id) {
  char buf[kVendorBufferSize];
  if (pacc_ && setjmp(error_handle_env) == 0) {
    return pci_lookup_name(pacc_, buf, sizeof(buf), PCI_LOOKUP_VENDOR,
                           static_cast<int>(vendor_id));
  }
  return "";
}

std::string PciUtilImpl::GetDeviceName(uint16_t vendor_id, uint16_t device_id) {
  char buf[kDeviceBufferSize];
  if (pacc_ && setjmp(error_handle_env) == 0) {
    return pci_lookup_name(pacc_, buf, sizeof(buf), PCI_LOOKUP_DEVICE,
                           static_cast<int>(vendor_id),
                           static_cast<int>(device_id));
  }
  return "";
}

}  // namespace diagnostics

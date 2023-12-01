// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_WILCO_DTC_SUPPORTD_UTILS_SYSTEM_DEBUGD_ADAPTER_H_
#define DIAGNOSTICS_WILCO_DTC_SUPPORTD_UTILS_SYSTEM_DEBUGD_ADAPTER_H_

#include <string>

#include <base/functional/callback.h>
#include <brillo/errors/error.h>

namespace diagnostics {
namespace wilco {

// Adapter for communication with debugd daemon.
class DebugdAdapter {
 public:
  using OnceStringResultCallback =
      base::OnceCallback<void(const std::string& result, brillo::Error* error)>;

  struct StringResult {
    std::string value;
    brillo::ErrorPtr error;
  };

  virtual ~DebugdAdapter() = default;

  // Sends async request to debugd via D-Bus call. On success, debugd runs
  // smartctl util to retrieve SMART attributes and returns output via callback.
  virtual void GetSmartAttributes(OnceStringResultCallback callback) = 0;

  // Sends async request to debugd via D-Bus call. On success, debugd runs
  // nvme util to retrieve NVMe identity data and returns output via callback.
  virtual void GetNvmeIdentity(OnceStringResultCallback callback) = 0;

  // Sends synchonous request to debugd via D-Bus call. On success, debugd runs
  // nvme util to retrieve NVMe identity data and returns output or an error.
  virtual StringResult GetNvmeIdentitySync() = 0;

  // Sends async request to debugd via D-Bus call. On success, debugd runs
  // nvme util to start NVMe short-time self-test and returns start result
  // output via callback.
  virtual void RunNvmeShortSelfTest(OnceStringResultCallback callback) = 0;

  // Sends async request to debugd via D-Bus call. On success, debugd runs
  // nvme util to start NVMe long-time self-test and returns start result
  // via callback.
  virtual void RunNvmeLongSelfTest(OnceStringResultCallback callback) = 0;

  // Sends async request to debugd via D-Bus call. On success, debugd runs
  // nvme util to abort NVMe self-test..
  virtual void StopNvmeSelfTest(OnceStringResultCallback callback) = 0;

  // Sends async request to debugd via D-Bus call. On success, debugd runs
  // nvme util to retrieve NVMe info from log page and returns output via
  // callback. Parameter page_id indicates which log page is required; length
  // indicates the size of required byte data (this parameter also means precise
  // length of decoded data if raw_binary is set); raw_binary indicates if data
  // shall be returned with raw binary format and encoded with Base64.
  virtual void GetNvmeLog(uint32_t page_id,
                          uint32_t length,
                          bool raw_binary,
                          OnceStringResultCallback callback) = 0;
};

}  // namespace wilco
}  // namespace diagnostics

#endif  // DIAGNOSTICS_WILCO_DTC_SUPPORTD_UTILS_SYSTEM_DEBUGD_ADAPTER_H_

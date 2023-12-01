// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "federated/federated_library.h"

#include <cstddef>

#include <absl/status/status.h>
#include <base/files/file_path.h>
#include <base/logging.h>
#include <base/native_library.h>
#include <base/no_destructor.h>

#include "federated/federated_client.h"
#include "federated/metrics.h"

namespace federated {

FederatedLibrary* FederatedLibrary::GetInstance(const std::string& lib_path) {
  static base::NoDestructor<FederatedLibrary> instance(lib_path);
  return instance.get();
}

FederatedLibrary::FederatedLibrary(const std::string& lib_path)
    : run_plan_(nullptr), free_run_plan_result_(nullptr) {
  base::NativeLibraryLoadError error;
  library_.emplace(base::LoadNativeLibraryWithOptions(
      base::FilePath(lib_path),
      /* options */ {.prefer_own_symbols = true}, &error));
  if (!library_->is_valid()) {
    LOG(ERROR) << "Failed to load library, error message: " << error.ToString();
    status_ = absl::FailedPreconditionError(
        "Failed to load library, error message: " + error.ToString());
    Metrics::GetInstance()->LogServiceEvent(ServiceEvent::kInvalidLibraryError);
    return;
  }

// Helper macro to look up functions from the library, assuming the function
// pointer type is named as (name+"Fn"), which is the case in
// <fcp/fcp.h>.
#define FEDERATED_LOOKUP_FUNCTION(function_ptr, name)                  \
  function_ptr =                                                       \
      reinterpret_cast<name##Fn>(library_->GetFunctionPointer(#name)); \
  if (function_ptr == nullptr) {                                       \
    LOG(ERROR) << "Failed to lookup function " << #name;               \
    status_ = absl::InternalError("Failed to lookup function");        \
    Metrics::GetInstance()->LogServiceEvent(                           \
        ServiceEvent::kFunctionMissingError);                          \
    return;                                                            \
  }
  // Look up the function pointers.
  FEDERATED_LOOKUP_FUNCTION(run_plan_, FlRunPlan);
  FEDERATED_LOOKUP_FUNCTION(free_run_plan_result_, FlFreeRunPlanResult);
#undef FEDERATED_LOOKUP_FUNCTION

  status_ = absl::OkStatus();
  Metrics::GetInstance()->LogServiceEvent(ServiceEvent::kLibraryLoadingSuccess);
}

FederatedLibrary::~FederatedLibrary() = default;

absl::Status FederatedLibrary::GetStatus() const {
  return status_;
}

FederatedClient FederatedLibrary::CreateClient(
    const std::string& service_uri,
    const std::string& api_key,
    const std::string& brella_lib_version,
    const ClientConfigMetadata client_config,
    DeviceStatusMonitor* const device_status_monitor) {
  DCHECK(status_.ok());
  return FederatedClient(run_plan_, free_run_plan_result_, service_uri, api_key,
                         brella_lib_version, client_config,
                         device_status_monitor);
}

}  // namespace federated

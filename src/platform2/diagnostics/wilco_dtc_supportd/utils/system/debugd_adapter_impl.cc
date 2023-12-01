// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/wilco_dtc_supportd/utils/system/debugd_adapter_impl.h"

#include <string>
#include <utility>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/memory/ptr_util.h>
#include <brillo/errors/error.h>

#include "debugd/dbus-proxies.h"

namespace diagnostics {
namespace wilco {

namespace {

constexpr char kSmartctlAttributesOption[] = "attributes";
constexpr char kNvmeIdentityOption[] = "identify_controller";
constexpr char kNvmeShortSelfTestOption[] = "short_self_test";
constexpr char kNvmeLongSelfTestOption[] = "long_self_test";
constexpr char kNvmeStopSelfTestOption[] = "stop_self_test";

using OnceStringResultCallback = DebugdAdapter::OnceStringResultCallback;
auto SplitStringResultCallback(OnceStringResultCallback callback) {
  auto [cb1, cb2] = base::SplitOnceCallback(std::move(callback));
  auto on_success = base::BindOnce(
      [](OnceStringResultCallback callback, const std::string& result) {
        std::move(callback).Run(result, nullptr);
      },
      std::move(cb1));
  auto on_error = base::BindOnce(
      [](OnceStringResultCallback callback, brillo::Error* error) {
        std::move(callback).Run(std::string(), error);
      },
      std::move(cb2));
  return std::make_pair(std::move(on_success), std::move(on_error));
}

}  // namespace

DebugdAdapterImpl::DebugdAdapterImpl(
    std::unique_ptr<org::chromium::debugdProxyInterface> debugd_proxy)
    : debugd_proxy_(std::move(debugd_proxy)) {
  DCHECK(debugd_proxy_);
}

DebugdAdapterImpl::~DebugdAdapterImpl() = default;

void DebugdAdapterImpl::GetSmartAttributes(OnceStringResultCallback callback) {
  auto [on_success, on_error] = SplitStringResultCallback(std::move(callback));
  debugd_proxy_->SmartctlAsync(kSmartctlAttributesOption, std::move(on_success),
                               std::move(on_error));
}

void DebugdAdapterImpl::GetNvmeIdentity(OnceStringResultCallback callback) {
  auto [on_success, on_error] = SplitStringResultCallback(std::move(callback));
  debugd_proxy_->NvmeAsync(kNvmeIdentityOption, std::move(on_success),
                           std::move(on_error));
}

DebugdAdapter::StringResult DebugdAdapterImpl::GetNvmeIdentitySync() {
  StringResult result;
  debugd_proxy_->Nvme(kNvmeIdentityOption, &result.value, &result.error);
  return result;
}

void DebugdAdapterImpl::RunNvmeShortSelfTest(
    OnceStringResultCallback callback) {
  auto [on_success, on_error] = SplitStringResultCallback(std::move(callback));
  debugd_proxy_->NvmeAsync(kNvmeShortSelfTestOption, std::move(on_success),
                           std::move(on_error));
}

void DebugdAdapterImpl::RunNvmeLongSelfTest(OnceStringResultCallback callback) {
  auto [on_success, on_error] = SplitStringResultCallback(std::move(callback));
  debugd_proxy_->NvmeAsync(kNvmeLongSelfTestOption, std::move(on_success),
                           std::move(on_error));
}

void DebugdAdapterImpl::StopNvmeSelfTest(OnceStringResultCallback callback) {
  auto [on_success, on_error] = SplitStringResultCallback(std::move(callback));
  debugd_proxy_->NvmeAsync(kNvmeStopSelfTestOption, std::move(on_success),
                           std::move(on_error));
}

void DebugdAdapterImpl::GetNvmeLog(uint32_t page_id,
                                   uint32_t length,
                                   bool raw_binary,
                                   OnceStringResultCallback callback) {
  auto [on_success, on_error] = SplitStringResultCallback(std::move(callback));
  debugd_proxy_->NvmeLogAsync(page_id, length, raw_binary,
                              std::move(on_success), std::move(on_error));
}

}  // namespace wilco
}  // namespace diagnostics

// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_WILCO_DTC_SUPPORTD_UTILS_SYSTEM_DEBUGD_ADAPTER_IMPL_H_
#define DIAGNOSTICS_WILCO_DTC_SUPPORTD_UTILS_SYSTEM_DEBUGD_ADAPTER_IMPL_H_

#include <memory>

#include "diagnostics/wilco_dtc_supportd/utils/system/debugd_adapter.h"

namespace org {
namespace chromium {
class debugdProxyInterface;
}  // namespace chromium
}  // namespace org

namespace diagnostics {
namespace wilco {

class DebugdAdapterImpl final : public DebugdAdapter {
 public:
  explicit DebugdAdapterImpl(
      std::unique_ptr<org::chromium::debugdProxyInterface> debugd_proxy);
  DebugdAdapterImpl(const DebugdAdapterImpl&) = delete;
  DebugdAdapterImpl& operator=(const DebugdAdapterImpl&) = delete;
  ~DebugdAdapterImpl() override;

  // DebugdAdapter overrides:
  void GetSmartAttributes(OnceStringResultCallback callback) override;
  void GetNvmeIdentity(OnceStringResultCallback callback) override;
  StringResult GetNvmeIdentitySync() override;
  void RunNvmeShortSelfTest(OnceStringResultCallback callback) override;
  void RunNvmeLongSelfTest(OnceStringResultCallback callback) override;
  void StopNvmeSelfTest(OnceStringResultCallback callback) override;
  void GetNvmeLog(uint32_t page_id,
                  uint32_t length,
                  bool raw_binary,
                  OnceStringResultCallback callback) override;

 private:
  std::unique_ptr<org::chromium::debugdProxyInterface> debugd_proxy_;
};

}  // namespace wilco
}  // namespace diagnostics

#endif  // DIAGNOSTICS_WILCO_DTC_SUPPORTD_UTILS_SYSTEM_DEBUGD_ADAPTER_IMPL_H_

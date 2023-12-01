/* Copyright 2019 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef HARDWARE_VERIFIER_PROBE_RESULT_GETTER_IMPL_H_
#define HARDWARE_VERIFIER_PROBE_RESULT_GETTER_IMPL_H_

#include <memory>
#include <optional>

#include "hardware_verifier/probe_result_getter.h"

namespace hardware_verifier {

// A helper class to invoke |runtime_probe| service via D-Bus interface.
//
// All methods are mostly implemented by using the existing functions in
// brillo::dbus::* so we mock this helper class and only test other parts
// of |ProbeResultGetterImpl| in unittest.
class RuntimeProbeProxy {
 public:
  RuntimeProbeProxy() = default;
  RuntimeProbeProxy(const RuntimeProbeProxy&) = delete;
  RuntimeProbeProxy& operator=(const RuntimeProbeProxy&) = delete;

  virtual ~RuntimeProbeProxy() = default;
  virtual bool ProbeCategories(const runtime_probe::ProbeRequest& req,
                               runtime_probe::ProbeResult* resp) const;
};

// The real implementation of |ProbeResultGetter|.
class ProbeResultGetterImpl : public ProbeResultGetter {
 public:
  ProbeResultGetterImpl();

  std::optional<runtime_probe::ProbeResult> GetFromRuntimeProbe()
      const override;
  std::optional<runtime_probe::ProbeResult> GetFromFile(
      const base::FilePath& file_path) const override;

 private:
  friend class TestProbeResultGetterImpl;

  explicit ProbeResultGetterImpl(
      std::unique_ptr<RuntimeProbeProxy> runtime_probe_proxy);
  ProbeResultGetterImpl(const ProbeResultGetterImpl&) = delete;
  ProbeResultGetterImpl& operator=(const ProbeResultGetterImpl&) = delete;

  std::unique_ptr<RuntimeProbeProxy> runtime_probe_proxy_;
};

}  // namespace hardware_verifier

#endif  // HARDWARE_VERIFIER_PROBE_RESULT_GETTER_IMPL_H_

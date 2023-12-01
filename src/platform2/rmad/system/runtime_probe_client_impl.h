// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_SYSTEM_RUNTIME_PROBE_CLIENT_IMPL_H_
#define RMAD_SYSTEM_RUNTIME_PROBE_CLIENT_IMPL_H_

#include "rmad/system/runtime_probe_client.h"

#include <memory>
#include <vector>

#include <base/memory/scoped_refptr.h>
#include <dbus/bus.h>
#include <rmad/proto_bindings/rmad.pb.h>
#include <runtime_probe/proto_bindings/runtime_probe.pb.h>

namespace org {
namespace chromium {
class RuntimeProbeProxyInterface;
}  // namespace chromium
}  // namespace org

namespace rmad {

class RuntimeProbeClientImpl : public RuntimeProbeClient {
 public:
  explicit RuntimeProbeClientImpl(const scoped_refptr<dbus::Bus>& bus);
  explicit RuntimeProbeClientImpl(
      std::unique_ptr<org::chromium::RuntimeProbeProxyInterface>
          runtime_probe_proxy);
  RuntimeProbeClientImpl(const RuntimeProbeClientImpl&) = delete;
  RuntimeProbeClientImpl& operator=(const RuntimeProbeClientImpl&) = delete;

  ~RuntimeProbeClientImpl() override;

  bool ProbeCategories(const std::vector<RmadComponent>& categories,
                       bool use_customized_identifier,
                       ComponentsWithIdentifier* components) override;
  bool ProbeSsfcComponents(bool use_customized_identifier,
                           ComponentsWithIdentifier* components) override;

 private:
  // The proxy object for runtime_probe dbus service.
  std::unique_ptr<org::chromium::RuntimeProbeProxyInterface>
      runtime_probe_proxy_;
};

}  // namespace rmad

#endif  // RMAD_SYSTEM_RUNTIME_PROBE_CLIENT_IMPL_H_

// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_SYSTEM_RUNTIME_PROBE_CLIENT_H_
#define RMAD_SYSTEM_RUNTIME_PROBE_CLIENT_H_

#include <string>
#include <utility>
#include <vector>

#include <rmad/proto_bindings/rmad.pb.h>

namespace rmad {

using ComponentsWithIdentifier =
    std::vector<std::pair<RmadComponent, std::string>>;

class RuntimeProbeClient {
 public:
  RuntimeProbeClient() = default;
  virtual ~RuntimeProbeClient() = default;

  // Probe the components specified in |categories|, and store their identifiers
  // in |components|.
  //
  // Input parameters:
  //   |categories| - A list of component categories to probe. If it is empty,
  //                  the function probes all categories.
  //   |use_customized_identifier| - Use customized identifier defined by rmad.
  //                                 If the value is false, use the default
  //                                 names in the runtime_probe probe config.
  //
  // Output parameters:
  //   |components| - A list of components with their (category, identifier)
  //                  pair.
  //
  // Returns True if the probing succeeds. Returns False if the probing fails,
  // in this case |components| is not modified.
  virtual bool ProbeCategories(const std::vector<RmadComponent>& categories,
                               bool use_customized_identifier,
                               ComponentsWithIdentifier* components) = 0;

  // Probe the SSFC components, and store their identifiers in |components|.
  //
  // Input parameters:
  //   |use_customized_identifier| - Use customized identifier defined by rmad.
  //                                 If the value is false, use the default
  //                                 names in the runtime_probe probe config.
  //
  // Output parameters:
  //   |components| - A list of components with their (category, identifier)
  //                  pair.
  //
  // Returns True if the probing succeeds. Returns False if the probing fails,
  // in this case |components| is not modified.
  virtual bool ProbeSsfcComponents(bool use_customized_identifier,
                                   ComponentsWithIdentifier* components) = 0;
};

}  // namespace rmad

#endif  // RMAD_SYSTEM_RUNTIME_PROBE_CLIENT_H_

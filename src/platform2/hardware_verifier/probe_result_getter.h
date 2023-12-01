/* Copyright 2019 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef HARDWARE_VERIFIER_PROBE_RESULT_GETTER_H_
#define HARDWARE_VERIFIER_PROBE_RESULT_GETTER_H_

#include <base/files/file_path.h>
#include <optional>
#include <runtime_probe/proto_bindings/runtime_probe.pb.h>

namespace hardware_verifier {

// Interface that provides ways to retrieve |ProbeResult| messages.
class ProbeResultGetter {
 public:
  virtual ~ProbeResultGetter() = default;

  // Gets the |ProbeResult| message by invoking |runtime_probe|.
  //
  // @return A |runtime_probe::ProbeResult| message if it succeeds.
  virtual std::optional<runtime_probe::ProbeResult> GetFromRuntimeProbe()
      const = 0;

  // Gets the |ProbeResult| message from the given file.
  //
  // The extension of the file name must be ".prototxt" and the format of the
  // file content is expected to be protobuf text format.
  //
  // @param file_path: Path to the file thath contains the data.
  //
  // @return A |runtime_probe::ProbeResult| message if it succeeds.
  virtual std::optional<runtime_probe::ProbeResult> GetFromFile(
      const base::FilePath& file_path) const = 0;
};

}  // namespace hardware_verifier

#endif  // HARDWARE_VERIFIER_PROBE_RESULT_GETTER_H_

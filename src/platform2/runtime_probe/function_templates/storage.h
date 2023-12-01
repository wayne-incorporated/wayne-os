// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RUNTIME_PROBE_FUNCTION_TEMPLATES_STORAGE_H_
#define RUNTIME_PROBE_FUNCTION_TEMPLATES_STORAGE_H_

#include <optional>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/values.h>

#include "runtime_probe/probe_function.h"

namespace runtime_probe {

class StorageFunction : public PrivilegedProbeFunction {
  using PrivilegedProbeFunction::PrivilegedProbeFunction;

 public:
  DataType EvalImpl() const final;
  void PostHelperEvalImpl(DataType* result) const final;

 protected:
  // The following are storage-type specific building blocks.
  // Must be implemented on each derived storage probe function class.
  // |node_path| is the sysfs path of the storage device. The functions return a
  // |base::Value| with dictionary type which contains the related information.

  // Probes the information from storage tools. This will be called in
  // |PostHelperEvalImpl| with the permissions to connect to dbus services.
  virtual std::optional<base::Value> ProbeFromStorageTool(
      const base::FilePath& node_path) const = 0;

  // Probes the information from sysfs.
  virtual std::optional<base::Value> ProbeFromSysfs(
      const base::FilePath& node_path) const = 0;
};

}  // namespace runtime_probe

#endif  // RUNTIME_PROBE_FUNCTION_TEMPLATES_STORAGE_H_

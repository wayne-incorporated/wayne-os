// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// A simplified interface to the ML service. Used to implement the ml_cmdline
// tool.

#ifndef ML_SIMPLE_H_
#define ML_SIMPLE_H_

#include <string>

namespace ml {
namespace simple {

// Result of adding two numbers
struct AddResult {
  std::string status;
  double sum;
};

// Add two numbers. Returns result and a status message.
// `use_nnapi` and `use_gpu` cause NNAPI or the TFLite
// GPU delegate to be used when true. These two options
// are mutually exclusive. `gpu_delegate_api_str` specifies
// the specific GPU API to be used by the GPU delegate
// (e.g. OpenGL). The string value should be one of the
// names enumerated in
// `chromeos::machine_learning::mojom::GpuDelegateApi`
// (e.g. "OPENGL").
AddResult Add(double x,
              double y,
              bool use_nnapi,
              bool use_gpu,
              const std::string& gpu_delegate_api_str);

}  // namespace simple
}  // namespace ml

#endif  // ML_SIMPLE_H_

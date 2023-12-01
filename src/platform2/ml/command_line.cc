// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <iostream>

#include <base/at_exit.h>
#include <base/task/single_thread_task_runner.h>
#include <brillo/flag_helper.h>
#include <brillo/message_loops/base_message_loop.h>
#include <mojo/core/embedder/embedder.h>
#include <mojo/core/embedder/scoped_ipc_support.h>

#include "ml/simple.h"

// Starts environment to support Mojo
void StartMojo() {
  (new brillo::BaseMessageLoop())->SetAsCurrent();
  mojo::core::Init();
  mojo::core::ScopedIPCSupport _(
      base::SingleThreadTaskRunner::GetCurrentDefault(),
      mojo::core::ScopedIPCSupport::ShutdownPolicy::FAST);
}

int main(int argc, char** argv) {
  base::AtExitManager at_exit;
  StartMojo();

  // TODO(avg): add flag to specify that NNAPI should be used
  DEFINE_double(x, 1.0, "First operand for add");
  DEFINE_double(y, 4.0, "Second operand for add");
  DEFINE_bool(nnapi, false, "Whether to use NNAPI");
  DEFINE_bool(gpu, false, "Whether to use GPU");
  DEFINE_string(gpu_delegate_api, "OPENGL",
                "Graphics API to use with GPU delegate");
  brillo::FlagHelper::Init(argc, argv, "ML Service commandline tool");

  // TODO(avg): add ability to run arbitrary models
  std::string processing = "CPU";
  if (FLAGS_nnapi)
    processing = "NNAPI";
  if (FLAGS_gpu)
    processing = "GPU";
  std::cout << "Adding " << FLAGS_x << " and " << FLAGS_y << " with "
            << processing;
  if (FLAGS_gpu)
    std::cout << " (API: " << FLAGS_gpu_delegate_api << ")";
  std::cout << std::endl;
  auto result = ml::simple::Add(FLAGS_x, FLAGS_y, FLAGS_nnapi, FLAGS_gpu,
                                FLAGS_gpu_delegate_api);
  std::cout << "Status: " << result.status << std::endl;
  std::cout << "Sum: " << result.sum << std::endl;

  return 0;
}

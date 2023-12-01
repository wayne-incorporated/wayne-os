// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_EXECUTOR_UTILS_DELEGATE_PROCESS_H_
#define DIAGNOSTICS_CROS_HEALTHD_EXECUTOR_UTILS_DELEGATE_PROCESS_H_

#include <string>
#include <vector>

#include <base/memory/weak_ptr.h>
#include <mojo/public/cpp/bindings/remote.h>
#include <mojo/public/cpp/platform/platform_channel.h>
#include <mojo/public/cpp/system/invitation.h>

#include "diagnostics/cros_healthd/executor/utils/sandboxed_process.h"
#include "diagnostics/cros_healthd/mojom/delegate.mojom.h"

namespace diagnostics {

// Run executor delegate.
//
// Argument definition can be found in the following header:
//     cros_healthd/executor/utils/sandboxed_process.h.
//
// Notice:
// 1. Mojo invitation can't be sent when the current thread is dealing with a
// mojo task. This is done when `Start()` is called. A workaround is post a task
// to call `Start()` in same thread, which is what `StartAsync()` does.
//
// 2. The users should be aware of the lifecycle of this object. Once it's
// destroyed, the mojo connection to the delegate will disconnect.
class DelegateProcess : public SandboxedProcess {
 public:
  DelegateProcess(const std::string& seccomp_filename,
                  const SandboxedProcess::Options& options);
  ~DelegateProcess() override;

 public:
  // SandboxedProcess overrides.
  bool Start() override;

  // Start the process async on the same thread.
  void StartAsync();

  auto remote() { return remote_.get(); }

 protected:
  DelegateProcess();

 private:
  void StartAndIgnoreResult();

  mojo::Remote<ash::cros_healthd::mojom::Delegate> remote_;
  mojo::OutgoingInvitation invitation_;
  // Must be the last member of the class.
  base::WeakPtrFactory<DelegateProcess> weak_factory_{this};
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_EXECUTOR_UTILS_DELEGATE_PROCESS_H_

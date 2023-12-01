// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PRINTSCANMGR_EXECUTOR_MOJO_ADAPTOR_H_
#define PRINTSCANMGR_EXECUTOR_MOJO_ADAPTOR_H_

#include <memory>

#include <base/functional/bind.h>
#include <base/memory/weak_ptr.h>
#include <base/task/single_thread_task_runner.h>
#include <dbus/bus.h>
#include <mojo/public/cpp/bindings/pending_receiver.h>
#include <mojo/public/cpp/bindings/receiver.h>

#include "printscanmgr/executor/upstart_tools.h"
#include "printscanmgr/mojom/executor.mojom.h"

namespace printscanmgr {

// Production implementation of the mojom::Executor Mojo interface.
class MojoAdaptor final : public mojom::Executor {
 public:
  MojoAdaptor(
      const scoped_refptr<base::SingleThreadTaskRunner> mojo_task_runner,
      mojo::PendingReceiver<mojom::Executor> receiver,
      base::OnceClosure on_disconnect);
  MojoAdaptor(const MojoAdaptor&) = delete;
  MojoAdaptor& operator=(const MojoAdaptor&) = delete;
  ~MojoAdaptor() override;

  // mojom::Executor overrides:
  void StopUpstartJob(mojom::UpstartJob job,
                      StopUpstartJobCallback callback) override;
  void RestartUpstartJob(mojom::UpstartJob job,
                         RestartUpstartJobCallback callback) override;

 private:
  // Task runner for all Mojo callbacks.
  const scoped_refptr<base::SingleThreadTaskRunner> mojo_task_runner_;

  // Provides a Mojo endpoint that printscanmgr can call to access the
  // executor's Mojo methods.
  mojo::Receiver<mojom::Executor> receiver_;

  scoped_refptr<dbus::Bus> bus_;
  std::unique_ptr<UpstartTools> upstart_tools_ = UpstartTools::Create(bus_);

  // Must be the last member of the class.
  base::WeakPtrFactory<MojoAdaptor> weak_factory_{this};
};

}  // namespace printscanmgr

#endif  // PRINTSCANMGR_EXECUTOR_MOJO_ADAPTOR_H_

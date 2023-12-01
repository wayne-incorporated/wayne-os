// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec/middleware/middleware_owner.h"

#include <memory>
#include <optional>
#include <utility>

#include <base/functional/callback.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <libhwsec-foundation/tpm/tpm_version.h>

#include "libhwsec/backend/backend.h"
#include "libhwsec/middleware/middleware.h"
#include "libhwsec/proxy/proxy_impl.h"
#include "libhwsec/status.h"

#if USE_TPM2
#include "libhwsec/backend/tpm2/backend.h"
#endif

#if USE_TPM1
#include "libhwsec/backend/tpm1/backend.h"
#endif

namespace {
constexpr char kThreadName[] = "libhwsec_thread";

scoped_refptr<base::TaskRunner> GetCurrentTaskRunnerOrNullptr() {
  return base::SequencedTaskRunner::HasCurrentDefault()
             ? base::SequencedTaskRunner::GetCurrentDefault()
             : nullptr;
}
}  // namespace

namespace hwsec {

MiddlewareOwner::MiddlewareOwner(ThreadingMode mode) {
  InitThreadingMode(mode);

  base::OnceClosure task =
      base::BindOnce(&MiddlewareOwner::InitBackend, weak_factory_.GetWeakPtr());
  Middleware(Derive()).RunBlockingTask(std::move(task));
}

MiddlewareOwner::MiddlewareOwner(std::unique_ptr<Backend> custom_backend,
                                 ThreadingMode mode) {
  InitThreadingMode(mode);

  base::OnceClosure task =
      base::BindOnce(&MiddlewareOwner::InitWithCustomBackend,
                     weak_factory_.GetWeakPtr(), std::move(custom_backend));
  Middleware(Derive()).RunBlockingTask(std::move(task));
}

void MiddlewareOwner::InitThreadingMode(ThreadingMode mode) {
  if (mode == ThreadingMode::kStandaloneWorkerThread) {
    background_thread_ = std::make_unique<base::Thread>(kThreadName);
    background_thread_->StartWithOptions(
        base::Thread::Options(base::MessagePumpType::IO, 0));
    task_runner_ = background_thread_->task_runner();
    thread_id_ = background_thread_->GetThreadId();
  } else {
    task_runner_ = GetCurrentTaskRunnerOrNullptr();
    thread_id_ = base::PlatformThread::CurrentId();
  }
}

MiddlewareOwner::~MiddlewareOwner() {
  // Post blocking task if we the backend thread had been initialized.
  if (thread_id_ != base::kInvalidThreadId) {
    base::OnceClosure task = base::BindOnce(&MiddlewareOwner::FiniBackend,
                                            weak_factory_.GetWeakPtr());
    task = std::move(task).Then(base::BindOnce(
        &base::WeakPtrFactory<MiddlewareOwner>::InvalidateWeakPtrs,
        base::Unretained(&weak_factory_)));
    Middleware(Derive()).RunBlockingTask(std::move(task));
  }
}

MiddlewareDerivative MiddlewareOwner::Derive() {
  return MiddlewareDerivative{
      .task_runner = task_runner_,
      .thread_id = thread_id_,
      .middleware = weak_factory_.GetWeakPtr(),
  };
}

void MiddlewareOwner::InitBackend() {
  CHECK(!backend_) << "Should not init backend twice.";

  if (thread_id_ == base::kInvalidThreadId) {
    thread_id_ = base::PlatformThread::CurrentId();
  }

  metrics_ = std::make_unique<Metrics>();

  TPM_SELECT_BEGIN;
  TPM1_SECTION({
    auto proxy = std::make_unique<ProxyImpl>();
    if (!proxy->Init()) {
      LOG(ERROR) << "Failed to init hwsec proxy";
      return;
    }
    proxy_ = std::move(proxy);
    backend_ = std::make_unique<BackendTpm1>(*proxy_, Derive());
  });
  TPM2_SECTION({
    auto proxy = std::make_unique<ProxyImpl>();
    if (!proxy->Init()) {
      LOG(ERROR) << "Failed to init hwsec proxy";
      return;
    }
    proxy_ = std::move(proxy);
    backend_ = std::make_unique<BackendTpm2>(*proxy_, Derive());
  });
  OTHER_TPM_SECTION({
    LOG(ERROR) << "Calling on unsupported TPM platform.";
    return;
  });
  TPM_SELECT_END;
}

void MiddlewareOwner::InitWithCustomBackend(
    std::unique_ptr<Backend> custom_backend) {
  CHECK(!backend_) << "Should not init backend twice.";

  if (thread_id_ == base::kInvalidThreadId) {
    thread_id_ = base::PlatformThread::CurrentId();
  }

  // Note: The metrics and proxy is meaningless with the custom backend, so we
  // don't init them here.

  backend_ = std::move(custom_backend);
}

void MiddlewareOwner::FiniBackend() {
  backend_.reset();
  proxy_.reset();
  metrics_.reset();
}

}  // namespace hwsec

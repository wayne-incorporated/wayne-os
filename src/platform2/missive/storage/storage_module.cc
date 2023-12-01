// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "missive/storage/storage_module.h"

#include <algorithm>
#include <memory>
#include <string>
#include <utility>

#include <base/containers/span.h>
#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <base/memory/ptr_util.h>
#include <base/memory/scoped_refptr.h>
#include <base/task/thread_pool.h>

#include "base/check.h"
#include "base/functional/callback_forward.h"
#include "base/location.h"
#include "base/sequence_checker.h"
#include "base/task/bind_post_task.h"
#include "missive/compression/compression_module.h"
#include "missive/encryption/encryption_module_interface.h"
#include "missive/proto/record.pb.h"
#include "missive/proto/record_constants.pb.h"
#include "missive/storage/new_storage.h"
#include "missive/storage/storage.h"
#include "missive/storage/storage_base.h"
#include "missive/storage/storage_configuration.h"
#include "missive/storage/storage_module_interface.h"
#include "missive/storage/storage_uploader_interface.h"
#include "missive/util/dynamic_flag.h"
#include "missive/util/status.h"
#include "missive/util/status_macros.h"
#include "missive/util/statusor.h"

namespace reporting {

const Status kStorageUnavailableStatus =
    Status(error::UNAVAILABLE, "Storage unavailable");

StorageModule::StorageModule(
    const StorageOptions& options,
    bool legacy_storage_enabled,
    UploaderInterface::AsyncStartUploaderCb async_start_upload_cb,
    scoped_refptr<QueuesContainer> queues_container,
    scoped_refptr<EncryptionModuleInterface> encryption_module,
    scoped_refptr<CompressionModule> compression_module,
    scoped_refptr<SignatureVerificationDevFlag> signature_verification_dev_flag)
    : DynamicFlag("legacy_storage_enabled", legacy_storage_enabled),
      sequenced_task_runner_(base::ThreadPool::CreateSequencedTaskRunner(
          {base::TaskPriority::BEST_EFFORT, base::MayBlock()})),
      options_(options),
      async_start_upload_cb_(async_start_upload_cb),
      queues_container_(queues_container),
      encryption_module_(encryption_module),
      compression_module_(compression_module),
      signature_verification_dev_flag_(signature_verification_dev_flag) {
  // Constructor may be called on any thread.
  DETACH_FROM_SEQUENCE(sequence_checker_);
}

StorageModule::~StorageModule() = default;

void StorageModule::AddRecord(Priority priority,
                              Record record,
                              EnqueueCallback callback) {
  sequenced_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(
                     [](scoped_refptr<StorageModule> self, Priority priority,
                        Record record, EnqueueCallback callback) {
                       DCHECK_CALLED_ON_VALID_SEQUENCE(self->sequence_checker_);
                       if (!(self->storage_)) {
                         std::move(callback).Run(kStorageUnavailableStatus);
                         return;
                       }
                       self->storage_->Write(priority, std::move(record),
                                             std::move(callback));
                     },
                     base::WrapRefCounted(this), priority, std::move(record),
                     std::move(callback)));
}

void StorageModule::Flush(Priority priority, FlushCallback callback) {
  sequenced_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(
          [](scoped_refptr<StorageModule> self, Priority priority,
             FlushCallback callback) {
            DCHECK_CALLED_ON_VALID_SEQUENCE(self->sequence_checker_);
            if (!(self->storage_)) {
              std::move(callback).Run(kStorageUnavailableStatus);
              return;
            }
            self->storage_->Flush(priority, std::move(callback));
          },
          base::WrapRefCounted(this), priority, std::move(callback)));
}

void StorageModule::ReportSuccess(SequenceInformation sequence_information,
                                  bool force) {
  sequenced_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(
          [](scoped_refptr<StorageModule> self,
             SequenceInformation sequence_information, bool force) {
            DCHECK_CALLED_ON_VALID_SEQUENCE(self->sequence_checker_);
            if (!(self->storage_)) {
              LOG(ERROR) << kStorageUnavailableStatus.error_message();
              return;
            }
            self->storage_->Confirm(
                std::move(sequence_information), force,
                base::BindOnce([](Status status) {
                  LOG_IF(ERROR, !status.ok())
                      << "Unable to confirm record deletion: " << status;
                }));
          },
          base::WrapRefCounted(this), std::move(sequence_information), force));
}

void StorageModule::UpdateEncryptionKey(
    SignedEncryptionInfo signed_encryption_key) {
  sequenced_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(
          [](scoped_refptr<StorageModule> self,
             SignedEncryptionInfo signed_encryption_key) {
            DCHECK_CALLED_ON_VALID_SEQUENCE(self->sequence_checker_);
            if (!(self->storage_)) {
              LOG(ERROR) << kStorageUnavailableStatus.error_message();
              return;
            }
            self->storage_->UpdateEncryptionKey(
                std::move(signed_encryption_key));
          },
          base::WrapRefCounted(this), std::move(signed_encryption_key)));
}

// static
void StorageModule::Create(
    const StorageOptions& options,
    bool legacy_storage_enabled,
    UploaderInterface::AsyncStartUploaderCb async_start_upload_cb,
    scoped_refptr<QueuesContainer> queues_container,
    scoped_refptr<EncryptionModuleInterface> encryption_module,
    scoped_refptr<CompressionModule> compression_module,
    scoped_refptr<SignatureVerificationDevFlag> signature_verification_dev_flag,
    base::OnceCallback<void(StatusOr<scoped_refptr<StorageModule>>)> callback) {
  // Call constructor.
  scoped_refptr<StorageModule> instance =
      // Cannot use `base::MakeRefCounted`, since constructor is protected.
      base::WrapRefCounted(new StorageModule(
          options, legacy_storage_enabled, async_start_upload_cb,
          queues_container, encryption_module, compression_module,
          signature_verification_dev_flag));

  // Initialize `instance`.
  InitAsync(instance, legacy_storage_enabled, std::move(callback)).Run();
}

// static
base::OnceClosure StorageModule::InitAsync(
    scoped_refptr<StorageModule> instance,
    bool legacy_storage_enabled,
    base::OnceCallback<void(StatusOr<scoped_refptr<StorageModule>>)> callback) {
  return VerifyQueuesAreEmptyAsync(instance->queues_container_)
      .Then(InitStorageAsync(instance, legacy_storage_enabled,
                             std::move(callback)));
}

// static
base::OnceClosure StorageModule::VerifyQueuesAreEmptyAsync(
    scoped_refptr<QueuesContainer> queues_container) {
  return base::BindPostTask(
      queues_container->sequenced_task_runner(),
      base::BindOnce(
          [](scoped_refptr<QueuesContainer> queues_container) {
            CHECK(queues_container);
            CHECK(queues_container->IsEmpty());
          },
          queues_container));
}

// static
base::OnceClosure StorageModule::InitStorageAsync(
    scoped_refptr<StorageModule> instance,
    bool legacy_storage_enabled,
    base::OnceCallback<void(StatusOr<scoped_refptr<StorageModule>>)> callback) {
  return base::BindPostTask(
      instance->sequenced_task_runner_,
      base::BindOnce(
          [](scoped_refptr<StorageModule> self, bool legacy_storage_enabled,
             base::OnceCallback<void(StatusOr<scoped_refptr<StorageModule>>)>
                 callback) {
            // Partially bound callback which sets `storage_` or returns an
            // error status via `callback`. Run on `sequenced_task_runner_`.
            auto set_storage_cb =
                base::BindPostTask(self->sequenced_task_runner_,
                                   base::BindOnce(&StorageModule::SetStorage,
                                                  self, std::move(callback)));

            // Select Storage implementation.
            if (legacy_storage_enabled) {
              Storage::Create(self->options_, self->async_start_upload_cb_,
                              self->queues_container_, self->encryption_module_,
                              self->compression_module_,
                              self->signature_verification_dev_flag_,
                              std::move(set_storage_cb));
            } else {
              NewStorage::Create(self->options_, self->async_start_upload_cb_,
                                 self->queues_container_,
                                 self->encryption_module_,
                                 self->compression_module_,
                                 self->signature_verification_dev_flag_,
                                 std::move(set_storage_cb));
            }
          },
          instance, legacy_storage_enabled, std::move(callback)));
}

void StorageModule::SetStorage(
    base::OnceCallback<void(StatusOr<scoped_refptr<StorageModule>>)> callback,
    StatusOr<scoped_refptr<StorageInterface>> storage) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (!storage.ok()) {
    std::move(callback).Run(storage.status());
    return;
  }
  storage_ = storage.ValueOrDie();
  std::move(callback).Run(base::WrapRefCounted(this));
}

bool StorageModule::legacy_storage_enabled() const {
  return is_enabled();
}

void StorageModule::OnValueUpdate(bool is_enabled) {
  sequenced_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(
          [](scoped_refptr<StorageModule> self, bool is_enabled) {
            // Callback for when `InitStorageAsync()` completed. This is just
            // base::DoNothing() unless
            // `RegisterOnStorageSetCallbackForTesting()` has been called.
            auto when_set_storage_complete =
                self->on_storage_set_cb_for_testing_
                    ? std::move(self->on_storage_set_cb_for_testing_)
                    : base::DoNothing();

            self->storage_->RegisterCompletionCallback(InitAsync(
                self, is_enabled, std::move(when_set_storage_complete)));

            // Drop reference to `Storage` object. At some point in the near
            // future the registered callback above should trigger once
            // remaining references are dropped from any scheduled tasks.
            self->storage_.reset();
          },
          base::WrapRefCounted(this), std::move(is_enabled)));
}

void StorageModule::RegisterOnStorageSetCallbackForTesting(
    base::OnceCallback<void(StatusOr<scoped_refptr<StorageModule>>)> callback) {
  sequenced_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(
          [](scoped_refptr<StorageModule> self,
             base::OnceCallback<void(StatusOr<scoped_refptr<StorageModule>>)>
                 callback) {
            self->on_storage_set_cb_for_testing_ = std::move(callback);
          },
          base::WrapRefCounted(this), std::move(callback)));
}

void StorageModule::GetStorageImplNameForTesting(
    base::OnceCallback<void(const char*)> callback) const {
  sequenced_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(
          [](scoped_refptr<const StorageModule> self,
             base::OnceCallback<void(const char*)> callback) {
            std::move(callback).Run(self->storage_->ImplNameForTesting());
          },
          base::WrapRefCounted(this), std::move(callback)));
}

void StorageModule::InjectStorageUnavailableErrorForTesting() {
  storage_.reset();
}

}  // namespace reporting

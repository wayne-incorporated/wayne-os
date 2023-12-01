// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "missive/storage/storage.h"

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/barrier_closure.h>
#include <base/check.h>
#include <base/containers/adapters.h>
#include <base/files/file.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/platform_file.h>
#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/location.h>
#include <base/logging.h>
#include <base/memory/scoped_refptr.h>
#include <base/sequence_checker.h>
#include <base/strings/strcat.h>
#include <base/strings/string_number_conversions.h>
#include <base/task/bind_post_task.h>
#include <base/task/sequenced_task_runner.h>
#include <base/task/task_runner.h>
#include <base/task/task_traits.h>
#include <base/task/thread_pool.h>
#include <base/threading/thread.h>
#include <base/time/time.h>
#include <google/protobuf/io/zero_copy_stream_impl.h>

#include "missive/analytics/metrics.h"
#include "missive/compression/compression_module.h"
#include "missive/encryption/encryption_module_interface.h"
#include "missive/encryption/primitives.h"
#include "missive/encryption/verification.h"
#include "missive/proto/record.pb.h"
#include "missive/proto/record_constants.pb.h"
#include "missive/resources/resource_manager.h"
#include "missive/storage/storage_base.h"
#include "missive/storage/storage_configuration.h"
#include "missive/storage/storage_queue.h"
#include "missive/storage/storage_uploader_interface.h"
#include "missive/util/file.h"
#include "missive/util/status.h"
#include "missive/util/status_macros.h"
#include "missive/util/statusor.h"
#include "missive/util/task_runner_context.h"

namespace reporting {

void Storage::Create(
    const StorageOptions& options,
    UploaderInterface::AsyncStartUploaderCb async_start_upload_cb,
    scoped_refptr<QueuesContainer> queues_container,
    scoped_refptr<EncryptionModuleInterface> encryption_module,
    scoped_refptr<CompressionModule> compression_module,
    scoped_refptr<SignatureVerificationDevFlag> signature_verification_dev_flag,
    base::OnceCallback<void(StatusOr<scoped_refptr<StorageInterface>>)>
        completion_cb) {
  // Initialize Storage object, populating all the queues.
  class StorageInitContext
      : public TaskRunnerContext<StatusOr<scoped_refptr<StorageInterface>>> {
   public:
    StorageInitContext(
        const StorageOptions::QueuesOptionsList& queues_options,
        scoped_refptr<Storage> storage,
        base::OnceCallback<void(StatusOr<scoped_refptr<StorageInterface>>)>
            callback)
        : TaskRunnerContext<StatusOr<scoped_refptr<StorageInterface>>>(
              std::move(callback),
              storage->sequenced_task_runner_),  // Same runner as the Storage!
          queues_options_(queues_options),
          storage_(std::move(storage)) {}

   private:
    // Context can only be deleted by calling Response method.
    ~StorageInitContext() override {
      DCHECK_CALLED_ON_VALID_SEQUENCE(storage_->sequence_checker_);
      DCHECK_EQ(count_, 0u);
    }

    void OnStart() override {
      CheckOnValidSequence();

      // If encryption is not enabled, proceed with the queues.
      if (!storage_->encryption_module_->is_enabled()) {
        InitAllQueues();
        return;
      }

      // Encryption is enabled. Locate the latest signed_encryption_key file
      // with matching key signature after deserialization.
      const auto download_key_result =
          storage_->key_in_storage_->DownloadKeyFile();
      if (!download_key_result.ok()) {
        // Key not found or corrupt. Proceed with encryption setup.
        // Key will be downloaded during setup.
        EncryptionSetUp(download_key_result.status());
        return;
      }

      // Key found, verified and downloaded.
      storage_->encryption_module_->UpdateAsymmetricKey(
          download_key_result.ValueOrDie().first,
          download_key_result.ValueOrDie().second,
          base::BindPostTaskToCurrentDefault(base::BindOnce(
              &StorageInitContext::EncryptionSetUp, base::Unretained(this))));
    }

    void EncryptionSetUp(Status status) {
      CheckOnValidSequence();

      if (status.ok()) {
        // Encryption key has been found and set up. Must be available now.
        DCHECK(storage_->encryption_module_->has_encryption_key());
      } else {
        LOG(WARNING)
            << "Encryption is enabled, but the key is not available yet, "
               "status="
            << status;

        // Start a task in the background which periodically requests the
        // encryption key if we need it.
        storage_->key_delivery_->StartPeriodicKeyUpdate(
            storage_->options_.key_check_period());
      }

      InitAllQueues();
    }

    void InitAllQueues() {
      CheckOnValidSequence();

      // Construct all queues.
      DCHECK_CALLED_ON_VALID_SEQUENCE(storage_->sequence_checker_);
      count_ = queues_options_.size();
      if (count_ == 0) {
        Response(std::move(storage_));
        return;
      }

      // Create queues the queue directories we found in the storage directory
      for (const auto& queue_options : queues_options_) {
        StorageQueue::Create(
            GenerationGuid(),
            /*options=*/queue_options.second,
            // Note: the callbacks below are attached to the Queue and do not
            // outlive Storage, so they cannot refer to `storage_` itself!
            base::BindRepeating(&QueueUploaderInterface::AsyncProvideUploader,
                                /*priority=*/queue_options.first,
                                storage_->async_start_upload_cb_,
                                storage_->encryption_module_),
            // `queues_container_` refers a weak pointer only, so that its
            // callback does not hold a reference to it.
            base::BindPostTask(
                storage_->sequenced_task_runner_,
                base::BindRepeating(&QueuesContainer::GetDegradationCandidates,
                                    storage_->queues_container_->GetWeakPtr(),
                                    /*priority=*/queue_options.first)),
            storage_->encryption_module_, storage_->compression_module_,
            base::BindRepeating(&StorageQueue::MaybeBackoffAndReInit),
            base::BindPostTaskToCurrentDefault(base::BindOnce(
                &StorageInitContext::AddQueue, base::Unretained(this),
                /*priority=*/queue_options.first)));
      }
    }

    void AddQueue(Priority priority,
                  StatusOr<scoped_refptr<StorageQueue>> storage_queue_result) {
      CheckOnValidSequence();
      DCHECK_CALLED_ON_VALID_SEQUENCE(storage_->sequence_checker_);
      if (storage_queue_result.ok()) {
        auto add_status = storage_->queues_container_->AddQueue(
            priority, storage_queue_result.ValueOrDie());
        if (final_status_.ok()) {
          final_status_ = add_status;
        }
      } else {
        LOG(ERROR) << "Could not create queue, priority=" << priority
                   << ", status=" << storage_queue_result.status();
        if (final_status_.ok()) {
          final_status_ = storage_queue_result.status();
        }
      }
      DCHECK_GT(count_, 0u);
      if (--count_ > 0u) {
        return;
      }
      if (!final_status_.ok()) {
        Response(final_status_);
        return;
      }
      Response(std::move(storage_));
    }

    const StorageOptions::QueuesOptionsList queues_options_;
    const scoped_refptr<Storage> storage_;
    size_t count_ GUARDED_BY_CONTEXT(storage_->sequence_checker_) = 0;
    Status final_status_;
  };

  // Create Storage object.
  // Cannot use base::MakeRefCounted<Storage>, because constructor is private.
  scoped_refptr<Storage> storage = base::WrapRefCounted(new Storage(
      options, queues_container, encryption_module, compression_module,
      signature_verification_dev_flag, std::move(async_start_upload_cb)));

  // Asynchronously run initialization.
  Start<StorageInitContext>(options.ProduceQueuesOptionsList(),
                            std::move(storage), std::move(completion_cb));
}

Storage::Storage(
    const StorageOptions& options,
    scoped_refptr<QueuesContainer> queues_container,
    scoped_refptr<EncryptionModuleInterface> encryption_module,
    scoped_refptr<CompressionModule> compression_module,
    scoped_refptr<SignatureVerificationDevFlag> signature_verification_dev_flag,
    UploaderInterface::AsyncStartUploaderCb async_start_upload_cb)
    : StorageInterface(queues_container,
                       queues_container->sequenced_task_runner()),
      options_(options),
      encryption_module_(encryption_module),
      key_delivery_(
          KeyDelivery::Create(encryption_module, async_start_upload_cb)),
      compression_module_(compression_module),
      key_in_storage_(std::make_unique<KeyInStorage>(
          options.signature_verification_public_key(),
          signature_verification_dev_flag,
          options.directory())),
      async_start_upload_cb_(async_start_upload_cb) {
  DETACH_FROM_SEQUENCE(sequence_checker_);
}

const char* Storage::ImplNameForTesting() const {
  return kLegacyStorageName;
}

void Storage::Write(Priority priority,
                    Record record,
                    base::OnceCallback<void(Status)> completion_cb) {
  AsyncGetQueueAndProceed(
      priority,
      base::BindOnce(
          [](scoped_refptr<Storage> self, Priority priority, Record record,
             scoped_refptr<StorageQueue> queue,
             base::OnceCallback<void(Status)> completion_cb) {
            if (self->encryption_module_->is_enabled() &&
                !self->encryption_module_->has_encryption_key()) {
              // Key was not found at startup time. Note that if the key is
              // outdated, we still can't use it, and won't load it now. So
              // this processing can only happen after Storage is initialized
              // (until the first successful delivery of a key). After that we
              // will resume the write into the queue.
              KeyDelivery::RequestCallback action = base::BindOnce(
                  [](scoped_refptr<StorageQueue> queue, Record record,
                     base::OnceCallback<void(Status)> completion_cb,
                     Status status) {
                    if (!status.ok()) {
                      std::move(completion_cb).Run(status);
                      return;
                    }
                    queue->Write(std::move(record), std::move(completion_cb));
                  },
                  queue, std::move(record), std::move(completion_cb));
              self->key_delivery_->Request(std::move(action));
              return;
            }
            // Otherwise we can write into the queue right away.
            queue->Write(std::move(record), std::move(completion_cb));
          },
          base::WrapRefCounted(this), priority, std::move(record)),
      std::move(completion_cb));
}

void Storage::Confirm(SequenceInformation sequence_information,
                      bool force,
                      base::OnceCallback<void(Status)> completion_cb) {
  const Priority priority = sequence_information.priority();
  AsyncGetQueueAndProceed(
      priority,
      base::BindOnce(
          [](SequenceInformation sequence_information, bool force,
             scoped_refptr<StorageQueue> queue,
             base::OnceCallback<void(Status)> completion_cb) {
            queue->Confirm(std::move(sequence_information), force,
                           std::move(completion_cb));
          },
          std::move(sequence_information), force),
      std::move(completion_cb));
}

void Storage::Flush(Priority priority,
                    base::OnceCallback<void(Status)> completion_cb) {
  AsyncGetQueueAndProceed(
      priority,
      base::BindOnce([](scoped_refptr<StorageQueue> queue,
                        base::OnceCallback<void(Status)> completion_cb) {
        queue->Flush(std::move(completion_cb));
      }),
      std::move(completion_cb));
}

void Storage::UpdateEncryptionKey(SignedEncryptionInfo signed_encryption_key) {
  // Verify received key signature. Bail out if failed.
  const auto signature_verification_status =
      key_in_storage_->VerifySignature(signed_encryption_key);
  if (!signature_verification_status.ok()) {
    LOG(WARNING) << "Key failed verification, status="
                 << signature_verification_status;
    key_delivery_->OnCompletion(signature_verification_status);
    return;
  }

  // Assign the received key to encryption module.
  encryption_module_->UpdateAsymmetricKey(
      signed_encryption_key.public_asymmetric_key(),
      signed_encryption_key.public_key_id(),
      base::BindOnce(
          [](scoped_refptr<Storage> storage, Status status) {
            if (!status.ok()) {
              LOG(WARNING) << "Encryption key update failed, status=" << status;
              storage->key_delivery_->OnCompletion(status);
              return;
            }
            // Encryption key updated successfully.
            storage->key_delivery_->OnCompletion(Status::StatusOK());
          },
          base::WrapRefCounted(this)));

  // Serialize whole signed_encryption_key to a new file, discard the old
  // one(s). Do it on a thread which may block doing file operations.
  base::ThreadPool::PostTask(
      FROM_HERE, {base::TaskPriority::BEST_EFFORT, base::MayBlock()},
      base::BindOnce(
          [](SignedEncryptionInfo signed_encryption_key,
             scoped_refptr<Storage> storage) {
            const Status status =
                storage->key_in_storage_->UploadKeyFile(signed_encryption_key);
            LOG_IF(ERROR, !status.ok())
                << "Failed to upload the new encription key.";
          },
          std::move(signed_encryption_key), base::WrapRefCounted(this)));
}

void Storage::AsyncGetQueueAndProceed(
    Priority priority,
    base::OnceCallback<void(scoped_refptr<StorageQueue>,
                            base::OnceCallback<void(Status)>)> queue_action,
    base::OnceCallback<void(Status)> completion_cb) {
  sequenced_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(
          [](scoped_refptr<QueuesContainer> queues_container, Priority priority,
             base::OnceCallback<void(scoped_refptr<StorageQueue>,
                                     base::OnceCallback<void(Status)>)>
                 queue_action,
             base::OnceCallback<void(Status)> completion_cb) {
            // Attempt to get queue by priority on the Storage task runner.
            auto queue_result =
                queues_container->GetQueue(priority, GenerationGuid());
            if (!queue_result.ok()) {
              // Queue not found, abort.
              std::move(completion_cb).Run(queue_result.status());
              return;
            }
            // Queue found, execute the action (it should relocate on
            // queue thread soon, to not block Storage task runner).
            std::move(queue_action)
                .Run(queue_result.ValueOrDie(), std::move(completion_cb));
          },
          queues_container_, priority, std::move(queue_action),
          std::move(completion_cb)));
}

void Storage::RegisterCompletionCallback(base::OnceClosure callback) {
  // Although this is an asynchronous action, note that Storage cannot be
  // destructed until the callback is registered - QueuesContainer owns
  // a reference to each StorageQueue and is itself held by an added
  // reference here. Thus, the callback being registered is guaranteed
  // to be called when the Storage is being destructed.
  DCHECK(callback);
  sequenced_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&QueuesContainer::RegisterCompletionCallback,
                                queues_container_, std::move(callback)));
}
}  // namespace reporting

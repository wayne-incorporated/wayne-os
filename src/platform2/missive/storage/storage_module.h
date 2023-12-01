// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MISSIVE_STORAGE_STORAGE_MODULE_H_
#define MISSIVE_STORAGE_STORAGE_MODULE_H_

#include <memory>
#include <queue>
#include <string>

#include <base/functional/callback.h>
#include <base/functional/callback_forward.h>
#include <base/memory/ref_counted.h>
#include <base/memory/scoped_refptr.h>
#include <base/task/sequenced_task_runner.h>

#include "base/functional/callback_helpers.h"
#include "missive/compression/compression_module.h"
#include "missive/encryption/encryption_module_interface.h"
#include "missive/encryption/verification.h"
#include "missive/proto/record.pb.h"
#include "missive/proto/record_constants.pb.h"
#include "missive/storage/storage.h"
#include "missive/storage/storage_configuration.h"
#include "missive/storage/storage_module_interface.h"
#include "missive/storage/storage_uploader_interface.h"
#include "missive/util/dynamic_flag.h"
#include "missive/util/status.h"
#include "missive/util/statusor.h"

namespace reporting {

class StorageModule : public StorageModuleInterface, public DynamicFlag {
 public:
  // Factory method creates |StorageModule| object.
  static void Create(
      const StorageOptions& options,
      bool legacy_storage_enabled,
      UploaderInterface::AsyncStartUploaderCb async_start_upload_cb,
      scoped_refptr<QueuesContainer> queues_container,
      scoped_refptr<EncryptionModuleInterface> encryption_module,
      scoped_refptr<CompressionModule> compression_module,
      scoped_refptr<SignatureVerificationDevFlag>
          signature_verification_dev_flag,
      base::OnceCallback<void(StatusOr<scoped_refptr<StorageModule>>)>
          callback);

  StorageModule(const StorageModule& other) = delete;
  StorageModule& operator=(const StorageModule& other) = delete;

  // AddRecord will add |record| (taking ownership) to the |StorageModule|
  // according to the provided |priority|. On completion, |callback| will be
  // called.
  void AddRecord(Priority priority,
                 Record record,
                 EnqueueCallback callback) override;

  // Initiates upload of collected records according to the priority.
  // Called usually for a queue with an infinite or very large upload period.
  // Multiple |Flush| calls can safely run in parallel.
  // Returns error if cannot start upload.
  void Flush(Priority priority, FlushCallback callback) override;

  // Once a record has been successfully uploaded, the sequence information
  // can be passed back to the StorageModule here for record deletion.
  // If |force| is false (which is used in most cases), |sequence_information|
  // only affects Storage if no higher sequencing was confirmed before;
  // otherwise it is accepted unconditionally.
  // Declared virtual for testing purposes.
  virtual void ReportSuccess(SequenceInformation sequence_information,
                             bool force);

  // If the server attached signed encryption key to the response, it needs to
  // be paased here.
  // Declared virtual for testing purposes.
  virtual void UpdateEncryptionKey(SignedEncryptionInfo signed_encryption_key);

  bool legacy_storage_enabled() const;

 protected:
  // Constructor can only be called by |Create| factory method.
  explicit StorageModule(
      const StorageOptions& options,
      bool legacy_storage_enabled,
      UploaderInterface::AsyncStartUploaderCb async_start_upload_cb,
      scoped_refptr<QueuesContainer> queues_container,
      scoped_refptr<EncryptionModuleInterface> encryption_module,
      scoped_refptr<CompressionModule> compression_module,
      scoped_refptr<SignatureVerificationDevFlag>
          signature_verification_dev_flag);

  // Refcounted object must have destructor declared protected or private.
  ~StorageModule() override;

  // Returns a callback that verifies that `instance->queues_container_`
  // contains no queue references and then initializes `instance->storage_`.
  [[nodiscard("Call .Run() on return value.")]] static base::OnceClosure
  InitAsync(scoped_refptr<StorageModule> instance,
            bool legacy_storage_enabled,
            base::OnceCallback<void(StatusOr<scoped_refptr<StorageModule>>)>
                callback);

  // Returns a callback that checks (on `queues_container`s task runner)
  // whether `queues_container` holds any references to any `StorageQueue`.
  [[nodiscard("Call .Run() on return value.")]] static base::OnceClosure
  VerifyQueuesAreEmptyAsync(scoped_refptr<QueuesContainer> queues_container);

  // Returns a callback that initializes `instance->storage_`.
  [[nodiscard("Call .Run() on return value.")]] static base::OnceClosure
  InitStorageAsync(
      scoped_refptr<StorageModule> instance,
      bool legacy_storage_enabled,
      base::OnceCallback<void(StatusOr<scoped_refptr<StorageModule>>)>
          callback);

  // Sets `storage_` to a valid `StorageInterface` or returns error status via
  // `callback`.
  void SetStorage(
      base::OnceCallback<void(StatusOr<scoped_refptr<StorageModule>>)> callback,
      StatusOr<scoped_refptr<StorageInterface>> storage);

  // Stores `callback` to be called when `StorageModule::InitStorageAsync` is
  // complete. Used only for testing.
  void RegisterOnStorageSetCallbackForTesting(
      base::OnceCallback<void(StatusOr<scoped_refptr<StorageModule>>)>
          callback);

  // Returns the name of the implementation of `storage_` via `callback`. Used
  // for testing.
  void GetStorageImplNameForTesting(
      base::OnceCallback<void(const char*)> callback) const;

  void InjectStorageUnavailableErrorForTesting();

 private:
  friend class StorageModuleTest;
  friend base::RefCountedThreadSafe<StorageModule>;

  // Task runner for serializing storage operations and setting internal
  // state.
  const scoped_refptr<base::SequencedTaskRunner> sequenced_task_runner_;
  SEQUENCE_CHECKER(sequence_checker_);

  // Called when DynamicFlag flips.
  void OnValueUpdate(bool is_enabled) override;

  // Reference to `Storage` object.
  // Note: all accesses to `storage_` should be done on StorageModule's
  // sequenced task runner since via StorageModule::AsyncSetStorage may change
  // the object `storage_` points to.
  scoped_refptr<StorageInterface> storage_
      GUARDED_BY_CONTEXT(sequence_checker_);

  // Parameters used to create Storage
  const StorageOptions options_;
  const UploaderInterface::AsyncStartUploaderCb async_start_upload_cb_;
  const scoped_refptr<QueuesContainer> queues_container_;
  const scoped_refptr<EncryptionModuleInterface> encryption_module_;
  const scoped_refptr<CompressionModule> compression_module_;
  const scoped_refptr<SignatureVerificationDevFlag>
      signature_verification_dev_flag_;

  // Callback for testing the result of `AsyncSetStorage` function.
  base::OnceCallback<void(StatusOr<scoped_refptr<StorageModule>>)>
      on_storage_set_cb_for_testing_;
};

}  // namespace reporting

#endif  // MISSIVE_STORAGE_STORAGE_MODULE_H_

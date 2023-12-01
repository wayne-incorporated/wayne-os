// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "missive/storage/storage.h"

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <optional>
#include <string>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <vector>

#include <base/files/scoped_temp_dir.h>
#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/sequence_checker.h>
#include <base/strings/strcat.h>
#include <base/strings/string_number_conversions.h>
#include <base/task/sequenced_task_runner.h>
#include <base/task/thread_pool.h>
#include <base/test/task_environment.h>
#include <base/thread_annotations.h>
#include <base/threading/sequence_bound.h>
#include <base/time/time.h>
#include <crypto/sha2.h>
#include <gmock/gmock-matchers.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "base/memory/scoped_refptr.h"
#include "missive/analytics/metrics.h"
#include "missive/analytics/metrics_test_util.h"
#include "missive/compression/compression_module.h"
#include "missive/compression/test_compression_module.h"
#include "missive/encryption/decryption.h"
#include "missive/encryption/encryption.h"
#include "missive/encryption/encryption_module.h"
#include "missive/encryption/encryption_module_interface.h"
#include "missive/encryption/test_encryption_module.h"
#include "missive/encryption/testing_primitives.h"
#include "missive/encryption/verification.h"
#include "missive/proto/record.pb.h"
#include "missive/proto/record_constants.pb.h"
#include "missive/resources/resource_manager.h"
#include "missive/storage/storage_configuration.h"
#include "missive/storage/storage_uploader_interface.h"
#include "missive/util/status.h"
#include "missive/util/status_macros.h"
#include "missive/util/statusor.h"
#include "missive/util/test_support_callbacks.h"

using ::testing::_;
using ::testing::AnyOf;
using ::testing::Args;
using ::testing::AtLeast;
using ::testing::AtMost;
using ::testing::Between;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Gt;
using ::testing::HasSubstr;
using ::testing::Invoke;
using ::testing::Property;
using ::testing::Return;
using ::testing::Sequence;
using ::testing::StrEq;
using ::testing::WithArg;
using ::testing::WithoutArgs;

// TODO(b/278734198): Combine common test logic with new_storage_test.cc
namespace reporting {

namespace {

using TestRecord = std::tuple<Priority, int64_t, std::string>;
using ExpectRecordGroupCallback =
    base::RepeatingCallback<void(std::vector<TestRecord>)>;

//  Returns true if the records in `expected_order` were found in the same
//  (not-necessarily continugous) order in `received_during_test`. Returns
//  false otherwise.
bool RecordsArrivedInExpectedOrder(
    const std::vector<TestRecord> received_during_test,
    const std::vector<TestRecord> expected_order) {
  auto expected = expected_order.begin();
  auto received = received_during_test.begin();

  while (expected != expected_order.end() &&
         received != received_during_test.end()) {
    if (*expected == *received) {
      ++expected;
    }
    ++received;
  }

  return expected == expected_order.end();
}

// Stores an entire upload of records from `SequenceBoundUpload` in the order
// they were received when the upload is declared complete. Intended to be a
// class member of `LegacyStorageTest`, so that it outlives
// `TestUploader` and `SequenceBoundUpload` and can be used to perform checks
// that span multiple separate uploads. The user is responsible for resetting
// the state by calling `Reset()`.
class RecordUploadStore {
 public:
  void Store(std::vector<TestRecord> records) {
    // Mark these records as uploaded
    records_.insert(records_.end(), records.begin(), records.end());
    // Add the entire upload as a whole
    uploads_.emplace_back(std::move(records));
  }
  void Reset() {
    uploads_.clear();
    records_.clear();
  }

  std::vector<std::vector<TestRecord>> Uploads() { return uploads_; }
  std::vector<TestRecord> Records() { return records_; }

 private:
  // List of uploads. Each vector is a distinct upload.
  std::vector<std::vector<TestRecord>> uploads_;
  // Concatenation of all records across all uploads in the order they were
  // received.
  std::vector<TestRecord> records_;
};
constexpr error::Code kKeyDeliveryError = error::FAILED_PRECONDITION;
constexpr char kKeyDeliveryErrorMessage[] = "Test cannot start upload";

// Test uploader counter - for generation of unique ids.
std::atomic<int64_t> next_uploader_id{0};

// Maximum length of debug data prints to prevent excessive output.
static constexpr size_t kDebugDataPrintSize = 16uL;

// Storage options to be used in tests.
class TestStorageOptions : public StorageOptions {
 public:
  TestStorageOptions()
      : StorageOptions(base::BindRepeating(
            &TestStorageOptions::ModifyQueueOptions, base::Unretained(this))) {}

  // Prepare options adjustment.
  // Must be called before the options are used by Storage::Create().
  void set_upload_retry_delay(base::TimeDelta upload_retry_delay) {
    upload_retry_delay_ = upload_retry_delay;
  }

 private:
  void ModifyQueueOptions(Priority /*priority*/,
                          QueueOptions& queue_options) const {
    queue_options.set_upload_retry_delay(upload_retry_delay_);
  }

  base::TimeDelta upload_retry_delay_{
      base::TimeDelta()};  // no retry by default
};

// Context of single decryption. Self-destructs upon completion or failure.
class SingleDecryptionContext {
 public:
  SingleDecryptionContext(
      const EncryptedRecord& encrypted_record,
      scoped_refptr<test::Decryptor> decryptor,
      base::OnceCallback<void(StatusOr<base::StringPiece>)> response)
      : encrypted_record_(encrypted_record),
        decryptor_(decryptor),
        response_(std::move(response)) {}

  SingleDecryptionContext(const SingleDecryptionContext& other) = delete;
  SingleDecryptionContext& operator=(const SingleDecryptionContext& other) =
      delete;

  ~SingleDecryptionContext() {
    DCHECK(!response_) << "Self-destruct without prior response";
  }

  void Start() {
    base::ThreadPool::PostTask(
        FROM_HERE,
        base::BindOnce(&SingleDecryptionContext::RetrieveMatchingPrivateKey,
                       base::Unretained(this)));
  }

 private:
  void Respond(StatusOr<base::StringPiece> result) {
    std::move(response_).Run(result);
    delete this;
  }

  void RetrieveMatchingPrivateKey() {
    // Retrieve private key that matches public key hash.
    decryptor_->RetrieveMatchingPrivateKey(
        encrypted_record_.encryption_info().public_key_id(),
        base::BindOnce(
            [](SingleDecryptionContext* self,
               StatusOr<std::string> private_key_result) {
              if (!private_key_result.ok()) {
                self->Respond(private_key_result.status());
                return;
              }
              base::ThreadPool::PostTask(
                  FROM_HERE,
                  base::BindOnce(&SingleDecryptionContext::DecryptSharedSecret,
                                 base::Unretained(self),
                                 private_key_result.ValueOrDie()));
            },
            base::Unretained(this)));
  }

  void DecryptSharedSecret(base::StringPiece private_key) {
    // Decrypt shared secret from private key and peer public key.
    auto shared_secret_result = decryptor_->DecryptSecret(
        private_key, encrypted_record_.encryption_info().encryption_key());
    if (!shared_secret_result.ok()) {
      Respond(shared_secret_result.status());
      return;
    }
    base::ThreadPool::PostTask(
        FROM_HERE, base::BindOnce(&SingleDecryptionContext::OpenRecord,
                                  base::Unretained(this),
                                  shared_secret_result.ValueOrDie()));
  }

  void OpenRecord(base::StringPiece shared_secret) {
    decryptor_->OpenRecord(
        shared_secret,
        base::BindOnce(
            [](SingleDecryptionContext* self,
               StatusOr<test::Decryptor::Handle*> handle_result) {
              if (!handle_result.ok()) {
                self->Respond(handle_result.status());
                return;
              }
              base::ThreadPool::PostTask(
                  FROM_HERE,
                  base::BindOnce(&SingleDecryptionContext::AddToRecord,
                                 base::Unretained(self),
                                 base::Unretained(handle_result.ValueOrDie())));
            },
            base::Unretained(this)));
  }

  void AddToRecord(test::Decryptor::Handle* handle) {
    handle->AddToRecord(
        encrypted_record_.encrypted_wrapped_record(),
        base::BindOnce(
            [](SingleDecryptionContext* self, test::Decryptor::Handle* handle,
               Status status) {
              if (!status.ok()) {
                self->Respond(status);
                return;
              }
              base::ThreadPool::PostTask(
                  FROM_HERE,
                  base::BindOnce(&SingleDecryptionContext::CloseRecord,
                                 base::Unretained(self),
                                 base::Unretained(handle)));
            },
            base::Unretained(this), base::Unretained(handle)));
  }

  void CloseRecord(test::Decryptor::Handle* handle) {
    handle->CloseRecord(base::BindOnce(
        [](SingleDecryptionContext* self,
           StatusOr<base::StringPiece> decryption_result) {
          self->Respond(decryption_result);
        },
        base::Unretained(this)));
  }

 private:
  const EncryptedRecord encrypted_record_;
  const scoped_refptr<test::Decryptor> decryptor_;
  base::OnceCallback<void(StatusOr<base::StringPiece>)> response_;
};

class LegacyStorageTest
    : public ::testing::TestWithParam<::testing::tuple<bool, size_t>> {
  // Mapping of <generation id, sequencing id> to matching record digest.
  // Whenever a record is uploaded and includes last record digest, this map
  // should have that digest already recorded. Only the first record in a
  // generation is uploaded without last record digest.
  struct LastRecordDigest {
    struct Hash {
      size_t operator()(
          const std::tuple<Priority,
                           int64_t /*generation id*/,
                           int64_t /*sequencing id*/>& v) const noexcept {
        const auto& [priority, generation_id, sequencing_id] = v;
        static constexpr std::hash<Priority> priority_hasher;
        static constexpr std::hash<int64_t> generation_hasher;
        static constexpr std::hash<int64_t> sequencing_hasher;
        return priority_hasher(priority) ^ generation_hasher(generation_id) ^
               sequencing_hasher(sequencing_id);
      }
    };
    using Map = std::unordered_map<std::tuple<Priority,
                                              int64_t /*generation id*/,
                                              int64_t /*sequencing id*/>,
                                   std::optional<std::string /*digest*/>,
                                   Hash>;
  };

  // Track the last uploaded generation id based on priority
  using LastUploadedGenerationIdMap = std::unordered_map<Priority, int64_t>;

 protected:
  void SetUp() override {
    ASSERT_TRUE(location_.CreateUniqueTempDir());
    options_.set_directory(location_.GetPath());

    // Turn uploads to no-ops unless other expectation is set (any later
    // EXPECT_CALL will take precedence over this one).
    EXPECT_CALL(set_mock_uploader_expectations_, Call(_))
        .WillRepeatedly(Invoke([this](UploaderInterface::UploadReason reason) {
          return TestUploader::SetUpDummy(this);
        }));
    ResetExpectedUploadsCount();
    // Prepare encryption, if requested to be enabled.
    if (is_encryption_enabled()) {
      // Generate signing key pair.
      test::GenerateSigningKeyPair(signing_private_key_,
                                   signature_verification_public_key_);
      options_.set_signature_verification_public_key(std::string(
          reinterpret_cast<const char*>(signature_verification_public_key_),
          kKeySize));
      // Create decryption module.
      auto decryptor_result = test::Decryptor::Create();
      ASSERT_OK(decryptor_result.status()) << decryptor_result.status();
      decryptor_ = std::move(decryptor_result.ValueOrDie());
      // Prepare the key.
      signed_encryption_key_ = GenerateAndSignKey();
      // First record enqueue to Storage would need key delivered.
      expect_to_need_key_ = true;
    }
    upload_store_.Reset();
  }

  void TearDown() override {
    ResetTestStorage();
    // Log next uploader id for possible verification.
    LOG(ERROR) << "Next uploader id=" << next_uploader_id.load();
  }

  // Mock class used for setting upload expectations on it.
  class MockUpload {
   public:
    MockUpload() = default;
    virtual ~MockUpload() = default;
    MOCK_METHOD(void,
                EncounterSeqId,
                (int64_t /*uploader_id*/, Priority, int64_t),
                (const));
    MOCK_METHOD(bool,
                UploadRecord,
                (int64_t /*uploader_id*/, Priority, int64_t, base::StringPiece),
                (const));
    MOCK_METHOD(bool,
                UploadRecordFailure,
                (int64_t /*uploader_id*/, Priority, int64_t, Status),
                (const));
    MOCK_METHOD(bool,
                UploadGap,
                (int64_t /*uploader_id*/, Priority, int64_t, uint64_t),
                (const));
    MOCK_METHOD(void,
                UploadComplete,
                (int64_t /*uploader_id*/, Status),
                (const));
  };

  // Helper class to be wrapped in SequenceBound<..>, in order to make sure
  // all its methods are run on a main sequential task wrapper. As a result,
  // collected information and EXPECT_CALLs to MockUpload are safe - executed on
  // the main test thread.
  class SequenceBoundUpload {
   public:
    explicit SequenceBoundUpload(
        std::unique_ptr<const MockUpload> mock_upload,
        LastUploadedGenerationIdMap* const last_upload_generation_id,
        LastRecordDigest::Map* const last_record_digest_map,
        ExpectRecordGroupCallback callback)
        : mock_upload_(std::move(mock_upload)),
          last_upload_generation_id_(last_upload_generation_id),
          last_record_digest_map_(last_record_digest_map),
          expect_record_group_callback_(std::move(callback)) {
      DETACH_FROM_SEQUENCE(scoped_checker_);
      upload_progress_.assign("\nStart\n");
    }
    SequenceBoundUpload(const SequenceBoundUpload& other) = delete;
    SequenceBoundUpload& operator=(const SequenceBoundUpload& other) = delete;
    ~SequenceBoundUpload() { DCHECK_CALLED_ON_VALID_SEQUENCE(scoped_checker_); }

    void ProcessGap(uint64_t uploader_id_,
                    SequenceInformation sequence_information,
                    uint64_t count,
                    base::OnceCallback<void(bool)> processed_cb) {
      DCHECK_CALLED_ON_VALID_SEQUENCE(scoped_checker_);
      // Verify generation match.
      if (generation_id_.has_value() &&
          generation_id_.value() != sequence_information.generation_id()) {
        DoUploadRecordFailure(
            uploader_id_, sequence_information.priority(),
            sequence_information.sequencing_id(),
            sequence_information.generation_id(),
            Status(error::DATA_LOSS,
                   base::StrCat({"Generation id mismatch, expected=",
                                 base::NumberToString(generation_id_.value()),
                                 " actual=",
                                 base::NumberToString(
                                     sequence_information.generation_id())})),
            std::move(processed_cb));
        return;
      }
      if (!generation_id_.has_value()) {
        generation_id_ = sequence_information.generation_id();
        last_upload_generation_id_->emplace(
            sequence_information.priority(),
            sequence_information.generation_id());
      }

      last_record_digest_map_->emplace(
          std::make_tuple(sequence_information.priority(),
                          sequence_information.sequencing_id(),
                          sequence_information.generation_id()),
          std::nullopt);

      DoUploadGap(uploader_id_, sequence_information.priority(),
                  sequence_information.sequencing_id(),
                  sequence_information.generation_id(), count,
                  std::move(processed_cb));
    }

    void VerifyRecord(int64_t uploader_id_,
                      SequenceInformation sequence_information,
                      WrappedRecord wrapped_record,
                      base::OnceCallback<void(bool)> processed_cb) {
      DCHECK_CALLED_ON_VALID_SEQUENCE(scoped_checker_);
      // Verify generation match.
      if (generation_id_.has_value() &&
          generation_id_.value() != sequence_information.generation_id()) {
        DoUploadRecordFailure(
            uploader_id_, sequence_information.priority(),
            sequence_information.sequencing_id(),
            sequence_information.generation_id(),
            Status(error::DATA_LOSS,
                   base::StrCat({"Generation id mismatch, expected=",
                                 base::NumberToString(generation_id_.value()),
                                 " actual=",
                                 base::NumberToString(
                                     sequence_information.generation_id())})),
            std::move(processed_cb));
        return;
      }
      if (!generation_id_.has_value()) {
        generation_id_ = sequence_information.generation_id();
        last_upload_generation_id_->emplace(
            sequence_information.priority(),
            sequence_information.generation_id());
      }

      // Verify digest and its match.
      {
        std::string serialized_record;
        wrapped_record.record().SerializeToString(&serialized_record);
        const auto record_digest = crypto::SHA256HashString(serialized_record);
        DCHECK_EQ(record_digest.size(), crypto::kSHA256Length);
        if (record_digest != wrapped_record.record_digest()) {
          DoUploadRecordFailure(
              uploader_id_, sequence_information.priority(),
              sequence_information.sequencing_id(),
              sequence_information.generation_id(),
              Status(error::DATA_LOSS, "Record digest mismatch"),
              std::move(processed_cb));
          return;
        }
        if (wrapped_record.has_last_record_digest()) {
          auto it = last_record_digest_map_->find(
              std::make_tuple(sequence_information.priority(),
                              sequence_information.sequencing_id() - 1,
                              sequence_information.generation_id()));
          ASSERT_TRUE(it != last_record_digest_map_->end());
          // Previous record has been seen, last record digest must match it.
          if (it->second != wrapped_record.last_record_digest()) {
            DoUploadRecordFailure(
                uploader_id_, sequence_information.priority(),
                sequence_information.sequencing_id(),
                sequence_information.generation_id(),
                Status(error::DATA_LOSS, "Last record digest mismatch"),
                std::move(processed_cb));
            return;
          }
        }
        last_record_digest_map_->emplace(
            std::make_tuple(sequence_information.priority(),
                            sequence_information.sequencing_id(),
                            sequence_information.generation_id()),
            record_digest);
      }

      DoUploadRecord(uploader_id_, sequence_information.priority(),
                     sequence_information.sequencing_id(),
                     sequence_information.generation_id(),
                     wrapped_record.record().data(), std::move(processed_cb));
    }

    void DoEncounterSeqId(int64_t uploader_id,
                          Priority priority,
                          int64_t sequencing_id,
                          int64_t generation_id) {
      DCHECK_CALLED_ON_VALID_SEQUENCE(scoped_checker_);
      upload_progress_.append("SeqId: ")
          .append(base::NumberToString(sequencing_id))
          .append("/")
          .append(base::NumberToString(generation_id))
          .append("\n");
      mock_upload_->EncounterSeqId(uploader_id, priority, sequencing_id);
    }

    void DoUploadRecord(int64_t uploader_id,
                        Priority priority,
                        int64_t sequencing_id,
                        int64_t generation_id,
                        base::StringPiece data,
                        base::OnceCallback<void(bool)> processed_cb) {
      DoEncounterSeqId(uploader_id, priority, sequencing_id, generation_id);
      DCHECK_CALLED_ON_VALID_SEQUENCE(scoped_checker_);
      upload_progress_.append("Record: ")
          .append(base::NumberToString(sequencing_id))
          .append("/")
          .append(base::NumberToString(generation_id))
          .append(" '")
          .append(data.data(), 0, std::min(data.size(), kDebugDataPrintSize))
          .append("'\n");
      std::move(processed_cb)
          .Run(mock_upload_->UploadRecord(uploader_id, priority, sequencing_id,
                                          data));
      records_.emplace_back(priority, sequencing_id, data);
    }

    void DoUploadRecordFailure(int64_t uploader_id,
                               Priority priority,
                               int64_t sequencing_id,
                               int64_t generation_id,
                               Status status,
                               base::OnceCallback<void(bool)> processed_cb) {
      DCHECK_CALLED_ON_VALID_SEQUENCE(scoped_checker_);
      upload_progress_.append("Failure: ")
          .append(base::NumberToString(sequencing_id))
          .append("/")
          .append(base::NumberToString(generation_id))
          .append(" '")
          .append(status.ToString())
          .append("'\n");
      std::move(processed_cb)
          .Run(mock_upload_->UploadRecordFailure(uploader_id, priority,
                                                 sequencing_id, status));
    }

    void DoUploadGap(int64_t uploader_id,
                     Priority priority,
                     int64_t sequencing_id,
                     int64_t generation_id,
                     uint64_t count,
                     base::OnceCallback<void(bool)> processed_cb) {
      DCHECK_CALLED_ON_VALID_SEQUENCE(scoped_checker_);
      for (uint64_t c = 0; c < count; ++c) {
        DoEncounterSeqId(uploader_id, priority,
                         sequencing_id + static_cast<int64_t>(c),
                         generation_id);
      }
      upload_progress_.append("Gap: ")
          .append(base::NumberToString(sequencing_id))
          .append("/")
          .append(base::NumberToString(generation_id))
          .append(" (")
          .append(base::NumberToString(count))
          .append(")\n");
      std::move(processed_cb)
          .Run(mock_upload_->UploadGap(uploader_id, priority, sequencing_id,
                                       count));
    }

    void DoUploadComplete(int64_t uploader_id, Status status) {
      DCHECK_CALLED_ON_VALID_SEQUENCE(scoped_checker_);
      upload_progress_.append("Complete: ")
          .append(status.ToString())
          .append("\n");
      LOG(ERROR) << "TestUploader: " << upload_progress_ << "End\n";
      mock_upload_->UploadComplete(uploader_id, status);
      expect_record_group_callback_.Run(std::move(records_));
    }

   private:
    const std::unique_ptr<const MockUpload> mock_upload_;
    std::optional<int64_t> generation_id_;
    LastUploadedGenerationIdMap* const last_upload_generation_id_;
    LastRecordDigest::Map* const last_record_digest_map_;
    ExpectRecordGroupCallback expect_record_group_callback_;
    std::vector<TestRecord> records_;
    SEQUENCE_CHECKER(scoped_checker_);

    // Snapshot of data received in this upload (for debug purposes).
    std::string upload_progress_;
  };

  // Uploader interface implementation to be assigned to tests.
  // Note that Storage guarantees that all APIs are executed on the same
  // sequenced task runner (not the main test thread!).
  class TestUploader : public UploaderInterface {
   public:
    // Helper class for setting up mock uploader expectations of a successful
    // completion.
    class SetUp {
     public:
      SetUp(Priority priority,
            test::TestCallbackWaiter* waiter,
            LegacyStorageTest* self)
          : priority_(priority),
            uploader_(std::make_unique<TestUploader>(self)),
            uploader_id_(uploader_->uploader_id_),
            waiter_(waiter) {}
      SetUp(const SetUp& other) = delete;
      SetUp& operator=(const SetUp& other) = delete;
      ~SetUp() { CHECK(!uploader_) << "Missed 'Complete' call"; }

      std::unique_ptr<TestUploader> Complete(
          Status status = Status::StatusOK()) {
        CHECK(uploader_) << "'Complete' already called";
        EXPECT_CALL(*uploader_->mock_upload_,
                    UploadRecordFailure(Eq(uploader_id_), _, _, _))
            .Times(0)
            .InSequence(uploader_->test_upload_sequence_);
        EXPECT_CALL(*uploader_->mock_upload_,
                    UploadComplete(Eq(uploader_id_), Eq(status)))
            .InSequence(uploader_->test_upload_sequence_,
                        uploader_->test_encounter_sequence_)
            .WillOnce(DoAll(
                WithoutArgs(Invoke(waiter_, &test::TestCallbackWaiter::Signal)),
                WithoutArgs(
                    Invoke([]() { LOG(ERROR) << "Completion signaled"; }))));
        return std::move(uploader_);
      }

      SetUp& Required(int64_t sequencing_id, base::StringPiece value) {
        CHECK(uploader_) << "'Complete' already called";
        EXPECT_CALL(*uploader_->mock_upload_,
                    UploadRecord(Eq(uploader_id_), Eq(priority_),
                                 Eq(sequencing_id), StrEq(std::string(value))))
            .InSequence(uploader_->test_upload_sequence_)
            .WillOnce(Return(true));
        return *this;
      }

      SetUp& RequireEither(int64_t seq_id,
                           base::StringPiece value,
                           int64_t seq_id_other,
                           base::StringPiece value_other) {
        CHECK(uploader_) << "'Complete' already called";
        EXPECT_CALL(*uploader_->mock_upload_,
                    UploadRecord(uploader_id_, priority_, _, _))
            .With(AnyOf(
                Args<2, 3>(Eq(std::make_tuple(seq_id, value))),
                Args<2, 3>(Eq(std::make_tuple(seq_id_other, value_other)))))
            .InSequence(uploader_->test_upload_sequence_)
            .WillOnce(Return(true));
        return *this;
      }

      SetUp& Possible(int64_t sequencing_id, base::StringPiece value) {
        CHECK(uploader_) << "'Complete' already called";
        EXPECT_CALL(*uploader_->mock_upload_,
                    UploadRecord(Eq(uploader_id_), Eq(priority_),
                                 Eq(sequencing_id), StrEq(std::string(value))))
            .Times(Between(0, 1))
            .InSequence(uploader_->test_upload_sequence_)
            .WillRepeatedly(Return(true));
        return *this;
      }

      SetUp& PossibleGap(int64_t sequencing_id, uint64_t count) {
        CHECK(uploader_) << "'Complete' already called";
        EXPECT_CALL(*uploader_->mock_upload_,
                    UploadGap(Eq(uploader_id_), Eq(priority_),
                              Eq(sequencing_id), Eq(count)))
            .Times(Between(0, 1))
            .InSequence(uploader_->test_upload_sequence_)
            .WillRepeatedly(Return(true));
        return *this;
      }

      // The following two expectations refer to the fact that specific
      // sequencing ids have been encountered, regardless of whether they
      // belonged to records or gaps. The expectations are set on a separate
      // test sequence.
      SetUp& RequiredSeqId(int64_t sequencing_id) {
        CHECK(uploader_) << "'Complete' already called";
        EXPECT_CALL(
            *uploader_->mock_upload_,
            EncounterSeqId(Eq(uploader_id_), Eq(priority_), Eq(sequencing_id)))
            .Times(1)
            .InSequence(uploader_->test_encounter_sequence_);
        return *this;
      }

      SetUp& PossibleSeqId(int64_t sequencing_id) {
        CHECK(uploader_) << "'Complete' already called";
        EXPECT_CALL(
            *uploader_->mock_upload_,
            EncounterSeqId(Eq(uploader_id_), Eq(priority_), Eq(sequencing_id)))
            .Times(Between(0, 1))
            .InSequence(uploader_->test_encounter_sequence_);
        return *this;
      }

     private:
      const Priority priority_;
      std::unique_ptr<TestUploader> uploader_;
      const int64_t uploader_id_;
      test::TestCallbackWaiter* const waiter_;
    };

    // Helper class for setting up mock uploader expectations for key delivery.
    class SetKeyDelivery {
     public:
      explicit SetKeyDelivery(LegacyStorageTest* self)
          : self_(self), uploader_(std::make_unique<TestUploader>(self)) {}
      SetKeyDelivery(const SetKeyDelivery& other) = delete;
      SetKeyDelivery& operator=(const SetKeyDelivery& other) = delete;
      ~SetKeyDelivery() { CHECK(!uploader_) << "Missed 'Complete' call"; }

      std::unique_ptr<TestUploader> Complete() {
        CHECK(uploader_) << "'Complete' already called";
        // Log and ignore records and failures (usually there are none).
        EXPECT_CALL(*uploader_->mock_upload_,
                    UploadRecord(Eq(uploader_->uploader_id_), _, _, _))
            .WillRepeatedly(Return(true));
        EXPECT_CALL(*uploader_->mock_upload_,
                    UploadRecordFailure(Eq(uploader_->uploader_id_), _, _, _))
            .WillRepeatedly(Return(true));
        EXPECT_CALL(
            *uploader_->mock_upload_,
            UploadComplete(Eq(uploader_->uploader_id_), Eq(Status::StatusOK())))
            .WillOnce(
                WithoutArgs(Invoke(self_, &LegacyStorageTest::DeliverKey)))
            .RetiresOnSaturation();
        return std::move(uploader_);
      }

     private:
      LegacyStorageTest* const self_;
      std::unique_ptr<TestUploader> uploader_;
    };

    explicit TestUploader(LegacyStorageTest* self)
        : uploader_id_(next_uploader_id.fetch_add(1)),
          // Allocate MockUpload as raw pointer and immediately wrap it in
          // unique_ptr and pass to SequenceBoundUpload to own.
          // MockUpload outlives TestUploader and is destructed together with
          // SequenceBoundUpload (on a sequenced task runner).
          mock_upload_(new ::testing::NiceMock<const MockUpload>()),
          sequence_bound_upload_(
              self->main_task_runner_,
              base::WrapUnique(mock_upload_),
              &self->last_upload_generation_id_,
              &self->last_record_digest_map_,
              base::BindRepeating(&RecordUploadStore::Store,
                                  base::Unretained(&self->upload_store_))),

          decryptor_(self->decryptor_) {
      DETACH_FROM_SEQUENCE(test_uploader_checker_);
    }

    ~TestUploader() override {
      DCHECK_CALLED_ON_VALID_SEQUENCE(test_uploader_checker_);
    }

    void ProcessRecord(EncryptedRecord encrypted_record,
                       ScopedReservation scoped_reservation,
                       base::OnceCallback<void(bool)> processed_cb) override {
      DCHECK_CALLED_ON_VALID_SEQUENCE(test_uploader_checker_);
      auto sequence_information = encrypted_record.sequence_information();
      if (!encrypted_record.has_encryption_info()) {
        // Wrapped record is not encrypted.
        WrappedRecord wrapped_record;
        ASSERT_TRUE(wrapped_record.ParseFromString(
            encrypted_record.encrypted_wrapped_record()));
        VerifyRecord(std::move(sequence_information), std::move(wrapped_record),
                     std::move(processed_cb));
        return;
      }
      // Decrypt encrypted_record asynhcronously, then resume on the current
      // sequence.
      (new SingleDecryptionContext(
           encrypted_record, decryptor_,
           base::BindOnce(
               [](SequenceInformation sequence_information,
                  base::OnceCallback<void(bool)> processed_cb,
                  scoped_refptr<base::SequencedTaskRunner> task_runner,
                  TestUploader* uploader, StatusOr<base::StringPiece> result) {
                 ASSERT_OK(result.status()) << result.status();
                 WrappedRecord wrapped_record;
                 ASSERT_TRUE(wrapped_record.ParseFromArray(
                     result.ValueOrDie().data(), result.ValueOrDie().size()));
                 // Schedule on the same runner to verify wrapped record once
                 // decrypted.
                 task_runner->PostTask(
                     FROM_HERE, base::BindOnce(&TestUploader::VerifyRecord,
                                               base::Unretained(uploader),
                                               std::move(sequence_information),
                                               std::move(wrapped_record),
                                               std::move(processed_cb)));
               },
               std::move(sequence_information), std::move(processed_cb),
               base::SequencedTaskRunner::GetCurrentDefault(),
               base::Unretained(this))))
          ->Start();
    }

    void ProcessGap(SequenceInformation sequence_information,
                    uint64_t count,
                    base::OnceCallback<void(bool)> processed_cb) override {
      DCHECK_CALLED_ON_VALID_SEQUENCE(test_uploader_checker_);
      sequence_bound_upload_.AsyncCall(&SequenceBoundUpload::ProcessGap)
          .WithArgs(uploader_id_, std::move(sequence_information), count,
                    std::move(processed_cb));
    }

    void Completed(Status status) override {
      DCHECK_CALLED_ON_VALID_SEQUENCE(test_uploader_checker_);
      sequence_bound_upload_.AsyncCall(&SequenceBoundUpload::DoUploadComplete)
          .WithArgs(uploader_id_, status);
    }

    // Helper method for setting up dummy mock uploader expectations.
    // To be used only for uploads that we want to just ignore and do not care
    // about their outcome.
    static std::unique_ptr<TestUploader> SetUpDummy(LegacyStorageTest* self) {
      auto uploader = std::make_unique<TestUploader>(self);
      // Any Record, RecordFailure of Gap could be encountered, and
      // returning false will cut the upload short.
      EXPECT_CALL(*uploader->mock_upload_,
                  UploadRecord(Eq(uploader->uploader_id_), _, _, _))
          .InSequence(uploader->test_upload_sequence_)
          .WillRepeatedly(Return(false));
      EXPECT_CALL(*uploader->mock_upload_,
                  UploadRecordFailure(Eq(uploader->uploader_id_), _, _, _))
          .InSequence(uploader->test_upload_sequence_)
          .WillRepeatedly(Return(false));
      EXPECT_CALL(*uploader->mock_upload_,
                  UploadGap(Eq(uploader->uploader_id_), _, _, _))
          .InSequence(uploader->test_upload_sequence_)
          .WillRepeatedly(Return(false));
      // Complete will always happen last (whether records/gaps were
      // encountered or not).
      EXPECT_CALL(*uploader->mock_upload_,
                  UploadComplete(Eq(uploader->uploader_id_), _))
          .Times(1)
          .InSequence(uploader->test_upload_sequence_);
      return uploader;
    }

   private:
    void VerifyRecord(SequenceInformation sequence_information,
                      WrappedRecord wrapped_record,
                      base::OnceCallback<void(bool)> processed_cb) {
      DCHECK_CALLED_ON_VALID_SEQUENCE(test_uploader_checker_);
      sequence_bound_upload_.AsyncCall(&SequenceBoundUpload::VerifyRecord)
          .WithArgs(uploader_id_, sequence_information, wrapped_record,
                    std::move(processed_cb));
    }

    SEQUENCE_CHECKER(test_uploader_checker_);

    // Unique ID of the uploader - even if the uploader is allocated
    // on the same address as an earlier one (already released),
    // it will get a new id and thus will ensure the expectations
    // match the expected uploader.
    const int64_t uploader_id_;
    const MockUpload* const mock_upload_;
    const base::SequenceBound<SequenceBoundUpload> sequence_bound_upload_;

    const scoped_refptr<test::Decryptor> decryptor_;

    Sequence test_encounter_sequence_;
    Sequence test_upload_sequence_;
  };

  StatusOr<scoped_refptr<StorageInterface>> CreateTestStorage(
      const StorageOptions& options,
      scoped_refptr<EncryptionModuleInterface> encryption_module) {
    // Initialize Storage with no key.
    test::TestEvent<StatusOr<scoped_refptr<StorageInterface>>> e;
    Storage::Create(
        options,
        base::BindRepeating(&LegacyStorageTest::AsyncStartMockUploader,
                            base::Unretained(this)),
        QueuesContainer::Create(/*is_enabled=*/false), encryption_module,
        base::MakeRefCounted<test::TestCompressionModule>(),
        base::MakeRefCounted<SignatureVerificationDevFlag>(
            /*is_enabled=*/false),
        e.cb());
    ASSIGN_OR_RETURN(auto storage, e.result());
    return storage;
  }

  void CreateTestStorageOrDie(
      const StorageOptions& options,
      scoped_refptr<EncryptionModuleInterface> encryption_module =
          EncryptionModule::Create(
              /*is_enabled=*/true,
              /*renew_encryption_key_period=*/base::Minutes(30))) {
    encryption_module->SetValue(is_encryption_enabled());
    if (expect_to_need_key_) {
      // Set uploader expectations for any queue; expect no records and need
      // key. Make sure no uploads happen, and key is requested.
      EXPECT_CALL(set_mock_uploader_expectations_,
                  Call(UploaderInterface::UploadReason::KEY_DELIVERY))
          .Times(AtLeast(1))
          .WillRepeatedly(Invoke([this](UploaderInterface::UploadReason) {
            return TestUploader::SetKeyDelivery(this).Complete();
          }));
    } else {
      // No attempts to deliver key.
      EXPECT_CALL(set_mock_uploader_expectations_,
                  Call(UploaderInterface::UploadReason::KEY_DELIVERY))
          .Times(0);
    }

    ASSERT_FALSE(storage_) << "TestStorage already assigned";
    StatusOr<scoped_refptr<StorageInterface>> storage_result =
        CreateTestStorage(options, encryption_module);
    ASSERT_OK(storage_result)
        << "Failed to create TestStorage, error=" << storage_result.status();
    storage_ = std::move(storage_result.ValueOrDie());
  }

  void ResetTestStorage() {
    if (storage_) {
      // StorageQueue comprising Storage are destructed on threads, wait
      // for them to finish.
      test::TestCallbackAutoWaiter waiter;
      storage_->RegisterCompletionCallback(base::BindOnce(
          &test::TestCallbackAutoWaiter::Signal, base::Unretained(&waiter)));
      storage_.reset();
    }
    // Let remaining asynchronous activity finish.
    // TODO(b/254418902): The next line is not logically necessary, but for
    // unknown reason the tests becomes flaky without it, keeping it for now.
    task_environment_.RunUntilIdle();
    // All expected uploads should have happened.
    EXPECT_THAT(expected_uploads_count_, Eq(0u));
    // Make sure all memory is deallocated.
    EXPECT_THAT(options_.memory_resource()->GetUsed(), Eq(0u));
    // Make sure all disk is not reserved (files remain, but Storage is
    // not responsible for them anymore).
    EXPECT_THAT(options_.disk_space_resource()->GetUsed(), Eq(0u));
  }

  StatusOr<scoped_refptr<StorageInterface>>
  CreateTestStorageWithFailedKeyDelivery(
      const StorageOptions& options,
      scoped_refptr<EncryptionModuleInterface> encryption_module =
          EncryptionModule::Create(
              /*is_enabled=*/true,
              /*renew_encryption_key_period=*/base::Minutes(30))) {
    // Initialize Storage with no key.
    test::TestEvent<StatusOr<scoped_refptr<StorageInterface>>> e;
    Storage::Create(
        options,
        base::BindRepeating(&LegacyStorageTest::AsyncStartMockUploaderFailing,
                            base::Unretained(this)),
        QueuesContainer::Create(/*is_enabled=*/false), encryption_module,
        base::MakeRefCounted<test::TestCompressionModule>(),
        base::MakeRefCounted<SignatureVerificationDevFlag>(
            /*is_enabled=*/false),
        e.cb());
    ASSIGN_OR_RETURN(auto storage, e.result());
    return storage;
  }

  const StorageOptions& BuildTestStorageOptions() const { return options_; }

  void AsyncStartMockUploader(
      UploaderInterface::UploadReason reason,
      UploaderInterface::UploaderInterfaceResultCb start_uploader_cb) {
    main_task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(
            [](UploaderInterface::UploadReason reason,
               UploaderInterface::UploaderInterfaceResultCb start_uploader_cb,
               LegacyStorageTest* self) {
              if (self->expect_to_need_key_ &&
                  reason == UploaderInterface::UploadReason::KEY_DELIVERY) {
                // Ignore expectation count in this special case.
              } else {
                if (self->expected_uploads_count_ == 0u) {
                  LOG(ERROR) << "Upload not expected, reason="
                             << UploaderInterface::ReasonToString(reason);
                  std::move(start_uploader_cb)
                      .Run(Status(
                          error::CANCELLED,
                          base::StrCat(
                              {"Unexpected upload ignored, reason=",
                               UploaderInterface::ReasonToString(reason)})));
                  return;
                }
                --(self->expected_uploads_count_);
              }
              LOG(ERROR) << "Attempt upload, reason="
                         << UploaderInterface::ReasonToString(reason);
              LOG_IF(FATAL, ++(self->upload_count_) >= 16uL)
                  << "Too many uploads";
              auto result = self->set_mock_uploader_expectations_.Call(reason);
              if (!result.ok()) {
                LOG(ERROR) << "Upload not allowed, reason="
                           << UploaderInterface::ReasonToString(reason) << " "
                           << result.status();
                std::move(start_uploader_cb).Run(result.status());
                return;
              }
              auto uploader = std::move(result.ValueOrDie());
              std::move(start_uploader_cb).Run(std::move(uploader));
            },
            reason, std::move(start_uploader_cb), base::Unretained(this)));
  }

  void AsyncStartMockUploaderFailing(
      UploaderInterface::UploadReason reason,
      UploaderInterface::UploaderInterfaceResultCb start_uploader_cb) {
    if (reason == UploaderInterface::UploadReason::KEY_DELIVERY &&
        key_delivery_failure_.load()) {
      std::move(start_uploader_cb)
          .Run(Status(kKeyDeliveryError, kKeyDeliveryErrorMessage));
      return;
    }
    AsyncStartMockUploader(reason, std::move(start_uploader_cb));
  }

  Status WriteString(Priority priority, base::StringPiece data) {
    EXPECT_TRUE(storage_) << "Storage not created yet";
    test::TestEvent<Status> w;
    Record record;
    record.set_data(std::string(data));
    record.set_destination(UPLOAD_EVENTS);
    record.set_dm_token("DM TOKEN");
    LOG(ERROR) << "Write priority=" << priority << " data='"
               << record.data().substr(0, kDebugDataPrintSize) << "'";
    storage_->Write(priority, std::move(record), w.cb());
    return w.result();
  }

  void WriteStringOrDie(Priority priority, base::StringPiece data) {
    const Status write_result = WriteString(priority, data);
    ASSERT_OK(write_result) << write_result;
  }

  void ConfirmOrDie(Priority priority,
                    int64_t sequencing_id,
                    bool force = false) {
    auto generation_it = last_upload_generation_id_.find(priority);
    ASSERT_NE(generation_it, last_upload_generation_id_.end()) << priority;
    LOG(ERROR) << "Confirm priority=" << priority << " force=" << force
               << " seq=" << sequencing_id << " gen=" << generation_it->second;
    SequenceInformation seq_info;
    seq_info.set_sequencing_id(sequencing_id);
    seq_info.set_generation_id(generation_it->second);
    seq_info.set_priority(priority);
    test::TestEvent<Status> c;
    storage_->Confirm(std::move(seq_info), force, c.cb());
    const Status c_result = c.result();
    ASSERT_OK(c_result) << c_result;
  }

  void FlushOrDie(Priority priority) {
    test::TestEvent<Status> c;
    storage_->Flush(priority, c.cb());
    const Status c_result = c.result();
    ASSERT_OK(c_result) << c_result;
  }

  SignedEncryptionInfo GenerateAndSignKey() {
    DCHECK(decryptor_) << "Decryptor not created";
    // Generate new pair of private key and public value.
    uint8_t private_key[kKeySize];
    Encryptor::PublicKeyId public_key_id;
    uint8_t public_value[kKeySize];
    test::GenerateEncryptionKeyPair(private_key, public_value);
    test::TestEvent<StatusOr<Encryptor::PublicKeyId>> prepare_key_pair;
    decryptor_->RecordKeyPair(
        std::string(reinterpret_cast<const char*>(private_key), kKeySize),
        std::string(reinterpret_cast<const char*>(public_value), kKeySize),
        prepare_key_pair.cb());
    auto prepare_key_result = prepare_key_pair.result();
    DCHECK(prepare_key_result.ok());
    public_key_id = prepare_key_result.ValueOrDie();
    // Prepare signed encryption key to be delivered to Storage.
    SignedEncryptionInfo signed_encryption_key;
    signed_encryption_key.set_public_asymmetric_key(
        std::string(reinterpret_cast<const char*>(public_value), kKeySize));
    signed_encryption_key.set_public_key_id(public_key_id);
    // Sign public key.
    uint8_t value_to_sign[sizeof(Encryptor::PublicKeyId) + kKeySize];
    memcpy(value_to_sign, &public_key_id, sizeof(Encryptor::PublicKeyId));
    memcpy(value_to_sign + sizeof(Encryptor::PublicKeyId), public_value,
           kKeySize);
    uint8_t signature[kSignatureSize];
    test::SignMessage(
        signing_private_key_,
        base::StringPiece(reinterpret_cast<const char*>(value_to_sign),
                          sizeof(value_to_sign)),
        signature);
    signed_encryption_key.set_signature(
        std::string(reinterpret_cast<const char*>(signature), kSignatureSize));
    // Double check signature.
    DCHECK(VerifySignature(
        signature_verification_public_key_,
        base::StringPiece(reinterpret_cast<const char*>(value_to_sign),
                          sizeof(value_to_sign)),
        signature));
    return signed_encryption_key;
  }

  void DeliverKey() {
    ASSERT_TRUE(is_encryption_enabled())
        << "Key can be delivered only when encryption is enabled";
    storage_->UpdateEncryptionKey(signed_encryption_key_);
    // Key has already been loaded, no need to redo it next time
    // (unless explicitly requested).
    expect_to_need_key_ = false;
  }

  bool is_encryption_enabled() const { return ::testing::get<0>(GetParam()); }
  size_t single_file_size_limit() const {
    return ::testing::get<1>(GetParam());
  }

  void ResetExpectedUploadsCount() { expected_uploads_count_ = 0u; }

  void SetExpectedUploadsCount(size_t count = 1u) {
    EXPECT_THAT(expected_uploads_count_, Eq(0u));
    expected_uploads_count_ = count;
  }

  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};

  // Track records that are uploaded across multiple uploads
  RecordUploadStore upload_store_;

  // Initializes mock metric functions for UMA
  analytics::Metrics::TestEnvironment metrics_test_environment_;

  // Sequenced task runner where all EXPECTs will happen - main thread.
  const scoped_refptr<base::SequencedTaskRunner> main_task_runner_{
      base::SequencedTaskRunner::GetCurrentDefault()};

  uint8_t signature_verification_public_key_[kKeySize];
  uint8_t signing_private_key_[kSignKeySize];

  SEQUENCE_CHECKER(sequence_checker_);
  base::ScopedTempDir location_;
  TestStorageOptions options_;
  scoped_refptr<test::Decryptor> decryptor_;
  scoped_refptr<StorageInterface> storage_;
  LastUploadedGenerationIdMap last_upload_generation_id_
      GUARDED_BY_CONTEXT(sequence_checker_);
  SignedEncryptionInfo signed_encryption_key_;
  bool expect_to_need_key_{false};
  std::atomic<bool> key_delivery_failure_{false};

  // Test-wide global mapping of <generation id, sequencing id> to record
  // digest. Serves all TestUploaders created by test fixture.
  LastRecordDigest::Map last_record_digest_map_
      GUARDED_BY_CONTEXT(sequence_checker_);

  size_t upload_count_ = 0uL;

  // Counter indicating how many upload calls are expected.
  // Can be set only if before that it is zero.
  // Needs to be set to a positive number (usually 1) before executing an action
  // that would trigger upload (e.g., advancing time or FLUSH or calling write
  // to IMMEDIATE/SECURITY queue). As long as the counter is positive, uploads
  // will be permitted, and the counter will decrement by 1. Once the counter
  // becomes zero, upload calls will be ignored (they may be caused by mocked
  // time being advanced more than requested).
  size_t expected_uploads_count_ = 0u;

  // Mock to be called for setting up the uploader.
  // Allowed only if expected_uploads_count_ is positive or for expected key
  // delivery.
  ::testing::MockFunction<StatusOr<std::unique_ptr<TestUploader>>(
      UploaderInterface::UploadReason /*reason*/)>
      set_mock_uploader_expectations_;
};

constexpr std::array<const char*, 3> kData = {"Rec1111", "Rec222", "Rec33"};
constexpr std::array<const char*, 3> kMoreData = {"More1111", "More222",
                                                  "More33"};

TEST_P(LegacyStorageTest, WriteIntoNewStorageAndReopen) {
  CreateTestStorageOrDie(BuildTestStorageOptions());
  WriteStringOrDie(FAST_BATCH, kData[0]);
  WriteStringOrDie(FAST_BATCH, kData[1]);
  WriteStringOrDie(FAST_BATCH, kData[2]);

  ResetTestStorage();

  // Init resume upload upon non-empty queue restart.
  test::TestCallbackAutoWaiter waiter;
  EXPECT_CALL(set_mock_uploader_expectations_,
              Call(Eq(UploaderInterface::UploadReason::INIT_RESUME)))
      .WillOnce(Invoke([&waiter, this](UploaderInterface::UploadReason reason) {
        return TestUploader::SetUp(FAST_BATCH, &waiter, this)
            .Required(0, kData[0])
            .Required(1, kData[1])
            .Required(2, kData[2])
            .Complete();
      }))
      .RetiresOnSaturation();

  // Reopening will cause INIT_RESUME
  SetExpectedUploadsCount();
  CreateTestStorageOrDie(BuildTestStorageOptions());
}

TEST_P(LegacyStorageTest, WriteIntoNewStorageReopenAndWriteMore) {
  CreateTestStorageOrDie(BuildTestStorageOptions());
  WriteStringOrDie(FAST_BATCH, kData[0]);
  WriteStringOrDie(FAST_BATCH, kData[1]);
  WriteStringOrDie(FAST_BATCH, kData[2]);

  ResetTestStorage();

  // Init resume upload upon non-empty queue restart.
  test::TestCallbackAutoWaiter waiter;
  EXPECT_CALL(set_mock_uploader_expectations_,
              Call(Eq(UploaderInterface::UploadReason::INIT_RESUME)))
      .WillOnce(Invoke([&waiter, this](UploaderInterface::UploadReason reason) {
        return TestUploader::SetUp(FAST_BATCH, &waiter, this)
            .Required(0, kData[0])
            .Required(1, kData[1])
            .Required(2, kData[2])
            .Complete();
      }))
      .RetiresOnSaturation();

  // Reopening will cause INIT_RESUME
  SetExpectedUploadsCount();
  CreateTestStorageOrDie(BuildTestStorageOptions());

  WriteStringOrDie(FAST_BATCH, kMoreData[0]);
  WriteStringOrDie(FAST_BATCH, kMoreData[1]);
  WriteStringOrDie(FAST_BATCH, kMoreData[2]);
}

TEST_P(LegacyStorageTest, WriteIntoNewStorageAndUpload) {
  CreateTestStorageOrDie(BuildTestStorageOptions());
  WriteStringOrDie(FAST_BATCH, kData[0]);
  WriteStringOrDie(FAST_BATCH, kData[1]);
  WriteStringOrDie(FAST_BATCH, kData[2]);

  // Set uploader expectations.
  test::TestCallbackAutoWaiter waiter;
  EXPECT_CALL(set_mock_uploader_expectations_,
              Call(Eq(UploaderInterface::UploadReason::PERIODIC)))
      .WillOnce(Invoke([&waiter, this](UploaderInterface::UploadReason reason) {
        return TestUploader::SetUp(FAST_BATCH, &waiter, this)
            .Required(0, kData[0])
            .Required(1, kData[1])
            .Required(2, kData[2])
            .Complete();
      }))
      .RetiresOnSaturation();

  // Trigger upload.
  SetExpectedUploadsCount();
  task_environment_.FastForwardBy(base::Seconds(1));
}

TEST_P(LegacyStorageTest, WriteIntoNewStorageAndUploadWithKeyUpdate) {
  // Run the test only when encryption is enabled.
  if (!is_encryption_enabled()) {
    return;
  }

  static constexpr auto kKeyRenewalTime = base::Milliseconds(500);
  CreateTestStorageOrDie(
      BuildTestStorageOptions(),
      EncryptionModule::Create(is_encryption_enabled(), kKeyRenewalTime));
  WriteStringOrDie(MANUAL_BATCH, kData[0]);
  WriteStringOrDie(MANUAL_BATCH, kData[1]);
  WriteStringOrDie(MANUAL_BATCH, kData[2]);

  {
    // Set uploader expectations.
    test::TestCallbackAutoWaiter waiter;
    EXPECT_CALL(set_mock_uploader_expectations_,
                Call(Eq(UploaderInterface::UploadReason::MANUAL)))
        .WillOnce(
            Invoke([&waiter, this](UploaderInterface::UploadReason reason) {
              return TestUploader::SetUp(MANUAL_BATCH, &waiter, this)
                  .Required(0, kData[0])
                  .Required(1, kData[1])
                  .Required(2, kData[2])
                  .Complete();
            }))
        .RetiresOnSaturation();

    // Trigger upload with no key update.
    SetExpectedUploadsCount();
    FlushOrDie(MANUAL_BATCH);
  }

  // Confirm written data to prevent upload retry.
  ConfirmOrDie(MANUAL_BATCH, /*sequencing_id=*/2);

  // Write more data.
  WriteStringOrDie(MANUAL_BATCH, kMoreData[0]);
  WriteStringOrDie(MANUAL_BATCH, kMoreData[1]);
  WriteStringOrDie(MANUAL_BATCH, kMoreData[2]);

  // Wait to trigger encryption key request on the next upload.
  task_environment_.FastForwardBy(kKeyRenewalTime + base::Milliseconds(100));

  // Set uploader expectations for MANUAL upload with key delivery.
  test::TestCallbackAutoWaiter waiter;
  EXPECT_CALL(set_mock_uploader_expectations_,
              Call(Eq(UploaderInterface::UploadReason::KEY_DELIVERY)))
      .WillOnce(Invoke([&waiter, this](UploaderInterface::UploadReason reason) {
        // Prevent more key delivery requests.
        DeliverKey();
        return TestUploader::SetUp(MANUAL_BATCH, &waiter, this)
            .Required(3, kMoreData[0])
            .Required(4, kMoreData[1])
            .Required(5, kMoreData[2])
            .Complete();
      }))
      .RetiresOnSaturation();

  // Trigger upload to make sure data is present.
  SetExpectedUploadsCount();
  FlushOrDie(MANUAL_BATCH);
}

TEST_P(LegacyStorageTest, WriteIntoNewStorageReopenWriteMoreAndUpload) {
  CreateTestStorageOrDie(BuildTestStorageOptions());
  WriteStringOrDie(FAST_BATCH, kData[0]);
  WriteStringOrDie(FAST_BATCH, kData[1]);
  WriteStringOrDie(FAST_BATCH, kData[2]);

  ResetTestStorage();

  {
    // Init resume upload upon non-empty queue restart.
    test::TestCallbackAutoWaiter waiter;
    EXPECT_CALL(set_mock_uploader_expectations_,
                Call(Eq(UploaderInterface::UploadReason::INIT_RESUME)))
        .WillOnce(
            Invoke([&waiter, this](UploaderInterface::UploadReason reason) {
              return TestUploader::SetUp(FAST_BATCH, &waiter, this)
                  .Required(0, kData[0])
                  .Required(1, kData[1])
                  .Required(2, kData[2])
                  .Complete();
            }))
        .RetiresOnSaturation();

    // Reopening will cause INIT_RESUME
    SetExpectedUploadsCount();
    CreateTestStorageOrDie(BuildTestStorageOptions());
  }

  const std::vector<TestRecord> data = {{FAST_BATCH, 0, kData[0]},
                                        {FAST_BATCH, 1, kData[1]},
                                        {FAST_BATCH, 2, kData[2]}};

  // Expect records to contained in the same upload
  EXPECT_THAT(upload_store_.Uploads(), testing::Contains(data));

  // Expect records are uploaded in the correct order relative to each other
  // regardless of which upload they arrive in.
  EXPECT_TRUE(RecordsArrivedInExpectedOrder(upload_store_.Records(), data));

  // Delete all records in the upload store. Otherwise they will
  // persist and potentially interfere with future
  // expectations.
  upload_store_.Reset();

  WriteStringOrDie(FAST_BATCH, kMoreData[0]);
  WriteStringOrDie(FAST_BATCH, kMoreData[1]);
  WriteStringOrDie(FAST_BATCH, kMoreData[2]);

  // Set uploader expectations.
  test::TestCallbackAutoWaiter waiter;
  EXPECT_CALL(set_mock_uploader_expectations_,
              Call(Eq(UploaderInterface::UploadReason::PERIODIC)))
      .WillOnce(Invoke([&waiter, this](UploaderInterface::UploadReason reason) {
        return TestUploader::SetUp(FAST_BATCH, &waiter, this)
            .RequireEither(0, kData[0], 3, kMoreData[0])
            .RequireEither(1, kData[1], 4, kMoreData[1])
            .RequireEither(2, kData[2], 5, kMoreData[2])
            .RequireEither(0, kData[0], 3, kMoreData[0])
            .RequireEither(1, kData[1], 4, kMoreData[1])
            .RequireEither(2, kData[2], 5, kMoreData[2])
            .Complete();
      }))
      .RetiresOnSaturation();

  // Trigger upload.
  SetExpectedUploadsCount();
  task_environment_.FastForwardBy(base::Seconds(1));
  task_environment_.RunUntilIdle();

  const std::vector<TestRecord> all_uploaded_records = {
      {FAST_BATCH, 0, kData[0]},     {FAST_BATCH, 1, kData[1]},
      {FAST_BATCH, 2, kData[2]},     {FAST_BATCH, 3, kMoreData[0]},
      {FAST_BATCH, 4, kMoreData[1]}, {FAST_BATCH, 5, kMoreData[2]}};

  // Expect records to be contained in the same upload
  EXPECT_THAT(upload_store_.Uploads(), testing::Contains(all_uploaded_records));

  // Expect records are uploaded in the correct order relative to each other
  // regardless of which upload they arrive in.
  EXPECT_TRUE(RecordsArrivedInExpectedOrder(upload_store_.Records(),
                                            all_uploaded_records));
}

TEST_P(LegacyStorageTest, WriteIntoNewStorageAndFlush) {
  CreateTestStorageOrDie(BuildTestStorageOptions());
  WriteStringOrDie(MANUAL_BATCH, kData[0]);
  WriteStringOrDie(MANUAL_BATCH, kData[1]);
  WriteStringOrDie(MANUAL_BATCH, kData[2]);

  // Set uploader expectations.
  test::TestCallbackAutoWaiter waiter;
  EXPECT_CALL(set_mock_uploader_expectations_,
              Call(Eq(UploaderInterface::UploadReason::MANUAL)))
      .WillOnce(Invoke([&waiter, this](UploaderInterface::UploadReason reason) {
        return TestUploader::SetUp(MANUAL_BATCH, &waiter, this)
            .Required(0, kData[0])
            .Required(1, kData[1])
            .Required(2, kData[2])
            .Complete();
      }))
      .RetiresOnSaturation();

  // Trigger upload.
  SetExpectedUploadsCount();
  FlushOrDie(MANUAL_BATCH);
}

TEST_P(LegacyStorageTest, WriteIntoNewStorageReopenWriteMoreAndFlush) {
  CreateTestStorageOrDie(BuildTestStorageOptions());
  WriteStringOrDie(MANUAL_BATCH, kData[0]);
  WriteStringOrDie(MANUAL_BATCH, kData[1]);
  WriteStringOrDie(MANUAL_BATCH, kData[2]);

  ResetTestStorage();

  {
    // Init resume upload upon non-empty queue restart.
    test::TestCallbackAutoWaiter waiter;
    EXPECT_CALL(set_mock_uploader_expectations_,
                Call(Eq(UploaderInterface::UploadReason::INIT_RESUME)))
        .WillOnce(
            Invoke([&waiter, this](UploaderInterface::UploadReason reason) {
              return TestUploader::SetUp(MANUAL_BATCH, &waiter, this)
                  .Required(0, kData[0])
                  .Required(1, kData[1])
                  .Required(2, kData[2])
                  .Complete();
            }))
        .RetiresOnSaturation();

    // Reopening will cause INIT_RESUME
    SetExpectedUploadsCount();
    CreateTestStorageOrDie(BuildTestStorageOptions());
  }

  WriteStringOrDie(MANUAL_BATCH, kMoreData[0]);
  WriteStringOrDie(MANUAL_BATCH, kMoreData[1]);
  WriteStringOrDie(MANUAL_BATCH, kMoreData[2]);

  // Set uploader expectations.
  test::TestCallbackAutoWaiter waiter;
  EXPECT_CALL(set_mock_uploader_expectations_,
              Call(Eq(UploaderInterface::UploadReason::MANUAL)))
      .WillOnce(Invoke([&waiter, this](UploaderInterface::UploadReason reason) {
        return TestUploader::SetUp(MANUAL_BATCH, &waiter, this)
            .Required(0, kData[0])
            .Required(1, kData[1])
            .Required(2, kData[2])
            .Required(3, kMoreData[0])
            .Required(4, kMoreData[1])
            .Required(5, kMoreData[2])
            .Complete();
      }))
      .RetiresOnSaturation();

  // Trigger upload.
  SetExpectedUploadsCount();
  FlushOrDie(MANUAL_BATCH);
}

TEST_P(LegacyStorageTest, WriteAndRepeatedlyUploadWithConfirmations) {
  CreateTestStorageOrDie(BuildTestStorageOptions());

  WriteStringOrDie(FAST_BATCH, kData[0]);
  WriteStringOrDie(FAST_BATCH, kData[1]);
  WriteStringOrDie(FAST_BATCH, kData[2]);

  {
    // Set uploader expectations.
    test::TestCallbackAutoWaiter waiter;
    EXPECT_CALL(set_mock_uploader_expectations_,
                Call(Eq(UploaderInterface::UploadReason::PERIODIC)))
        .WillOnce(
            Invoke([&waiter, this](UploaderInterface::UploadReason reason) {
              return TestUploader::SetUp(FAST_BATCH, &waiter, this)
                  .Required(0, kData[0])
                  .Required(1, kData[1])
                  .Required(2, kData[2])
                  .Complete();
            }))
        .RetiresOnSaturation();

    // Forward time to trigger upload
    SetExpectedUploadsCount();
    task_environment_.FastForwardBy(base::Seconds(1));
  }

  // Confirm #0 and forward time again, removing data #0
  ConfirmOrDie(FAST_BATCH, /*sequencing_id=*/0);
  {
    // Set uploader expectations.
    test::TestCallbackAutoWaiter waiter;
    EXPECT_CALL(set_mock_uploader_expectations_,
                Call(Eq(UploaderInterface::UploadReason::PERIODIC)))
        .WillOnce(
            Invoke([&waiter, this](UploaderInterface::UploadReason reason) {
              return TestUploader::SetUp(FAST_BATCH, &waiter, this)
                  .Required(1, kData[1])
                  .Required(2, kData[2])
                  .Complete();
            }))
        .RetiresOnSaturation();

    // Forward time to trigger upload
    SetExpectedUploadsCount();
    task_environment_.FastForwardBy(base::Seconds(1));
  }

  // Confirm #1 and forward time again, removing data #1
  ConfirmOrDie(FAST_BATCH, /*sequencing_id=*/1);
  {
    test::TestCallbackAutoWaiter waiter;
    // Set uploader expectations.
    EXPECT_CALL(set_mock_uploader_expectations_,
                Call(Eq(UploaderInterface::UploadReason::PERIODIC)))
        .WillOnce(
            Invoke([&waiter, this](UploaderInterface::UploadReason reason) {
              return TestUploader::SetUp(FAST_BATCH, &waiter, this)
                  .Required(2, kData[2])
                  .Complete();
            }))
        .RetiresOnSaturation();

    // Forward time to trigger upload
    SetExpectedUploadsCount();
    task_environment_.FastForwardBy(base::Seconds(1));
  }

  // Add more records and verify that #2 and new records are returned.
  WriteStringOrDie(FAST_BATCH, kMoreData[0]);
  WriteStringOrDie(FAST_BATCH, kMoreData[1]);
  WriteStringOrDie(FAST_BATCH, kMoreData[2]);

  {
    // Set uploader expectations.
    test::TestCallbackAutoWaiter waiter;
    EXPECT_CALL(set_mock_uploader_expectations_,
                Call(Eq(UploaderInterface::UploadReason::PERIODIC)))
        .WillOnce(
            Invoke([&waiter, this](UploaderInterface::UploadReason reason) {
              return TestUploader::SetUp(FAST_BATCH, &waiter, this)
                  .Required(2, kData[2])
                  .Required(3, kMoreData[0])
                  .Required(4, kMoreData[1])
                  .Required(5, kMoreData[2])
                  .Complete();
            }))
        .RetiresOnSaturation();
    SetExpectedUploadsCount();
    task_environment_.FastForwardBy(base::Seconds(1));
  }

  // Confirm #2 and forward time again, removing data #2
  ConfirmOrDie(FAST_BATCH, /*sequencing_id=*/2);
  {
    // Set uploader expectations.
    test::TestCallbackAutoWaiter waiter;
    EXPECT_CALL(set_mock_uploader_expectations_,
                Call(Eq(UploaderInterface::UploadReason::PERIODIC)))
        .WillOnce(
            Invoke([&waiter, this](UploaderInterface::UploadReason reason) {
              return TestUploader::SetUp(FAST_BATCH, &waiter, this)
                  .Required(3, kMoreData[0])
                  .Required(4, kMoreData[1])
                  .Required(5, kMoreData[2])
                  .Complete();
            }))
        .RetiresOnSaturation();
    SetExpectedUploadsCount();
    task_environment_.FastForwardBy(base::Seconds(1));
  }
}

TEST_P(LegacyStorageTest, WriteAndUploadWithBadConfirmation) {
  CreateTestStorageOrDie(BuildTestStorageOptions());

  WriteStringOrDie(FAST_BATCH, kData[0]);
  WriteStringOrDie(FAST_BATCH, kData[1]);
  WriteStringOrDie(FAST_BATCH, kData[2]);

  {
    // Set uploader expectations.
    test::TestCallbackAutoWaiter waiter;
    EXPECT_CALL(set_mock_uploader_expectations_,
                Call(Eq(UploaderInterface::UploadReason::PERIODIC)))
        .WillOnce(
            Invoke([&waiter, this](UploaderInterface::UploadReason reason) {
              return TestUploader::SetUp(FAST_BATCH, &waiter, this)
                  .Required(0, kData[0])
                  .Required(1, kData[1])
                  .Required(2, kData[2])
                  .Complete();
            }))
        .RetiresOnSaturation();

    // Forward time to trigger upload
    SetExpectedUploadsCount();
    task_environment_.FastForwardBy(base::Seconds(1));
  }

  // Confirm #0 with bad generation.
  test::TestEvent<Status> c;
  SequenceInformation seq_info;
  seq_info.set_priority(FAST_BATCH);
  seq_info.set_sequencing_id(0);
  // Do not set generation!
  LOG(ERROR) << "Bad confirm priority=" << seq_info.priority()
             << " seq=" << seq_info.sequencing_id();
  storage_->Confirm(std::move(seq_info), /*force=*/false, c.cb());
  const Status c_result = c.result();
  ASSERT_FALSE(c_result.ok()) << c_result;
}

TEST_P(LegacyStorageTest, WriteAndRepeatedlySecurityUpload) {
  CreateTestStorageOrDie(BuildTestStorageOptions());

  // Upload is initiated asynchronously, so it may happen after the next
  // record is also written. Because of that we set expectations for the
  // records after the current one as |Possible|.
  {
    test::TestCallbackAutoWaiter waiter;
    EXPECT_CALL(set_mock_uploader_expectations_,
                Call(Eq(UploaderInterface::UploadReason::IMMEDIATE_FLUSH)))
        .WillOnce(
            Invoke([&waiter, this](UploaderInterface::UploadReason reason) {
              return TestUploader::SetUp(SECURITY, &waiter, this)
                  .Required(0, kData[0])
                  .Complete();
            }))
        .RetiresOnSaturation();
    SetExpectedUploadsCount(1);
    WriteStringOrDie(SECURITY,
                     kData[0]);  // Immediately uploads and verifies.
  }

  {
    test::TestCallbackAutoWaiter waiter;
    EXPECT_CALL(set_mock_uploader_expectations_,
                Call(Eq(UploaderInterface::UploadReason::IMMEDIATE_FLUSH)))
        .WillOnce(
            Invoke([&waiter, this](UploaderInterface::UploadReason reason) {
              return TestUploader::SetUp(SECURITY, &waiter, this)
                  .Required(0, kData[0])
                  .Required(1, kData[1])
                  .Complete();
            }))
        .RetiresOnSaturation();
    SetExpectedUploadsCount();
    WriteStringOrDie(SECURITY,
                     kData[1]);  // Immediately uploads and verifies.
  }

  {
    test::TestCallbackAutoWaiter waiter;
    EXPECT_CALL(set_mock_uploader_expectations_,
                Call(Eq(UploaderInterface::UploadReason::IMMEDIATE_FLUSH)))
        .WillOnce(
            Invoke([&waiter, this](UploaderInterface::UploadReason reason) {
              return TestUploader::SetUp(SECURITY, &waiter, this)
                  .Required(0, kData[0])
                  .Required(1, kData[1])
                  .Required(2, kData[2])
                  .Complete();
            }))
        .RetiresOnSaturation();
    SetExpectedUploadsCount();
    WriteStringOrDie(SECURITY,
                     kData[2]);  // Immediately uploads and verifies.
  }
}

TEST_P(LegacyStorageTest, WriteAndRepeatedlyImmediateUpload) {
  CreateTestStorageOrDie(BuildTestStorageOptions());

  // Upload is initiated asynchronously, so it may happen after the next
  // record is also written. Because of that we set expectations for the
  // records after the current one as |Possible|.
  {
    test::TestCallbackAutoWaiter waiter;
    EXPECT_CALL(set_mock_uploader_expectations_,
                Call(Eq(UploaderInterface::UploadReason::IMMEDIATE_FLUSH)))
        .WillOnce(
            Invoke([&waiter, this](UploaderInterface::UploadReason reason) {
              return TestUploader::SetUp(IMMEDIATE, &waiter, this)
                  .Required(0, kData[0])
                  .Complete();
            }))
        .RetiresOnSaturation();
    SetExpectedUploadsCount();
    WriteStringOrDie(IMMEDIATE,
                     kData[0]);  // Immediately uploads and verifies.
  }

  {
    test::TestCallbackAutoWaiter waiter;
    EXPECT_CALL(set_mock_uploader_expectations_,
                Call(Eq(UploaderInterface::UploadReason::IMMEDIATE_FLUSH)))
        .WillOnce(
            Invoke([&waiter, this](UploaderInterface::UploadReason reason) {
              return TestUploader::SetUp(IMMEDIATE, &waiter, this)
                  .Required(0, kData[0])
                  .Required(1, kData[1])
                  .Complete();
            }))
        .RetiresOnSaturation();
    SetExpectedUploadsCount();
    WriteStringOrDie(IMMEDIATE,
                     kData[1]);  // Immediately uploads and verifies.
  }

  {
    test::TestCallbackAutoWaiter waiter;
    EXPECT_CALL(set_mock_uploader_expectations_,
                Call(Eq(UploaderInterface::UploadReason::IMMEDIATE_FLUSH)))
        .WillOnce(
            Invoke([&waiter, this](UploaderInterface::UploadReason reason) {
              return TestUploader::SetUp(IMMEDIATE, &waiter, this)
                  .Required(0, kData[0])
                  .Required(1, kData[1])
                  .Required(2, kData[2])
                  .Complete();
            }))
        .RetiresOnSaturation();
    SetExpectedUploadsCount();
    WriteStringOrDie(IMMEDIATE,
                     kData[2]);  // Immediately uploads and verifies.
  }
}

TEST_P(LegacyStorageTest, WriteAndRepeatedlyImmediateUploadWithConfirmations) {
  CreateTestStorageOrDie(BuildTestStorageOptions());

  // Upload is initiated asynchronously, so it may happen after the next
  // record is also written. Because of the Confirmation below, we set
  // expectations for the records that may be eliminated by Confirmation as
  // |Possible|.
  {
    test::TestCallbackAutoWaiter waiter;
    EXPECT_CALL(set_mock_uploader_expectations_,
                Call(Eq(UploaderInterface::UploadReason::IMMEDIATE_FLUSH)))
        .WillOnce(
            Invoke([&waiter, this](UploaderInterface::UploadReason reason) {
              return TestUploader::SetUp(IMMEDIATE, &waiter, this)
                  .Required(0, kData[0])
                  .Complete();
            }))
        .RetiresOnSaturation();
    SetExpectedUploadsCount();
    WriteStringOrDie(IMMEDIATE, kData[0]);
  }

  {
    test::TestCallbackAutoWaiter waiter;
    EXPECT_CALL(set_mock_uploader_expectations_,
                Call(Eq(UploaderInterface::UploadReason::IMMEDIATE_FLUSH)))
        .WillOnce(
            Invoke([&waiter, this](UploaderInterface::UploadReason reason) {
              return TestUploader::SetUp(IMMEDIATE, &waiter, this)
                  .Required(0, kData[0])
                  .Required(1, kData[1])
                  .Complete();
            }))
        .RetiresOnSaturation();
    SetExpectedUploadsCount();
    WriteStringOrDie(IMMEDIATE, kData[1]);
  }

  {
    test::TestCallbackAutoWaiter waiter;
    EXPECT_CALL(set_mock_uploader_expectations_,
                Call(Eq(UploaderInterface::UploadReason::IMMEDIATE_FLUSH)))
        .WillOnce(
            Invoke([&waiter, this](UploaderInterface::UploadReason reason) {
              return TestUploader::SetUp(IMMEDIATE, &waiter, this)
                  .Required(0, kData[0])
                  .Required(1, kData[1])
                  .Required(2, kData[2])
                  .Complete();
            }))
        .RetiresOnSaturation();
    SetExpectedUploadsCount();
    WriteStringOrDie(IMMEDIATE, kData[2]);
  }

  // Confirm #1, removing data #0 and #1
  ConfirmOrDie(IMMEDIATE, /*sequencing_id=*/1);

  // Add more data to verify that #2 and new data are returned.
  // Upload is initiated asynchronously, so it may happen after the next
  // record is also written. Because of that we set expectations for the
  // data after the current one as |Possible|.
  {
    test::TestCallbackAutoWaiter waiter;
    EXPECT_CALL(set_mock_uploader_expectations_,
                Call(Eq(UploaderInterface::UploadReason::IMMEDIATE_FLUSH)))
        .WillOnce(
            Invoke([&waiter, this](UploaderInterface::UploadReason reason) {
              return TestUploader::SetUp(IMMEDIATE, &waiter, this)
                  .Required(2, kData[2])
                  .Required(3, kMoreData[0])
                  .Complete();
            }))
        .RetiresOnSaturation();
    SetExpectedUploadsCount();
    WriteStringOrDie(IMMEDIATE, kMoreData[0]);
  }

  {
    test::TestCallbackAutoWaiter waiter;
    EXPECT_CALL(set_mock_uploader_expectations_,
                Call(Eq(UploaderInterface::UploadReason::IMMEDIATE_FLUSH)))
        .WillOnce(
            Invoke([&waiter, this](UploaderInterface::UploadReason reason) {
              return TestUploader::SetUp(IMMEDIATE, &waiter, this)
                  .Required(2, kData[2])
                  .Required(3, kMoreData[0])
                  .Required(4, kMoreData[1])
                  .Complete();
            }))
        .RetiresOnSaturation();
    SetExpectedUploadsCount();
    WriteStringOrDie(IMMEDIATE, kMoreData[1]);
  }

  {
    test::TestCallbackAutoWaiter waiter;
    EXPECT_CALL(set_mock_uploader_expectations_,
                Call(Eq(UploaderInterface::UploadReason::IMMEDIATE_FLUSH)))
        .WillOnce(
            Invoke([&waiter, this](UploaderInterface::UploadReason reason) {
              return TestUploader::SetUp(IMMEDIATE, &waiter, this)
                  .Required(2, kData[2])
                  .Required(3, kMoreData[0])
                  .Required(4, kMoreData[1])
                  .Required(5, kMoreData[2])
                  .Complete();
            }))
        .RetiresOnSaturation();
    SetExpectedUploadsCount();
    WriteStringOrDie(IMMEDIATE, kMoreData[2]);
  }
}

TEST_P(LegacyStorageTest, WriteAndRepeatedlyUploadMultipleQueues) {
  CreateTestStorageOrDie(BuildTestStorageOptions());

  {
    test::TestCallbackAutoWaiter waiter;
    EXPECT_CALL(set_mock_uploader_expectations_,
                Call(Eq(UploaderInterface::UploadReason::IMMEDIATE_FLUSH)))
        .WillOnce(
            Invoke([&waiter, this](UploaderInterface::UploadReason reason) {
              return TestUploader::SetUp(IMMEDIATE, &waiter, this)
                  .Required(0, kData[0])
                  .Complete();
            }))
        .RetiresOnSaturation();
    SetExpectedUploadsCount();
    WriteStringOrDie(IMMEDIATE, kData[0]);
  }

  WriteStringOrDie(SLOW_BATCH, kMoreData[0]);

  {
    test::TestCallbackAutoWaiter waiter;
    EXPECT_CALL(set_mock_uploader_expectations_,
                Call(Eq(UploaderInterface::UploadReason::IMMEDIATE_FLUSH)))
        .WillOnce(
            Invoke([&waiter, this](UploaderInterface::UploadReason reason) {
              return TestUploader::SetUp(IMMEDIATE, &waiter, this)
                  .Required(0, kData[0])
                  .Required(1, kData[1])
                  .Complete();
            }))
        .RetiresOnSaturation();
    SetExpectedUploadsCount();
    WriteStringOrDie(IMMEDIATE, kData[1]);
  }

  WriteStringOrDie(SLOW_BATCH, kMoreData[1]);

  // Confirm #1 IMMEDIATE, removing data #0 and #1, to prevent upload retry.
  ConfirmOrDie(IMMEDIATE, /*sequencing_id=*/1);

  // Set uploader expectations for FAST_BATCH and SLOW_BATCH.
  {
    test::TestCallbackAutoWaiter waiter;
    EXPECT_CALL(set_mock_uploader_expectations_,
                Call(Eq(UploaderInterface::UploadReason::PERIODIC)))
        .WillOnce(
            Invoke([&waiter, this](UploaderInterface::UploadReason reason) {
              return TestUploader::SetUp(SLOW_BATCH, &waiter, this)
                  .Required(0, kMoreData[0])
                  .Required(1, kMoreData[1])
                  .Complete();
            }))
        .RetiresOnSaturation();
    SetExpectedUploadsCount();
    task_environment_.FastForwardBy(base::Seconds(20));
  }

  // Confirm #0 SLOW_BATCH, removing data #0
  ConfirmOrDie(SLOW_BATCH, /*sequencing_id=*/0);

  // Add more data
  {
    test::TestCallbackAutoWaiter waiter;
    EXPECT_CALL(set_mock_uploader_expectations_,
                Call(Eq(UploaderInterface::UploadReason::IMMEDIATE_FLUSH)))
        .WillOnce(
            Invoke([&waiter, this](UploaderInterface::UploadReason reason) {
              return TestUploader::SetUp(IMMEDIATE, &waiter, this)
                  .Required(2, kData[2])
                  .Complete();
            }))
        .RetiresOnSaturation();
    SetExpectedUploadsCount();
    WriteStringOrDie(IMMEDIATE, kData[2]);
  }
  WriteStringOrDie(SLOW_BATCH, kMoreData[2]);

  // Confirm #2 IMMEDIATE, to prevent upload retry.
  ConfirmOrDie(IMMEDIATE, /*sequencing_id=*/2);

  // Set uploader expectations for FAST_BATCH and SLOW_BATCH.
  {
    test::TestCallbackAutoWaiter waiter;
    EXPECT_CALL(set_mock_uploader_expectations_,
                Call(Eq(UploaderInterface::UploadReason::PERIODIC)))
        .WillOnce(
            Invoke([&waiter, this](UploaderInterface::UploadReason reason) {
              return TestUploader::SetUp(SLOW_BATCH, &waiter, this)
                  .Required(1, kMoreData[1])
                  .Required(2, kMoreData[2])
                  .Complete();
            }))
        .RetiresOnSaturation();
    SetExpectedUploadsCount();
    task_environment_.FastForwardBy(base::Seconds(20));
  }
}

TEST_P(LegacyStorageTest, WriteAndImmediateUploadWithFailure) {
  // Reset options to enable failure retry.
  options_.set_upload_retry_delay(base::Seconds(1));

  CreateTestStorageOrDie(BuildTestStorageOptions());

  // Write a record as Immediate, initiating an upload which fails
  // and then restarts.
  {
    test::TestCallbackAutoWaiter waiter;
    EXPECT_CALL(set_mock_uploader_expectations_,
                Call(Eq(UploaderInterface::UploadReason::IMMEDIATE_FLUSH)))
        .WillOnce(Invoke([](UploaderInterface::UploadReason reason) {
          return Status(error::UNAVAILABLE, "Intended failure in test");
        }))
        .RetiresOnSaturation();
    EXPECT_CALL(set_mock_uploader_expectations_,
                Call(Eq(UploaderInterface::UploadReason::FAILURE_RETRY)))
        .WillOnce(
            Invoke([&waiter, this](UploaderInterface::UploadReason reason) {
              return TestUploader::SetUp(IMMEDIATE, &waiter, this)
                  .Required(0, kData[0])
                  .Complete();
            }))
        .RetiresOnSaturation();
    SetExpectedUploadsCount(2u);
    WriteStringOrDie(IMMEDIATE,
                     kData[0]);  // Immediately uploads and fails.
    // Let it retry upload and verify.
    task_environment_.FastForwardBy(base::Seconds(1));
  }
}

TEST_P(LegacyStorageTest, WriteEncryptFailure) {
  if (!is_encryption_enabled()) {
    return;  // No need to test when encryption is disabled.
  }
  auto test_encryption_module =
      base::MakeRefCounted<test::TestEncryptionModule>(/*is_enabled=*/true);
  test::TestEvent<Status> key_update_event;
  test_encryption_module->UpdateAsymmetricKey("DUMMY KEY", 0,
                                              key_update_event.cb());
  ASSERT_OK(key_update_event.result());
  expect_to_need_key_ = false;
  CreateTestStorageOrDie(BuildTestStorageOptions(), test_encryption_module);
  EXPECT_CALL(*test_encryption_module, EncryptRecordImpl(_, _))
      .WillOnce(WithArg<1>(
          Invoke([](base::OnceCallback<void(StatusOr<EncryptedRecord>)> cb) {
            std::move(cb).Run(Status(error::UNKNOWN, "Failing for tests"));
          })))
      .RetiresOnSaturation();
  const Status result = WriteString(FAST_BATCH, "TEST_MESSAGE");
  EXPECT_FALSE(result.ok());
  EXPECT_EQ(result.error_code(), error::UNKNOWN);
}

TEST_P(LegacyStorageTest, ForceConfirm) {
  CreateTestStorageOrDie(BuildTestStorageOptions());

  WriteStringOrDie(FAST_BATCH, kData[0]);
  WriteStringOrDie(FAST_BATCH, kData[1]);
  WriteStringOrDie(FAST_BATCH, kData[2]);

  // Set uploader expectations.
  {
    test::TestCallbackAutoWaiter waiter;
    EXPECT_CALL(set_mock_uploader_expectations_,
                Call(Eq(UploaderInterface::UploadReason::PERIODIC)))
        .WillOnce(
            Invoke([&waiter, this](UploaderInterface::UploadReason reason) {
              return TestUploader::SetUp(FAST_BATCH, &waiter, this)
                  .Required(0, kData[0])
                  .Required(1, kData[1])
                  .Required(2, kData[2])
                  .Complete();
            }))
        .RetiresOnSaturation();
    // Forward time to trigger upload
    SetExpectedUploadsCount();
    task_environment_.FastForwardBy(base::Seconds(1));
  }

  // Confirm #1 and forward time again, possibly removing records #0 and #1
  ConfirmOrDie(FAST_BATCH, /*sequencing_id=*/1);
  // Set uploader expectations.
  {
    test::TestCallbackAutoWaiter waiter;
    EXPECT_CALL(set_mock_uploader_expectations_,
                Call(Eq(UploaderInterface::UploadReason::PERIODIC)))
        .WillOnce(
            Invoke([&waiter, this](UploaderInterface::UploadReason reason) {
              return TestUploader::SetUp(FAST_BATCH, &waiter, this)
                  .Required(2, kData[2])
                  .Complete();
            }))
        .RetiresOnSaturation();
    // Forward time to trigger upload
    SetExpectedUploadsCount();
    task_environment_.FastForwardBy(base::Seconds(1));
  }

  // Now force confirm #0 and forward time again.
  ConfirmOrDie(FAST_BATCH, /*sequencing_id=*/-1, /*force=*/true);
  // Set uploader expectations: #0 and #1 could be returned as Gaps
  {
    test::TestCallbackAutoWaiter waiter;
    EXPECT_CALL(set_mock_uploader_expectations_,
                Call(Eq(UploaderInterface::UploadReason::PERIODIC)))
        .WillOnce(
            Invoke([&waiter, this](UploaderInterface::UploadReason reason) {
              return TestUploader::SetUp(FAST_BATCH, &waiter, this)
                  .RequiredSeqId(0)
                  .RequiredSeqId(1)
                  .RequiredSeqId(2)
                  // 0-2 must have been encountered, but actual contents
                  // can be different:
                  .Possible(0, kData[0])
                  .PossibleGap(0, 1)
                  .PossibleGap(0, 2)
                  .Possible(1, kData[1])
                  .Required(2, kData[2])
                  .Complete();
            }))
        .RetiresOnSaturation();
    // Forward time to trigger upload
    SetExpectedUploadsCount();
    task_environment_.FastForwardBy(base::Seconds(1));
  }

  // Force confirm #0 and forward time again.
  ConfirmOrDie(FAST_BATCH, /*sequencing_id=*/0, /*force=*/true);
  // Set uploader expectations: #0 and #1 could be returned as Gaps
  {
    test::TestCallbackAutoWaiter waiter;
    EXPECT_CALL(set_mock_uploader_expectations_,
                Call(Eq(UploaderInterface::UploadReason::PERIODIC)))
        .WillOnce(
            Invoke([&waiter, this](UploaderInterface::UploadReason reason) {
              return TestUploader::SetUp(FAST_BATCH, &waiter, this)
                  .RequiredSeqId(1)
                  .RequiredSeqId(2)
                  // 0-2 must have been encountered, but actual contents
                  // can be different:
                  .PossibleGap(1, 1)
                  .Possible(1, kData[1])
                  .Required(2, kData[2])
                  .Complete();
            }))
        .RetiresOnSaturation();
    // Forward time to trigger upload
    SetExpectedUploadsCount();
    task_environment_.FastForwardBy(base::Seconds(1));
  }
}

TEST_P(LegacyStorageTest, KeyIsRequestedWhenEncryptionRenewalPeriodExpires) {
  if (!is_encryption_enabled()) {
    return;  // Test only makes sense with encryption enabled.
  }

  // Initialize Storage with failure to deliver key.
  ASSERT_FALSE(storage_) << "LegacyStorageTest already assigned";
  options_.set_key_check_period(base::Seconds(4));
  StatusOr<scoped_refptr<StorageInterface>> storage_result =
      CreateTestStorageWithFailedKeyDelivery(
          BuildTestStorageOptions(),
          // Set the renew encryption key period to be 1 second less than the
          // storage key check period so that each time storage asks the
          // encryption module if it needs a new key, the encryption module says
          // "yes"
          EncryptionModule::Create(
              /*is_enabled=*/true,
              base::Seconds(options_.key_check_period().InSeconds() - 1)));
  ASSERT_OK(storage_result) << "Failed to create LegacyStorageTest, error="
                            << storage_result.status();
  storage_ = std::move(storage_result.ValueOrDie());

  test::TestCallbackAutoWaiter waiter;
  EXPECT_CALL(set_mock_uploader_expectations_,
              Call(Eq(UploaderInterface::UploadReason::KEY_DELIVERY)))
      // We'll fast forward time such that we trigger two key requests from
      // storage
      .Times(2)
      .WillRepeatedly(Invoke([&waiter, this](UploaderInterface::UploadReason) {
        auto result = TestUploader::SetKeyDelivery(this).Complete();
        waiter.Signal();
        return result;
      }))
      .RetiresOnSaturation();

  // Storage doesn't have a key yet, so key request should succeed, and
  // thus we expect UMA to log success for key delivery
  EXPECT_CALL(
      reporting::analytics::Metrics::TestEnvironment::GetMockMetricsLibrary(),
      SendEnumToUMA(kKeyDeliveryResultUma, error::OK, error::MAX_VALUE));

  // Forward time to trigger key request.
  task_environment_.FastForwardBy(options_.key_check_period());

  // Set test infrastructure to expect another key request
  expect_to_need_key_ = true;

  EXPECT_CALL(
      reporting::analytics::Metrics::TestEnvironment::GetMockMetricsLibrary(),
      SendEnumToUMA(kKeyDeliveryResultUma, error::OK, error::MAX_VALUE));

  // Forward time to trigger key request.
  task_environment_.FastForwardBy(options_.key_check_period());
}

TEST_P(LegacyStorageTest, KeyDeliveryFailureOnNewStorage) {
  static constexpr size_t kFailuresCount = 3;

  if (!is_encryption_enabled()) {
    return;  // Test only makes sense with encryption enabled.
  }

  // Initialize Storage with failure to deliver key.
  ASSERT_FALSE(storage_) << "LegacyStorageTest already assigned";
  StatusOr<scoped_refptr<StorageInterface>> storage_result =
      CreateTestStorageWithFailedKeyDelivery(BuildTestStorageOptions());
  ASSERT_OK(storage_result) << "Failed to create LegacyStorageTest, error="
                            << storage_result.status();
  storage_ = std::move(storage_result.ValueOrDie());

  key_delivery_failure_.store(true);

  // Expect storage to request the encryption key after initialization
  EXPECT_CALL(analytics::Metrics::TestEnvironment::GetMockMetricsLibrary(),
              SendEnumToUMA(kKeyDeliveryResultUma, kKeyDeliveryError,
                            error::MAX_VALUE));

  // Forward time to trigger key request
  task_environment_.FastForwardBy(options_.key_check_period());

  // Try writing multiple times and expect failure since we don't have the key
  for (size_t failure = 1; failure < kFailuresCount; ++failure) {
    // Failing attempt to write
    const Status write_result = WriteString(MANUAL_BATCH, kData[0]);
    EXPECT_FALSE(write_result.ok());
    EXPECT_THAT(write_result.error_code(), Eq(kKeyDeliveryError))
        << write_result;
    EXPECT_THAT(write_result.message(), HasSubstr(kKeyDeliveryErrorMessage))
        << write_result;

    // Storage will continue to request the encryption key
    EXPECT_CALL(
        reporting::analytics::Metrics::TestEnvironment::GetMockMetricsLibrary(),
        SendEnumToUMA(kKeyDeliveryResultUma, kKeyDeliveryError,
                      error::MAX_VALUE));

    // Forward time to trigger key request
    task_environment_.FastForwardBy(options_.key_check_period());
  }

  // This time key delivery is to succeed.
  // Set uploader expectations for any queue; expect no records and need
  // key. Make sure no uploads happen, and key is requested.
  key_delivery_failure_.store(false);
  {
    test::TestCallbackAutoWaiter waiter;
    EXPECT_CALL(set_mock_uploader_expectations_,
                Call(Eq(UploaderInterface::UploadReason::KEY_DELIVERY)))
        .WillOnce(Invoke([&waiter, this](UploaderInterface::UploadReason) {
          auto result = TestUploader::SetKeyDelivery(this).Complete();
          waiter.Signal();
          return result;
        }))
        .RetiresOnSaturation();

    // Key request should succeed, so expect UMA to log success for key
    // delivery
    EXPECT_CALL(
        reporting::analytics::Metrics::TestEnvironment::GetMockMetricsLibrary(),
        SendEnumToUMA(kKeyDeliveryResultUma, error::OK, error::MAX_VALUE));

    // Forward time to trigger key request
    task_environment_.FastForwardBy(options_.key_check_period());
  }

  // Successfully write data
  WriteStringOrDie(MANUAL_BATCH, kData[0]);
  WriteStringOrDie(MANUAL_BATCH, kData[1]);
  WriteStringOrDie(MANUAL_BATCH, kData[2]);

  // Set uploader expectations.
  {
    test::TestCallbackAutoWaiter waiter;
    EXPECT_CALL(set_mock_uploader_expectations_,
                Call(Eq(UploaderInterface::UploadReason::MANUAL)))
        .WillOnce(
            Invoke([&waiter, this](UploaderInterface::UploadReason reason) {
              return TestUploader::SetUp(MANUAL_BATCH, &waiter, this)
                  .Required(0, kData[0])
                  .Required(1, kData[1])
                  .Required(2, kData[2])
                  .Complete();
            }))
        .RetiresOnSaturation();

    // Trigger upload.
    SetExpectedUploadsCount();
    FlushOrDie(MANUAL_BATCH);
  }

  ResetTestStorage();

  {
    // Avoid init resume upload upon non-empty queue restart.
    test::TestCallbackAutoWaiter waiter;
    EXPECT_CALL(set_mock_uploader_expectations_,
                Call(Eq(UploaderInterface::UploadReason::INIT_RESUME)))
        .WillOnce(Invoke([&waiter](UploaderInterface::UploadReason reason) {
          waiter.Signal();
          return Status(error::UNAVAILABLE, "Skipped upload in test");
        }))
        .RetiresOnSaturation();

    // Reopening will cause INIT_RESUME
    SetExpectedUploadsCount();
    CreateTestStorageOrDie(BuildTestStorageOptions());
  }

  // Write more data.
  WriteStringOrDie(MANUAL_BATCH, kMoreData[0]);
  WriteStringOrDie(MANUAL_BATCH, kMoreData[1]);
  WriteStringOrDie(MANUAL_BATCH, kMoreData[2]);

  // Set uploader expectations.
  {
    test::TestCallbackAutoWaiter waiter;
    EXPECT_CALL(set_mock_uploader_expectations_,
                Call(Eq(UploaderInterface::UploadReason::MANUAL)))
        .WillOnce(
            Invoke([&waiter, this](UploaderInterface::UploadReason reason) {
              return TestUploader::SetUp(MANUAL_BATCH, &waiter, this)
                  .Required(0, kData[0])
                  .Required(1, kData[1])
                  .Required(2, kData[2])
                  .Required(3, kMoreData[0])
                  .Required(4, kMoreData[1])
                  .Required(5, kMoreData[2])
                  .Complete();
            }))
        .RetiresOnSaturation();

    // Trigger upload.
    SetExpectedUploadsCount();
    FlushOrDie(MANUAL_BATCH);
  }
}

INSTANTIATE_TEST_SUITE_P(
    VaryingFileSize,
    LegacyStorageTest,
    ::testing::Combine(::testing::Bool() /* true - encryption enabled */,
                       ::testing::Values(128u * 1024uLL * 1024uLL,
                                         256u /* two records in file */,
                                         1u /* single record in file */)));

}  // namespace
}  // namespace reporting

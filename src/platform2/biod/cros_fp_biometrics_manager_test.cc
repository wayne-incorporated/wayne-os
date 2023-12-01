// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "biod/cros_fp_biometrics_manager.h"

#include <algorithm>
#include <optional>
#include <utility>

#include <base/base64.h>
#include <base/functional/bind.h>
#include <base/test/task_environment.h>
#include <dbus/mock_bus.h>
#include <dbus/mock_object_proxy.h>
#include <gtest/gtest.h>
#include <libec/fingerprint/cros_fp_device_interface.h>

#include "base/time/time.h"
#include "biod/biod_crypto.h"
#include "biod/biod_crypto_test_data.h"
#include "biod/mock_biod_metrics.h"
#include "biod/mock_cros_fp_biometrics_manager.h"
#include "biod/mock_cros_fp_device.h"
#include "biod/mock_cros_fp_record_manager.h"
#include "ec/ec_commands.h"
#include "libec/fingerprint/fp_mode.h"
#include "libec/fingerprint/fp_sensor_errors.h"

namespace biod {

using Mode = ec::FpMode::Mode;

namespace {
constexpr int kMaxPartialAttempts = 20;
constexpr int kMaxTemplateCount = 5;
constexpr char kRecordID[] = "record0";
constexpr char kData1[] = "some_super_interesting_data1";
constexpr char kLabel[] = "label0";
constexpr char kTemplateMetadataVersion0[] =
    "AAAdY8N2B+A/3Bz/Z7jZQId8OTgBksdFxjlWXzZ4lRg/GhE+MazZtq6M2tcMUk7e";
constexpr char kTemplateMetadataVersion1[] =
    "AQDPIyylfuu1jT+nf5x3WHdWnunhRyVh5tIu4jo+mM0rztdi50id7XMFPycVJHoR";
}  // namespace

using crypto_test_data::kFakePositiveMatchSecret1;
using crypto_test_data::kFakePositiveMatchSecret2;
using crypto_test_data::kFakeValidationValue1;
using crypto_test_data::kFakeValidationValue2;
using crypto_test_data::kUserID;

using testing::_;
using testing::ByMove;
using testing::DoAll;
using testing::Return;
using testing::ReturnRef;
using testing::SaveArg;

// Using a peer class to control access to the class under test is better than
// making the text fixture a friend class.
class CrosFpBiometricsManagerPeer {
 public:
  explicit CrosFpBiometricsManagerPeer(
      std::unique_ptr<CrosFpBiometricsManager> cros_fp_biometrics_manager)
      : cros_fp_biometrics_manager_(std::move(cros_fp_biometrics_manager)) {}

  // Methods to execute CrosFpBiometricsManager private methods.

  bool ValidationValueEquals(const std::string& id,
                             const std::vector<uint8_t>& reference_value) {
    return cros_fp_biometrics_manager_->GetRecordMetadata(id)->validation_val ==
           reference_value;
  }

  bool ComputeValidationValue(const brillo::SecureVector& secret,
                              const std::string& user_id,
                              std::vector<uint8_t>* out) {
    return BiodCrypto::ComputeValidationValue(secret, user_id, out);
  }

  bool CheckPositiveMatchSecret(const std::string& record_id, int match_idx) {
    return cros_fp_biometrics_manager_->CheckPositiveMatchSecret(record_id,
                                                                 match_idx);
  }

  void AddLoadedRecord(const std::string& record_id) {
    cros_fp_biometrics_manager_->loaded_records_.emplace_back(record_id);
  }

 private:
  std::unique_ptr<CrosFpBiometricsManager> cros_fp_biometrics_manager_;
};

class CrosFpBiometricsManagerTest : public ::testing::Test {
 public:
  CrosFpBiometricsManagerTest() {
    dbus::Bus::Options options;
    options.bus_type = dbus::Bus::SYSTEM;
    const auto mock_bus = base::MakeRefCounted<dbus::MockBus>(options);

    // Set EXPECT_CALL, otherwise gmock forces an failure due to "uninteresting
    // call" because we use StrictMock.
    // https://github.com/google/googletest/blob/fb49e6c164490a227bbb7cf5223b846c836a0305/googlemock/docs/cook_book.md#the-nice-the-strict-and-the-naggy-nicestrictnaggy
    const auto power_manager_proxy =
        base::MakeRefCounted<dbus::MockObjectProxy>(
            mock_bus.get(), power_manager::kPowerManagerServiceName,
            dbus::ObjectPath(power_manager::kPowerManagerServicePath));
    EXPECT_CALL(*mock_bus,
                GetObjectProxy(
                    power_manager::kPowerManagerServiceName,
                    dbus::ObjectPath(power_manager::kPowerManagerServicePath)))
        .WillOnce(testing::Return(power_manager_proxy.get()));

    auto mock_cros_dev = std::make_unique<MockCrosFpDevice>();
    // Keep a pointer to the fake device to manipulate it later.
    mock_cros_dev_ = mock_cros_dev.get();

    auto mock_record_manager = std::make_unique<MockCrosFpRecordManager>();
    // Keep a pointer to record manager, to manipulate it later.
    mock_record_manager_ = mock_record_manager.get();

    // Always support positive match secret
    EXPECT_CALL(*mock_cros_dev_, SupportsPositiveMatchSecret())
        .WillRepeatedly(Return(true));

    // Save OnMkbpEvent callback to use later in tests
    ON_CALL(*mock_cros_dev_, SetMkbpEventCallback)
        .WillByDefault(SaveArg<0>(&on_mkbp_event_));

    mock_metrics_ = std::make_unique<metrics::MockBiodMetrics>();

    auto cros_fp_biometrics_manager = std::make_unique<CrosFpBiometricsManager>(
        PowerButtonFilter::Create(mock_bus), std::move(mock_cros_dev),
        mock_metrics_.get(), std::move(mock_record_manager));
    cros_fp_biometrics_manager_ = cros_fp_biometrics_manager.get();

    // Register OnAuthScanDone and OnSessionFailed callbacks which are actually
    // mocks. That way we can conveniently handle these calls without
    // using lambda.
    cros_fp_biometrics_manager_->SetAuthScanDoneHandler(
        base::BindRepeating(&CrosFpBiometricsManagerTest::AuthScanDoneHandler,
                            base::Unretained(this)));
    cros_fp_biometrics_manager_->SetSessionFailedHandler(
        base::BindRepeating(&CrosFpBiometricsManagerTest::SessionFailedHandler,
                            base::Unretained(this)));

    cros_fp_biometrics_manager_peer_.emplace(
        std::move(cros_fp_biometrics_manager));
  }

  MOCK_METHOD(void,
              AuthScanDoneHandler,
              (biod::FingerprintMessage result,
               BiometricsManager::AttemptMatches matches));
  MOCK_METHOD(void, SessionFailedHandler, ());

 protected:
  std::optional<CrosFpBiometricsManagerPeer> cros_fp_biometrics_manager_peer_;
  std::unique_ptr<metrics::MockBiodMetrics> mock_metrics_;
  MockCrosFpRecordManager* mock_record_manager_;
  MockCrosFpDevice* mock_cros_dev_;
  CrosFpBiometricsManager* cros_fp_biometrics_manager_;
  CrosFpDevice::MkbpCallback on_mkbp_event_;
  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
};

TEST_F(CrosFpBiometricsManagerTest, TestComputeValidationValue) {
  const std::vector<std::pair<brillo::SecureVector, std::vector<uint8_t>>>
      kSecretValidationValuePairs = {
          std::make_pair(kFakePositiveMatchSecret1, kFakeValidationValue1),
          std::make_pair(kFakePositiveMatchSecret2, kFakeValidationValue2),
      };
  for (const auto& pair : kSecretValidationValuePairs) {
    std::vector<uint8_t> validation_value;
    EXPECT_TRUE(cros_fp_biometrics_manager_peer_->ComputeValidationValue(
        pair.first, kUserID, &validation_value));
    EXPECT_EQ(validation_value, pair.second);
  }
}

TEST_F(CrosFpBiometricsManagerTest, TestValidationValueCalculation) {
  const BiodStorageInterface::RecordMetadata kMetadata1{
      kRecordFormatVersion, kRecordID, kUserID, kLabel, kFakeValidationValue1};

  EXPECT_CALL(*mock_record_manager_, GetRecordMetadata)
      .WillRepeatedly(Return(kMetadata1));
  EXPECT_CALL(*mock_cros_dev_, GetPositiveMatchSecret)
      .WillOnce(Return(kFakePositiveMatchSecret1));
  EXPECT_TRUE(
      cros_fp_biometrics_manager_peer_->CheckPositiveMatchSecret(kRecordID, 0));
}

TEST_F(CrosFpBiometricsManagerTest, TestPositiveMatchSecretIsCorrect) {
  const BiodStorageInterface::RecordMetadata kMetadata{
      kRecordFormatVersion, kRecordID, kUserID, kLabel, kFakeValidationValue1};
  EXPECT_CALL(*mock_record_manager_, GetRecordMetadata(kRecordID))
      .WillRepeatedly(Return(kMetadata));

  EXPECT_CALL(*mock_cros_dev_, GetPositiveMatchSecret)
      .WillOnce(Return(kFakePositiveMatchSecret1));
  EXPECT_TRUE(
      cros_fp_biometrics_manager_peer_->CheckPositiveMatchSecret(kRecordID, 0));
}

TEST_F(CrosFpBiometricsManagerTest, TestPositiveMatchSecretIsNotCorrect) {
  const BiodStorageInterface::RecordMetadata kMetadata{
      kRecordFormatVersion, kRecordID, kUserID, kLabel, kFakeValidationValue2};
  EXPECT_CALL(*mock_record_manager_, GetRecordMetadata(kRecordID))
      .WillRepeatedly(Return(kMetadata));

  EXPECT_CALL(*mock_cros_dev_, GetPositiveMatchSecret)
      .WillOnce(Return(kFakePositiveMatchSecret1));
  EXPECT_FALSE(
      cros_fp_biometrics_manager_peer_->CheckPositiveMatchSecret(kRecordID, 0));
}

TEST_F(CrosFpBiometricsManagerTest, TestCheckPositiveMatchSecretNoSecret) {
  EXPECT_CALL(*mock_cros_dev_, GetPositiveMatchSecret)
      .WillOnce(Return(std::nullopt));
  EXPECT_FALSE(
      cros_fp_biometrics_manager_peer_->CheckPositiveMatchSecret(kRecordID, 0));
}

TEST_F(CrosFpBiometricsManagerTest, TestInvalidRecordsAreDeletedWhileReading) {
  EXPECT_CALL(*mock_record_manager_, UserHasInvalidRecords(kUserID))
      .WillOnce(Return(true));
  EXPECT_CALL(*mock_record_manager_, DeleteInvalidRecords);

  EXPECT_FALSE(cros_fp_biometrics_manager_->ReadRecordsForSingleUser(kUserID));
}

TEST_F(CrosFpBiometricsManagerTest, TestCheckPositiveMatchSecret) {
  const BiodStorageInterface::RecordMetadata kMetadata{
      kRecordFormatVersion, kRecordID, kUserID, kLabel, kFakeValidationValue1};
  EXPECT_CALL(*mock_record_manager_, GetRecordMetadata(kRecordID))
      .WillRepeatedly(Return(kMetadata));
  EXPECT_CALL(*mock_cros_dev_, GetPositiveMatchSecret)
      .WillOnce(Return(kFakePositiveMatchSecret1));
  EXPECT_TRUE(
      cros_fp_biometrics_manager_peer_->CheckPositiveMatchSecret(kRecordID, 0));
}

TEST_F(CrosFpBiometricsManagerTest, TestLoadingTemplate) {
  std::string template_decoded;
  base::Base64Decode(kTemplateMetadataVersion0, &template_decoded);
  VendorTemplate tmpl(template_decoded.begin(), template_decoded.end());
  EXPECT_EQ(tmpl.size(), sizeof(struct ec_fp_template_encryption_metadata));

  // Expect that biod will send correct record data to FPMCU.
  EXPECT_CALL(*mock_cros_dev_, UploadTemplate(tmpl)).WillOnce(Return(true));

  std::vector<Record> user_records({{{kRecordFormatVersion, kRecordID, kUserID,
                                      kLabel, kFakeValidationValue1},
                                     kTemplateMetadataVersion0}});

  EXPECT_CALL(*mock_record_manager_, GetRecordsForUser)
      .WillOnce(Return(user_records));
  EXPECT_CALL(*mock_cros_dev_, MaxTemplateCount)
      .WillRepeatedly(Return(kMaxTemplateCount));
  EXPECT_TRUE(cros_fp_biometrics_manager_->ReadRecordsForSingleUser(kUserID));
}

TEST_F(CrosFpBiometricsManagerTest, TestLoadingTemplateUploadError) {
  std::vector<Record> user_records({{{kRecordFormatVersion, kRecordID, kUserID,
                                      kLabel, kFakeValidationValue1},
                                     kTemplateMetadataVersion0}});

  EXPECT_CALL(*mock_record_manager_, GetRecordsForUser)
      .WillOnce(Return(user_records));
  EXPECT_CALL(*mock_cros_dev_, MaxTemplateCount)
      .WillRepeatedly(Return(kMaxTemplateCount));
  EXPECT_CALL(*mock_cros_dev_, UploadTemplate).WillOnce(Return(false));
  // Still expect true, because there are no invalid records
  EXPECT_TRUE(cros_fp_biometrics_manager_->ReadRecordsForSingleUser(kUserID));
}

TEST_F(CrosFpBiometricsManagerTest, TestLoadingTemplateInvalidVersion) {
  std::vector<Record> user_records({{{kRecordFormatVersion, kRecordID, kUserID,
                                      kLabel, kFakeValidationValue1},
                                     kTemplateMetadataVersion1}});

  EXPECT_CALL(*mock_record_manager_, GetRecordsForUser)
      .WillOnce(Return(user_records));
  EXPECT_CALL(*mock_record_manager_, DeleteRecord(kRecordID))
      .WillOnce(Return(true));
  EXPECT_CALL(*mock_cros_dev_, MaxTemplateCount)
      .WillRepeatedly(Return(kMaxTemplateCount));
  EXPECT_CALL(*mock_cros_dev_, UploadTemplate).Times(0);
  // Still expect true, because there are no invalid records
  EXPECT_TRUE(cros_fp_biometrics_manager_->ReadRecordsForSingleUser(kUserID));
}

TEST_F(CrosFpBiometricsManagerTest, TestLoadingTemplateNoSpaceAvailable) {
  std::vector<Record> user_records({{{kRecordFormatVersion, kRecordID, kUserID,
                                      kLabel, kFakeValidationValue1},
                                     kData1}});

  EXPECT_CALL(*mock_record_manager_, GetRecordsForUser)
      .WillOnce(Return(user_records));
  EXPECT_CALL(*mock_cros_dev_, MaxTemplateCount).WillRepeatedly(Return(0));
  EXPECT_CALL(*mock_cros_dev_, UploadTemplate).Times(0);
  // Still expect true, because there are no invalid records
  EXPECT_TRUE(cros_fp_biometrics_manager_->ReadRecordsForSingleUser(kUserID));
}

TEST_F(CrosFpBiometricsManagerTest, TestAuthSessionStartStopSuccess) {
  BiometricsManager::AuthSession auth_session;

  // Expect that biod will ask FPMCU to set the match mode.
  EXPECT_CALL(*mock_cros_dev_, SetFpMode(ec::FpMode(Mode::kMatch)))
      .WillOnce(Return(true));

  // Start auth session.
  auth_session = cros_fp_biometrics_manager_->StartAuthSession();
  EXPECT_TRUE(auth_session);

  // When auth session ends, FP mode will be set to kNone.
  EXPECT_CALL(*mock_cros_dev_, SetFpMode(ec::FpMode(Mode::kNone)))
      .WillOnce(Return(true));

  // Stop auth session
  auth_session.End();
}

TEST_F(CrosFpBiometricsManagerTest, TestStartEnrollSessionSuccess) {
  BiometricsManager::EnrollSession enroll_session;

  // Expect biod will check if there is space for a new template.
  EXPECT_CALL(*mock_cros_dev_, MaxTemplateCount).WillOnce(Return(1));
  EXPECT_CALL(*mock_cros_dev_, SetFpMode(ec::FpMode(Mode::kNone)))
      .WillOnce(Return(true));

  // Expect that biod will ask FPMCU to set the enroll mode.
  EXPECT_CALL(*mock_cros_dev_,
              SetFpMode(ec::FpMode(Mode::kEnrollSessionEnrollImage)))
      .WillOnce(Return(true));

  // Expect biod not to return any fingerprint hardware errors.
  EXPECT_CALL(*mock_cros_dev_, GetHwErrors())
      .WillOnce(Return(ec::FpSensorErrors::kNone));

  enroll_session = cros_fp_biometrics_manager_->StartEnrollSession("0", "0");
  EXPECT_TRUE(enroll_session);
}

TEST_F(CrosFpBiometricsManagerTest, TestStartEnrollSessionHwFailure) {
  BiometricsManager::EnrollSession enroll_session;

  ON_CALL(*mock_cros_dev_, MaxTemplateCount).WillByDefault(Return(1));
  ON_CALL(*mock_cros_dev_,
          SetFpMode(ec::FpMode(Mode::kEnrollSessionEnrollImage)))
      .WillByDefault(Return(true));
  ON_CALL(*mock_cros_dev_, GetHwErrors())
      .WillByDefault(Return(ec::FpSensorErrors::kBadHardwareID));

  enroll_session = cros_fp_biometrics_manager_->StartEnrollSession("0", "0");
  EXPECT_FALSE(enroll_session);
  EXPECT_EQ(enroll_session.error(), "Fingerprint hardware is unavailable");
}

TEST_F(CrosFpBiometricsManagerTest, TestStartEnrollSessionTwiceFailed) {
  BiometricsManager::EnrollSession first_enroll_session;
  BiometricsManager::EnrollSession second_enroll_session;

  // Expect biod will check if there is space for a new template.
  EXPECT_CALL(*mock_cros_dev_, MaxTemplateCount).WillRepeatedly(Return(2));
  EXPECT_CALL(*mock_cros_dev_, SetFpMode(_)).WillRepeatedly(Return(true));

  first_enroll_session =
      cros_fp_biometrics_manager_->StartEnrollSession("0", "0");
  ASSERT_TRUE(first_enroll_session);

  second_enroll_session =
      cros_fp_biometrics_manager_->StartEnrollSession("0", "0");
  EXPECT_FALSE(second_enroll_session);
  EXPECT_EQ(second_enroll_session.error(),
            "Another EnrollSession already exists");
}

TEST_F(CrosFpBiometricsManagerTest, TestAuthSessionMatchModeFailed) {
  BiometricsManager::AuthSession auth_session;

  // Expect that biod will ask FPMCU to set the match mode.
  EXPECT_CALL(*mock_cros_dev_, SetFpMode(ec::FpMode(Mode::kMatch)))
      .WillOnce(Return(false));

  // Auth session should fail to start when FPMCU refuses to set match mode.
  auth_session = cros_fp_biometrics_manager_->StartAuthSession();
  EXPECT_FALSE(auth_session);
  EXPECT_EQ(auth_session.error(), "Match was not requested");
}

TEST_F(CrosFpBiometricsManagerTest, TestStartAuthSessionHwFailure) {
  BiometricsManager::AuthSession auth_session;

  ON_CALL(*mock_cros_dev_, SetFpMode(ec::FpMode(Mode::kMatch)))
      .WillByDefault(Return(true));
  ON_CALL(*mock_cros_dev_, GetHwErrors())
      .WillByDefault(Return(ec::FpSensorErrors::kBadHardwareID));

  auth_session = cros_fp_biometrics_manager_->StartAuthSession();
  EXPECT_FALSE(auth_session);
  EXPECT_EQ(auth_session.error(), "Fingerprint hardware is unavailable");
}

TEST_F(CrosFpBiometricsManagerTest, TestDoEnrollImageEventSuccess) {
  // Start an enrollment sessions without performing all checks since this is
  // already tested by TestStartEnrollSessionSuccess.
  BiometricsManager::EnrollSession enroll_session;
  EXPECT_CALL(*mock_cros_dev_, MaxTemplateCount).WillOnce(Return(1));
  EXPECT_CALL(*mock_cros_dev_, SetFpMode(_)).WillRepeatedly(Return(true));
  enroll_session = cros_fp_biometrics_manager_->StartEnrollSession("0", "0");
  ASSERT_TRUE(enroll_session);

  // Simulate 4 finger touches and expect UMA to be sent with correct value.
  EXPECT_CALL(*mock_metrics_, SendEnrollmentCapturesCount(4)).Times(1);

  on_mkbp_event_.Run(EC_MKBP_FP_ENROLL | EC_MKBP_FP_ERR_ENROLL_IMMOBILE |
                     25 << EC_MKBP_FP_ENROLL_PROGRESS_OFFSET);
  on_mkbp_event_.Run(EC_MKBP_FP_FINGER_UP);
  on_mkbp_event_.Run(EC_MKBP_FP_ENROLL | EC_MKBP_FP_ERR_ENROLL_LOW_COVERAGE |
                     50 << EC_MKBP_FP_ENROLL_PROGRESS_OFFSET);
  on_mkbp_event_.Run(EC_MKBP_FP_FINGER_UP);
  on_mkbp_event_.Run(EC_MKBP_FP_ENROLL | EC_MKBP_FP_ERR_ENROLL_LOW_QUALITY |
                     75 << EC_MKBP_FP_ENROLL_PROGRESS_OFFSET);
  on_mkbp_event_.Run(EC_MKBP_FP_FINGER_UP);
  on_mkbp_event_.Run(EC_MKBP_FP_ENROLL | EC_MKBP_FP_ERR_ENROLL_OK |
                     100 << EC_MKBP_FP_ENROLL_PROGRESS_OFFSET);
}

TEST_F(CrosFpBiometricsManagerTest, TestAuthSessionRequestsFingerUp) {
  BiometricsManager::AuthSession auth_session;

  // Expect that biod will ask FPMCU to set the match mode.
  EXPECT_CALL(*mock_cros_dev_, SetFpMode(ec::FpMode(Mode::kMatch)))
      .WillOnce(Return(true));

  // Expect biod not to return any fingerprint hardware errors.
  EXPECT_CALL(*mock_cros_dev_, GetHwErrors())
      .WillOnce(Return(ec::FpSensorErrors::kNone));

  // Start auth session.
  auth_session = cros_fp_biometrics_manager_->StartAuthSession();
  EXPECT_TRUE(auth_session);

  // Biod will set FP mode to FingerUp, when calling on_mkbp_event_.Run.
  EXPECT_CALL(*mock_cros_dev_, SetFpMode(ec::FpMode(Mode::kFingerUp)))
      .WillOnce(Return(true));

  // When auth session ends, FP mode will be set to kNone.
  EXPECT_CALL(*mock_cros_dev_, SetFpMode(ec::FpMode(Mode::kNone)))
      .WillOnce(Return(true));

  // Send response from Cros FP. Finger up should be requested regardless of
  // response from FPMCU
  on_mkbp_event_.Run(EC_MKBP_FP_MATCH);
}

TEST_F(CrosFpBiometricsManagerTest, TestAuthSessionRequestsFingerUpFailed) {
  BiometricsManager::AuthSession auth_session;

  // Expect that biod will ask FPMCU to set the match mode.
  EXPECT_CALL(*mock_cros_dev_, SetFpMode(ec::FpMode(Mode::kMatch)))
      .WillOnce(Return(true));

  // Start auth session.
  auth_session = cros_fp_biometrics_manager_->StartAuthSession();
  EXPECT_TRUE(auth_session);

  // Biod will set FP mode to FingerUp, when calling on_mkbp_event_.
  EXPECT_CALL(*mock_cros_dev_, SetFpMode(ec::FpMode(Mode::kFingerUp)))
      .WillOnce(Return(false));

  // Expect that OnSessionFailed callback is called.
  EXPECT_CALL(*this, SessionFailedHandler).Times(1);

  // When auth session ends, FP mode will be set to kNone.
  EXPECT_CALL(*mock_cros_dev_, SetFpMode(ec::FpMode(Mode::kNone)))
      .WillOnce(Return(true));

  // Send response from Cros FP. Finger up should be requested regardless of
  // response from FPMCU
  on_mkbp_event_.Run(EC_MKBP_FP_MATCH);
}

TEST_F(CrosFpBiometricsManagerTest, TestAuthSessionSuccessNoUpdate) {
  BiometricsManager::AuthSession auth_session;
  const BiodStorageInterface::RecordMetadata kMetadata{
      kRecordFormatVersion, kRecordID, kUserID, kLabel, kFakeValidationValue1};
  const BiometricsManager::AttemptMatches kExpectedMatches(
      {{std::string(kUserID), std::vector<std::string>({kRecordID})}});
  BiometricsManager::AttemptMatches received_matches;
  biod::FingerprintMessage msg;

  // Give record details if asked.
  EXPECT_CALL(*mock_record_manager_, GetRecordMetadata)
      .WillRepeatedly(Return(kMetadata));

  // Always allow setting FP mode.
  EXPECT_CALL(*mock_cros_dev_, SetFpMode).WillRepeatedly(Return(true));

  // Pretend that we have some records loaded.
  cros_fp_biometrics_manager_peer_->AddLoadedRecord(kMetadata.record_id);

  EXPECT_CALL(*this, AuthScanDoneHandler)
      .WillOnce(DoAll(SaveArg<0>(&msg), SaveArg<1>(&received_matches)));

  // Start auth session.
  auth_session = cros_fp_biometrics_manager_->StartAuthSession();
  EXPECT_TRUE(auth_session);

  EXPECT_CALL(*mock_cros_dev_, GetPositiveMatchSecret)
      .WillOnce(Return(kFakePositiveMatchSecret1));

  // Send response from Cros FP.
  on_mkbp_event_.Run(EC_MKBP_FP_MATCH | EC_MKBP_FP_ERR_MATCH_YES);

  EXPECT_EQ(msg.msg_case(), biod::FingerprintMessage::MsgCase::kScanResult);
  EXPECT_EQ(msg.scan_result(), ScanResult::SCAN_RESULT_SUCCESS);
  EXPECT_EQ(received_matches, kExpectedMatches);
}

TEST_F(CrosFpBiometricsManagerTest, TestAuthSessionFailedInvalidTemplate) {
  BiometricsManager::AuthSession auth_session;
  const BiodStorageInterface::RecordMetadata kMetadata{
      kRecordFormatVersion, kRecordID, kUserID, kLabel, kFakeValidationValue1};
  BiometricsManager::AttemptMatches received_matches;
  biod::FingerprintMessage msg;

  // Always allow setting FP mode.
  EXPECT_CALL(*mock_cros_dev_, SetFpMode).WillRepeatedly(Return(true));

  // No records are loaded, so don't expect asking for record details.
  EXPECT_CALL(*mock_record_manager_, GetRecordMetadata).Times(0);

  EXPECT_CALL(*this, AuthScanDoneHandler)
      .WillOnce(DoAll(SaveArg<0>(&msg), SaveArg<1>(&received_matches)));

  // Start auth session.
  auth_session = cros_fp_biometrics_manager_->StartAuthSession();
  EXPECT_TRUE(auth_session);

  // Send response from Cros FP.
  on_mkbp_event_.Run(EC_MKBP_FP_MATCH | EC_MKBP_FP_ERR_MATCH_YES);

  EXPECT_EQ(msg.msg_case(), biod::FingerprintMessage::MsgCase::kError);
  EXPECT_EQ(msg.error(), FingerprintError::ERROR_UNABLE_TO_PROCESS);
  EXPECT_TRUE(received_matches.empty());
}

TEST_F(CrosFpBiometricsManagerTest,
       TestAuthSessionFailedInvalidPositiveMatchSecret) {
  BiometricsManager::AuthSession auth_session;
  const BiodStorageInterface::RecordMetadata kMetadata{
      kRecordFormatVersion, kRecordID, kUserID, kLabel, kFakeValidationValue1};
  BiometricsManager::AttemptMatches received_matches;
  biod::FingerprintMessage msg;

  // Give record details if asked.
  EXPECT_CALL(*mock_record_manager_, GetRecordMetadata)
      .WillRepeatedly(Return(kMetadata));

  // Always allow setting FP mode.
  EXPECT_CALL(*mock_cros_dev_, SetFpMode).WillRepeatedly(Return(true));

  // Pretend that we have some records loaded.
  cros_fp_biometrics_manager_peer_->AddLoadedRecord(kMetadata.record_id);

  EXPECT_CALL(*this, AuthScanDoneHandler)
      .WillOnce(DoAll(SaveArg<0>(&msg), SaveArg<1>(&received_matches)));

  // Start auth session.
  auth_session = cros_fp_biometrics_manager_->StartAuthSession();
  EXPECT_TRUE(auth_session);

  // Return wrong Positive Match Secret.
  EXPECT_CALL(*mock_cros_dev_, GetPositiveMatchSecret)
      .WillOnce(Return(kFakePositiveMatchSecret2));

  // Send response from Cros FP.
  on_mkbp_event_.Run(EC_MKBP_FP_MATCH | EC_MKBP_FP_ERR_MATCH_YES);

  // Expected values when Positive Match Secret is not correct.
  EXPECT_EQ(msg.msg_case(), biod::FingerprintMessage::MsgCase::kError);
  EXPECT_EQ(msg.error(), FingerprintError::ERROR_UNABLE_TO_PROCESS);
  EXPECT_TRUE(received_matches.empty());
}

TEST_F(CrosFpBiometricsManagerTest, TestAuthSessionMatchNo) {
  BiometricsManager::AuthSession auth_session;
  const BiodStorageInterface::RecordMetadata kMetadata{
      kRecordFormatVersion, kRecordID, kUserID, kLabel, kFakeValidationValue1};
  BiometricsManager::AttemptMatches received_matches;
  biod::FingerprintMessage msg;

  // Always allow setting FP mode.
  EXPECT_CALL(*mock_cros_dev_, SetFpMode).WillRepeatedly(Return(true));

  // If result is different than MATCH_YES, then we expect to receive
  // empty matches.
  EXPECT_CALL(*this, AuthScanDoneHandler)
      .WillOnce(DoAll(SaveArg<0>(&msg), SaveArg<1>(&received_matches)));

  // Start auth session.
  auth_session = cros_fp_biometrics_manager_->StartAuthSession();
  EXPECT_TRUE(auth_session);

  // Send response from Cros FP.
  on_mkbp_event_.Run(EC_MKBP_FP_MATCH | EC_MKBP_FP_ERR_MATCH_NO);

  EXPECT_EQ(msg.msg_case(), biod::FingerprintMessage::MsgCase::kScanResult);
  EXPECT_EQ(msg.scan_result(), ScanResult::SCAN_RESULT_NO_MATCH);
  EXPECT_TRUE(received_matches.empty());
}

TEST_F(CrosFpBiometricsManagerTest, TestAuthSessionMatchNoTemplates) {
  BiometricsManager::AuthSession auth_session;
  const BiodStorageInterface::RecordMetadata kMetadata{
      kRecordFormatVersion, kRecordID, kUserID, kLabel, kFakeValidationValue1};
  BiometricsManager::AttemptMatches received_matches;
  biod::FingerprintMessage msg;

  // Always allow setting FP mode.
  EXPECT_CALL(*mock_cros_dev_, SetFpMode).WillRepeatedly(Return(true));

  EXPECT_CALL(*this, AuthScanDoneHandler)
      .WillOnce(DoAll(SaveArg<0>(&msg), SaveArg<1>(&received_matches)));

  // Start auth session.
  auth_session = cros_fp_biometrics_manager_->StartAuthSession();
  EXPECT_TRUE(auth_session);

  // Send response from Cros FP.
  on_mkbp_event_.Run(EC_MKBP_FP_MATCH | EC_MKBP_FP_ERR_MATCH_NO_TEMPLATES);

  // Expected values when FPMCU reports no templates.
  EXPECT_EQ(msg.msg_case(), biod::FingerprintMessage::MsgCase::kError);
  EXPECT_EQ(msg.error(), FingerprintError::ERROR_NO_TEMPLATES);
  EXPECT_TRUE(received_matches.empty());
}

TEST_F(CrosFpBiometricsManagerTest, TestAuthSessionMatchNoInternal) {
  BiometricsManager::AuthSession auth_session;
  const BiodStorageInterface::RecordMetadata kMetadata{
      kRecordFormatVersion, kRecordID, kUserID, kLabel, kFakeValidationValue1};
  BiometricsManager::AttemptMatches received_matches;
  biod::FingerprintMessage msg;

  // Always allow setting FP mode.
  EXPECT_CALL(*mock_cros_dev_, SetFpMode).WillRepeatedly(Return(true));

  EXPECT_CALL(*this, AuthScanDoneHandler)
      .WillOnce(DoAll(SaveArg<0>(&msg), SaveArg<1>(&received_matches)));

  // Start auth session.
  auth_session = cros_fp_biometrics_manager_->StartAuthSession();
  EXPECT_TRUE(auth_session);

  // Send response from Cros FP.
  on_mkbp_event_.Run(EC_MKBP_FP_MATCH | EC_MKBP_FP_ERR_MATCH_NO_INTERNAL);

  // Expected values when FPMCU reports internal error.
  EXPECT_EQ(msg.msg_case(), biod::FingerprintMessage::MsgCase::kError);
  EXPECT_EQ(msg.error(), FingerprintError::ERROR_UNABLE_TO_PROCESS);
  EXPECT_TRUE(received_matches.empty());
}

TEST_F(CrosFpBiometricsManagerTest, TestAuthSessionMatchNoLowQuality) {
  BiometricsManager::AuthSession auth_session;
  const BiodStorageInterface::RecordMetadata kMetadata{
      kRecordFormatVersion, kRecordID, kUserID, kLabel, kFakeValidationValue1};
  BiometricsManager::AttemptMatches received_matches;
  biod::FingerprintMessage msg;

  // Always allow setting FP mode.
  EXPECT_CALL(*mock_cros_dev_, SetFpMode).WillRepeatedly(Return(true));

  EXPECT_CALL(*this, AuthScanDoneHandler)
      .WillOnce(DoAll(SaveArg<0>(&msg), SaveArg<1>(&received_matches)));

  // Start auth session.
  auth_session = cros_fp_biometrics_manager_->StartAuthSession();
  EXPECT_TRUE(auth_session);

  // Send response from Cros FP.
  on_mkbp_event_.Run(EC_MKBP_FP_MATCH | EC_MKBP_FP_ERR_MATCH_NO_LOW_QUALITY);

  // Expected values when FPMCU reports scan is low quality.
  EXPECT_EQ(msg.msg_case(), biod::FingerprintMessage::MsgCase::kScanResult);
  EXPECT_EQ(msg.scan_result(), ScanResult::SCAN_RESULT_INSUFFICIENT);
  EXPECT_TRUE(received_matches.empty());
}

TEST_F(CrosFpBiometricsManagerTest, TestAuthSessionMatchNoLowCoverage) {
  BiometricsManager::AuthSession auth_session;
  const BiodStorageInterface::RecordMetadata kMetadata{
      kRecordFormatVersion, kRecordID, kUserID, kLabel, kFakeValidationValue1};
  BiometricsManager::AttemptMatches received_matches;
  biod::FingerprintMessage msg;

  // Always allow setting FP mode.
  EXPECT_CALL(*mock_cros_dev_, SetFpMode).WillRepeatedly(Return(true));

  EXPECT_CALL(*this, AuthScanDoneHandler)
      .WillOnce(DoAll(SaveArg<0>(&msg), SaveArg<1>(&received_matches)));

  // Start auth session.
  auth_session = cros_fp_biometrics_manager_->StartAuthSession();
  EXPECT_TRUE(auth_session);

  // Send response from Cros FP.
  // DoMatchEvent will automatically retry the LOW_COVERAGE event (without
  // ending the AuthSession) up to kMaxPartialAttempts times.
  // When kMaxPartialAttempts is reached, AuthScanDoneHandler will be
  // called with SCAN_RESULT_PARTIAL.
  for (int i = 0; i < kMaxPartialAttempts + 1; i++) {
    on_mkbp_event_.Run(EC_MKBP_FP_MATCH | EC_MKBP_FP_ERR_MATCH_NO_LOW_COVERAGE);
  }

  // Expected values when FPMCU reports scan has low coverage.
  EXPECT_EQ(msg.msg_case(), biod::FingerprintMessage::MsgCase::kScanResult);
  EXPECT_EQ(msg.scan_result(), ScanResult::SCAN_RESULT_PARTIAL);
  EXPECT_TRUE(received_matches.empty());
}

TEST_F(CrosFpBiometricsManagerTest, TestAuthSessionSuccessAfterLowCoverage) {
  BiometricsManager::AuthSession auth_session;
  const BiodStorageInterface::RecordMetadata kMetadata{
      kRecordFormatVersion, kRecordID, kUserID, kLabel, kFakeValidationValue1};
  const BiometricsManager::AttemptMatches kExpectedMatches(
      {{std::string(kUserID), std::vector<std::string>({kRecordID})}});
  BiometricsManager::AttemptMatches received_matches;
  biod::FingerprintMessage msg;

  // Give record details if asked.
  EXPECT_CALL(*mock_record_manager_, GetRecordMetadata)
      .WillRepeatedly(Return(kMetadata));

  // Always allow setting FP mode.
  EXPECT_CALL(*mock_cros_dev_, SetFpMode).WillRepeatedly(Return(true));

  EXPECT_CALL(*mock_metrics_,
              SendPartialAttemptsBeforeSuccess(kMaxPartialAttempts / 2))
      .Times(1);

  // Pretend that we have some records loaded.
  cros_fp_biometrics_manager_peer_->AddLoadedRecord(kMetadata.record_id);

  // Start auth session.
  auth_session = cros_fp_biometrics_manager_->StartAuthSession();
  EXPECT_TRUE(auth_session);

  // Send LOW_COVERAGE for kMaxPartialAttempts/2 times then send MATCH_YES.
  // DoMatchEvent will automatically retry the LOW_COVERAGE event (without
  // ending the AuthSession) up to kMaxPartialAttempts times.
  for (int i = 0; i < kMaxPartialAttempts / 2; i++) {
    on_mkbp_event_.Run(EC_MKBP_FP_MATCH | EC_MKBP_FP_ERR_MATCH_NO_LOW_COVERAGE);
  }

  EXPECT_CALL(*mock_cros_dev_, GetPositiveMatchSecret)
      .WillOnce(Return(kFakePositiveMatchSecret1));

  EXPECT_CALL(*this, AuthScanDoneHandler)
      .WillOnce(DoAll(SaveArg<0>(&msg), SaveArg<1>(&received_matches)));

  on_mkbp_event_.Run(EC_MKBP_FP_MATCH | EC_MKBP_FP_ERR_MATCH_YES);

  EXPECT_EQ(msg.msg_case(), biod::FingerprintMessage::MsgCase::kScanResult);
  EXPECT_EQ(msg.scan_result(), ScanResult::SCAN_RESULT_SUCCESS);
  EXPECT_EQ(received_matches, kExpectedMatches);
}

TEST_F(CrosFpBiometricsManagerTest, TestAuthSessionMatchUnknownCode) {
  BiometricsManager::AuthSession auth_session;

  // Always allow setting FP mode.
  EXPECT_CALL(*mock_cros_dev_, SetFpMode).WillRepeatedly(Return(true));

  // When code from FPMCU is unknown a failure is expected..
  EXPECT_CALL(*this, AuthScanDoneHandler).Times(0);
  EXPECT_CALL(*this, SessionFailedHandler).Times(1);

  // Start auth session.
  auth_session = cros_fp_biometrics_manager_->StartAuthSession();
  EXPECT_TRUE(auth_session);

  // Send response from Cros FP.
  on_mkbp_event_.Run(EC_MKBP_FP_MATCH | 15);
}

TEST_F(CrosFpBiometricsManagerTest, TestAuthSessionSuccessUpdated) {
  BiometricsManager::AuthSession auth_session;
  const BiodStorageInterface::RecordMetadata kMetadata{
      kRecordFormatVersion, kRecordID, kUserID, kLabel, kFakeValidationValue1};
  const BiometricsManager::AttemptMatches kExpectedMatches(
      {{std::string(kUserID), std::vector<std::string>({kRecordID})}});
  BiometricsManager::AttemptMatches received_matches;
  biod::FingerprintMessage msg;

  // Give record details if asked.
  EXPECT_CALL(*mock_record_manager_, GetRecordMetadata)
      .WillRepeatedly(Return(kMetadata));

  // Always allow setting FP mode.
  EXPECT_CALL(*mock_cros_dev_, SetFpMode).WillRepeatedly(Return(true));

  // Pretend that we have some records loaded.
  cros_fp_biometrics_manager_peer_->AddLoadedRecord(kMetadata.record_id);

  EXPECT_CALL(*this, AuthScanDoneHandler)
      .WillOnce(DoAll(SaveArg<0>(&msg), SaveArg<1>(&received_matches)));

  // Start auth session.
  auth_session = cros_fp_biometrics_manager_->StartAuthSession();
  EXPECT_TRUE(auth_session);

  EXPECT_CALL(*mock_cros_dev_, GetPositiveMatchSecret)
      .WillOnce(Return(kFakePositiveMatchSecret1));

  // Return information that template 0 was updated
  EXPECT_CALL(*mock_cros_dev_, GetDirtyMap)
      .WillOnce(Return(std::bitset<32>(1)));

  EXPECT_CALL(*mock_cros_dev_, GetTemplate)
      .WillOnce(Return(ByMove(std::make_unique<VendorTemplate>())));

  EXPECT_CALL(*mock_record_manager_, UpdateRecord(kMetadata, _))
      .WillOnce(Return(true));

  // Send response from Cros FP.
  on_mkbp_event_.Run(EC_MKBP_FP_MATCH | EC_MKBP_FP_ERR_MATCH_YES_UPDATED);

  EXPECT_EQ(msg.msg_case(), biod::FingerprintMessage::MsgCase::kScanResult);
  EXPECT_EQ(msg.scan_result(), ScanResult::SCAN_RESULT_SUCCESS);
  EXPECT_EQ(received_matches, kExpectedMatches);
}

class CrosFpBiometricsManagerMockTest : public ::testing::Test {
 protected:
  CrosFpBiometricsManagerMockTest() {
    dbus::Bus::Options options;
    options.bus_type = dbus::Bus::SYSTEM;
    const auto mock_bus = base::MakeRefCounted<dbus::MockBus>(options);

    // Set EXPECT_CALL, otherwise gmock forces an failure due to "uninteresting
    // call" because we use StrictMock.
    // https://github.com/google/googletest/blob/fb49e6c164490a227bbb7cf5223b846c836a0305/googlemock/docs/cook_book.md#the-nice-the-strict-and-the-naggy-nicestrictnaggy
    power_manager_proxy_ = base::MakeRefCounted<dbus::MockObjectProxy>(
        mock_bus.get(), power_manager::kPowerManagerServiceName,
        dbus::ObjectPath(power_manager::kPowerManagerServicePath));
    EXPECT_CALL(*mock_bus,
                GetObjectProxy(
                    power_manager::kPowerManagerServiceName,
                    dbus::ObjectPath(power_manager::kPowerManagerServicePath)))
        .WillOnce(testing::Return(power_manager_proxy_.get()));

    // Keep a pointer to the mocks so they can be used in the tests. The
    // pointers must come after the MockCrosFpBiometricsManager pointer in the
    // class so that MockCrosFpBiometricsManager outlives the bare pointers,
    // since MockCrosFpBiometricsManager maintains ownership of the underlying
    // objects.
    auto mock_cros_fp_dev = std::make_unique<MockCrosFpDevice>();
    mock_cros_dev_ = mock_cros_fp_dev.get();
    auto mock_record_manager = std::make_unique<MockCrosFpRecordManager>();
    mock_record_manager_ = mock_record_manager.get();

    mock_metrics_ = std::make_unique<metrics::MockBiodMetrics>();
    EXPECT_CALL(*mock_cros_dev_, SupportsPositiveMatchSecret())
        .WillRepeatedly(Return(true));

    mock_ = std::make_unique<MockCrosFpBiometricsManager>(
        PowerButtonFilter::Create(mock_bus), std::move(mock_cros_fp_dev),
        mock_metrics_.get(), std::move(mock_record_manager));
    EXPECT_TRUE(mock_);
  }

  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
  scoped_refptr<dbus::MockObjectProxy> power_manager_proxy_;
  std::unique_ptr<metrics::MockBiodMetrics> mock_metrics_;
  std::unique_ptr<MockCrosFpBiometricsManager> mock_;
  MockCrosFpDevice* mock_cros_dev_;
  MockCrosFpRecordManager* mock_record_manager_;
};

TEST_F(CrosFpBiometricsManagerMockTest, TestMaintenanceTimer_TooShort) {
  EXPECT_CALL(*mock_, OnMaintenanceTimerFired).Times(0);
  task_environment_.FastForwardBy(base::Hours(12));
}

TEST_F(CrosFpBiometricsManagerMockTest, TestMaintenanceTimer_Once) {
  EXPECT_CALL(*mock_, OnMaintenanceTimerFired).Times(1);
  task_environment_.FastForwardBy(base::Days(1));
}

TEST_F(CrosFpBiometricsManagerMockTest, TestOnMaintenanceTimerFired) {
  constexpr int kNumDeadPixels = 1;
  const base::TimeDelta delta = base::Days(1);

  EXPECT_NE(mock_cros_dev_, nullptr);
  EXPECT_NE(mock_metrics_, nullptr);

  EXPECT_CALL(*mock_metrics_, SendDeadPixelCount(kNumDeadPixels)).Times(1);

  EXPECT_CALL(*mock_cros_dev_, DeadPixelCount)
      .WillOnce(testing::Return(kNumDeadPixels));

  EXPECT_CALL(*mock_cros_dev_, GetFpMode)
      .WillOnce(Return(ec::FpMode(Mode::kNone)));

  EXPECT_CALL(*mock_cros_dev_,
              SetFpMode(ec::FpMode(ec::FpMode::Mode::kSensorMaintenance)))
      .Times(1);
  EXPECT_CALL(*mock_, ScheduleMaintenance(delta)).Times(1);

  mock_->OnMaintenanceTimerFiredDelegate();
}

TEST_F(CrosFpBiometricsManagerMockTest, TestOnMaintenanceTimerRescheduled) {
  const base::TimeDelta delta = base::Minutes(10);
  EXPECT_NE(mock_cros_dev_, nullptr);

  EXPECT_CALL(*mock_cros_dev_, GetFpMode)
      .Times(1)
      .WillOnce(Return(ec::FpMode(Mode::kEnrollSession)));
  EXPECT_CALL(*mock_, ScheduleMaintenance(delta)).Times(1);

  mock_->OnMaintenanceTimerFiredDelegate();
}

TEST_F(CrosFpBiometricsManagerMockTest, TestGetDirtyList_Empty) {
  EXPECT_CALL(*mock_cros_dev_, GetDirtyMap).WillOnce(Return(std::bitset<32>()));
  auto dirty_list = mock_->GetDirtyList();
  EXPECT_EQ(dirty_list, std::vector<int>());
}

TEST_F(CrosFpBiometricsManagerMockTest, TestGetDirtyList) {
  EXPECT_CALL(*mock_cros_dev_, GetDirtyMap)
      .WillOnce(Return(std::bitset<32>("1001")));
  auto dirty_list = mock_->GetDirtyList();
  EXPECT_EQ(dirty_list, (std::vector<int>{0, 3}));
}

TEST_F(CrosFpBiometricsManagerMockTest, TestUpdateTemplatesOnDisk) {
  const BiodStorageInterface::RecordMetadata kMetadata{
      kRecordFormatVersion, kRecordID, kUserID, kLabel, kFakeValidationValue1};
  const std::vector<int> dirty_list = {0};
  const std::unordered_set<uint32_t> suspicious_templates;

  EXPECT_CALL(*mock_cros_dev_, GetTemplate)
      .WillOnce(Return(ByMove(std::make_unique<VendorTemplate>())));

  EXPECT_CALL(*mock_, GetLoadedRecordId(0)).WillRepeatedly(Return(kRecordID));
  EXPECT_CALL(*mock_record_manager_, GetRecordMetadata(kRecordID))
      .WillRepeatedly(Return(kMetadata));
  EXPECT_CALL(*mock_record_manager_, UpdateRecord(kMetadata, _))
      .WillOnce(Return(true));

  EXPECT_TRUE(mock_->UpdateTemplatesOnDisk(dirty_list, suspicious_templates));
}

TEST_F(CrosFpBiometricsManagerMockTest,
       TestUpdateTemplatesOnDisk_RecordNotAvailable) {
  const std::vector<int> dirty_list = {0};
  const std::unordered_set<uint32_t> suspicious_templates;

  EXPECT_CALL(*mock_, GetLoadedRecordId(0)).WillOnce(Return(std::nullopt));
  EXPECT_CALL(*mock_cros_dev_, GetTemplate).Times(0);
  EXPECT_CALL(*mock_record_manager_, UpdateRecord).Times(0);

  EXPECT_TRUE(mock_->UpdateTemplatesOnDisk(dirty_list, suspicious_templates));
}

TEST_F(CrosFpBiometricsManagerMockTest,
       TestUpdateTemplatesOnDisk_NoDirtyTemplates) {
  const std::vector<int> dirty_list;
  const std::unordered_set<uint32_t> suspicious_templates;

  EXPECT_CALL(*mock_record_manager_, UpdateRecord).Times(0);

  EXPECT_TRUE(mock_->UpdateTemplatesOnDisk(dirty_list, suspicious_templates));
}

TEST_F(CrosFpBiometricsManagerMockTest,
       TestUpdateTemplatesOnDisk_SkipSuspiciousTemplates) {
  const std::vector<int> dirty_list = {0};
  const std::unordered_set<uint32_t> suspicious_templates = {0};

  EXPECT_CALL(*mock_, GetLoadedRecordId(0)).WillRepeatedly(Return(kRecordID));
  EXPECT_CALL(*mock_record_manager_, UpdateRecord).Times(0);

  EXPECT_TRUE(mock_->UpdateTemplatesOnDisk(dirty_list, suspicious_templates));
}

TEST_F(CrosFpBiometricsManagerMockTest,
       TestUpdateTemplatesOnDisk_ErrorFetchingTemplate) {
  const std::vector<int> dirty_list = {0};
  const std::unordered_set<uint32_t> suspicious_templates;

  EXPECT_CALL(*mock_, GetLoadedRecordId(0)).WillRepeatedly(Return(kRecordID));
  EXPECT_CALL(*mock_cros_dev_, GetTemplate).Times(1);
  EXPECT_CALL(*mock_record_manager_, UpdateRecord).Times(0);

  EXPECT_TRUE(mock_->UpdateTemplatesOnDisk(dirty_list, suspicious_templates));
}

TEST_F(CrosFpBiometricsManagerMockTest, TestCallDeleteRecord) {
  EXPECT_CALL(*mock_cros_dev_, MaxTemplateCount).WillOnce(Return(5));

  EXPECT_CALL(*mock_record_manager_, DeleteRecord);

  struct ec_fp_template_encryption_metadata Data = {0};
  Data.struct_version = 0x3;  // Correct version is zero.
  const BiodStorageInterface::RecordMetadata mock_test_recordmetadata{
      1, kRecordID, kUserID, kLabel, kFakeValidationValue1};
  const BiodStorageInterface::Record mock_test_record{
      mock_test_recordmetadata,
      base::Base64Encode(base::as_bytes(base::make_span(&Data, sizeof(Data))))};
  mock_->LoadRecord(mock_test_record);
}

TEST_F(CrosFpBiometricsManagerMockTest, TestSkipDeleteRecord) {
  EXPECT_CALL(*mock_cros_dev_, MaxTemplateCount).WillOnce(Return(5));

  EXPECT_CALL(*mock_record_manager_, DeleteRecord).Times(0);

  struct ec_fp_template_encryption_metadata Data = {0};
  // Template version is zero because it comes from mock.
  const BiodStorageInterface::RecordMetadata mock_test_recordmetadata{
      1, kRecordID, kUserID, kLabel, kFakeValidationValue1};
  const BiodStorageInterface::Record mock_test_record{
      mock_test_recordmetadata,
      base::Base64Encode(base::as_bytes(base::make_span(&Data, sizeof(Data))))};
  mock_->LoadRecord(mock_test_record);
}

}  // namespace biod

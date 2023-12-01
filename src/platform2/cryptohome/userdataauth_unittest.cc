// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/userdataauth.h"

#include <algorithm>
#include <deque>
#include <limits>
#include <memory>
#include <optional>
#include <set>
#include <vector>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/location.h>
#include <base/stl_util.h>
#include <base/test/bind.h>
#include <base/test/test_future.h>
#include <base/test/test_mock_time_task_runner.h>
#include <base/time/time.h>
#include <brillo/cryptohome.h>
#include <brillo/errors/error_codes.h>
#include <chaps/token_manager_client_mock.h>
#include <cryptohome/proto_bindings/auth_factor.pb.h>
#include <cryptohome/proto_bindings/UserDataAuth.pb.h>
#include <dbus/mock_bus.h>
#include <featured/fake_platform_features.h>
#include <gmock/gmock.h>
#include <libhwsec/backend/mock_backend.h>
#include <libhwsec/error/tpm_error.h>
#include <libhwsec/factory/mock_factory.h>
#include <libhwsec/factory/tpm2_simulator_factory_for_test.h>
#include <libhwsec/frontend/cryptohome/mock_frontend.h>
#include <libhwsec/frontend/pinweaver/mock_frontend.h>
#include <libhwsec/frontend/recovery_crypto/mock_frontend.h>
#include <libhwsec/status.h>
#include <libhwsec-foundation/crypto/libscrypt_compat.h>
#include <libhwsec-foundation/crypto/secure_blob_util.h>
#include <libhwsec-foundation/crypto/sha.h>
#include <libhwsec-foundation/error/testing_helper.h>
#include <libhwsec-foundation/tpm/tpm_version.h>
#include <metrics/metrics_library_mock.h>

#include "cryptohome/auth_blocks/biometrics_auth_block_service.h"
#include "cryptohome/auth_blocks/fp_service.h"
#include "cryptohome/auth_blocks/mock_auth_block_utility.h"
#include "cryptohome/auth_blocks/mock_biometrics_command_processor.h"
#include "cryptohome/auth_factor/auth_factor_metadata.h"
#include "cryptohome/auth_factor/auth_factor_storage_type.h"
#include "cryptohome/auth_intent.h"
#include "cryptohome/challenge_credentials/challenge_credentials_helper.h"
#include "cryptohome/challenge_credentials/mock_challenge_credentials_helper.h"
#include "cryptohome/cleanup/mock_disk_cleanup.h"
#include "cryptohome/cleanup/mock_low_disk_space_handler.h"
#include "cryptohome/cleanup/mock_user_oldest_activity_timestamp_manager.h"
#include "cryptohome/common/print_UserDataAuth_proto.h"
#include "cryptohome/cryptohome_common.h"
#include "cryptohome/error/cryptohome_mount_error.h"
#include "cryptohome/fake_features.h"
#include "cryptohome/features.h"
#include "cryptohome/filesystem_layout.h"
#include "cryptohome/flatbuffer_schemas/auth_factor.h"
#include "cryptohome/mock_credential_verifier.h"
#include "cryptohome/mock_cryptohome_keys_manager.h"
#include "cryptohome/mock_fingerprint_manager.h"
#include "cryptohome/mock_firmware_management_parameters.h"
#include "cryptohome/mock_install_attributes.h"
#include "cryptohome/mock_key_challenge_service.h"
#include "cryptohome/mock_key_challenge_service_factory.h"
#include "cryptohome/mock_keyset_management.h"
#include "cryptohome/mock_le_credential_manager.h"
#include "cryptohome/mock_pkcs11_init.h"
#include "cryptohome/mock_platform.h"
#include "cryptohome/mock_vault_keyset.h"
#include "cryptohome/pkcs11/fake_pkcs11_token.h"
#include "cryptohome/pkcs11/mock_pkcs11_token_factory.h"
#include "cryptohome/protobuf_test_utils.h"
#include "cryptohome/storage/file_system_keyset.h"
#include "cryptohome/storage/homedirs.h"
#include "cryptohome/storage/mock_arc_disk_quota.h"
#include "cryptohome/storage/mock_homedirs.h"
#include "cryptohome/storage/mock_mount.h"
#include "cryptohome/storage/mock_mount_factory.h"
#include "cryptohome/user_secret_stash/user_secret_stash.h"
#include "cryptohome/user_session/mock_user_session.h"
#include "cryptohome/user_session/mock_user_session_factory.h"
#include "cryptohome/username.h"

using base::FilePath;
using base::test::TestFuture;
using brillo::SecureBlob;
using brillo::cryptohome::home::GetGuestUsername;
using brillo::cryptohome::home::SanitizeUserName;
using cryptohome::error::CryptohomeCryptoError;
using cryptohome::error::CryptohomeError;
using cryptohome::error::CryptohomeMountError;
using cryptohome::error::CryptohomeTPMError;
using cryptohome::error::ErrorActionSet;
using cryptohome::error::PossibleAction;
using cryptohome::error::PrimaryAction;

using ::hwsec::TPMError;
using ::hwsec::TPMErrorBase;
using ::hwsec::TPMRetryAction;
using ::hwsec_foundation::CreateSecureRandomBlob;
using ::hwsec_foundation::Sha1;
using ::hwsec_foundation::error::testing::IsOk;
using ::hwsec_foundation::error::testing::ReturnError;
using ::hwsec_foundation::error::testing::ReturnOk;
using ::hwsec_foundation::error::testing::ReturnValue;
using ::hwsec_foundation::status::MakeStatus;
using ::hwsec_foundation::status::OkStatus;
using ::hwsec_foundation::status::StatusChain;
using ::testing::_;
using ::testing::AtLeast;
using ::testing::ByMove;
using ::testing::DoAll;
using ::testing::ElementsAre;
using ::testing::ElementsAreArray;
using ::testing::EndsWith;
using ::testing::Eq;
using ::testing::InSequence;
using ::testing::Invoke;
using ::testing::IsEmpty;
using ::testing::NiceMock;
using ::testing::Pointee;
using ::testing::Property;
using ::testing::Return;
using ::testing::SaveArg;
using ::testing::SaveArgPointee;
using ::testing::SetArgPointee;
using ::testing::UnorderedElementsAre;

namespace cryptohome {

namespace {

// Set to match the 5 minute timer and a 1 minute extension in AuthSession.
constexpr int kAuthSessionExtensionDuration = 60;
constexpr auto kAuthSessionTimeout = base::Minutes(5);
constexpr auto kAuthSessionExtension =
    base::Seconds(kAuthSessionExtensionDuration);

// Fake labels to be in used in this test suite.
constexpr char kFakeLabel[] = "test_label";

ACTION_P(SetEphemeralSettings, ephemeral_settings) {
  *arg0 = ephemeral_settings;
  return true;
}
}  // namespace

// UserDataAuthTestBase is a test fixture that does not call
// UserDataAuth::Initialize() during setup. Therefore, it's suited to tests that
// can be conducted without calling UserDataAuth::Initialize(), or for tests
// that wants some flexibility before calling UserDataAuth::Initialize(), note
// that in this case the test have to call UserDataAuth::Initialize().
// Note: We shouldn't use this test fixture directly.
class UserDataAuthTestBase : public ::testing::Test {
 public:
  UserDataAuthTestBase() = default;
  UserDataAuthTestBase(const UserDataAuthTestBase&) = delete;
  UserDataAuthTestBase& operator=(const UserDataAuthTestBase&) = delete;

  ~UserDataAuthTestBase() override = default;

  void SetUp() override {
    // Note: If anything is modified/added here, we might need to adjust
    // UserDataAuthApiTest::SetUp() as well.

    SetupDefaultUserDataAuth();
    SetupHwsec();
  }

  void SetupHwsec() {
    userdataauth_->set_auth_block_utility(&auth_block_utility_);
    userdataauth_->set_keyset_management(&keyset_management_);
    userdataauth_->set_crypto(&crypto_);
    userdataauth_->set_hwsec_factory(&hwsec_factory_);
    userdataauth_->set_hwsec(&hwsec_);
    userdataauth_->set_cryptohome_keys_manager(&cryptohome_keys_manager_);
    userdataauth_->set_challenge_credentials_helper(
        &challenge_credentials_helper_);
    userdataauth_->set_user_session_factory(&user_session_factory_);
  }

  void SetupDefaultUserDataAuth() {
    SET_DEFAULT_TPM_FOR_TESTING;
    attrs_ = std::make_unique<NiceMock<MockInstallAttributes>>();
    dbus::Bus::Options options;
    options.bus_type = dbus::Bus::SYSTEM;
    mount_bus_ = base::MakeRefCounted<NiceMock<dbus::MockBus>>(options);
    ON_CALL(hwsec_, IsEnabled()).WillByDefault(ReturnValue(true));
    ON_CALL(hwsec_, IsReady()).WillByDefault(ReturnValue(true));
    ON_CALL(hwsec_, IsPinWeaverEnabled()).WillByDefault(ReturnValue(false));
    ON_CALL(hwsec_, IsSealingSupported()).WillByDefault(ReturnValue(true));
    ON_CALL(pinweaver_, IsEnabled()).WillByDefault(ReturnValue(true));
    ON_CALL(pinweaver_, GetVersion()).WillByDefault(ReturnValue(2));
    ON_CALL(pinweaver_, BlockGeneratePk()).WillByDefault(ReturnOk<TPMError>());

    if (!userdataauth_) {
      // Note that this branch is usually taken as |userdataauth_| is usually
      // NULL. The reason for this branch is because some derived-class of this
      // class (such as UserDataAuthTestThreaded) need to have the constructor
      // of UserDataAuth run on a specific thread, and therefore will construct
      // |userdataauth_| before calling UserDataAuthTestBase::SetUp().
      userdataauth_ = std::make_unique<UserDataAuth>();
    }

    userdataauth_->set_user_activity_timestamp_manager(
        &user_activity_timestamp_manager_);
    userdataauth_->set_install_attrs(attrs_.get());
    userdataauth_->set_homedirs(&homedirs_);
    userdataauth_->set_pinweaver(&pinweaver_);
    userdataauth_->set_recovery_crypto(&recovery_crypto_);
    userdataauth_->set_platform(&platform_);
    userdataauth_->set_chaps_client(&chaps_client_);
    userdataauth_->set_firmware_management_parameters(&fwmp_);
    userdataauth_->set_fingerprint_manager(&fingerprint_manager_);
    userdataauth_->set_arc_disk_quota(&arc_disk_quota_);
    userdataauth_->set_pkcs11_init(&pkcs11_init_);
    userdataauth_->set_pkcs11_token_factory(&pkcs11_token_factory_);
    userdataauth_->set_key_challenge_service_factory(
        &key_challenge_service_factory_);
    userdataauth_->set_low_disk_space_handler(&low_disk_space_handler_);

    {
      auto mock_processor =
          std::make_unique<NiceMock<MockBiometricsCommandProcessor>>();
      bio_processor_ = mock_processor.get();
      bio_service_ = std::make_unique<BiometricsAuthBlockService>(
          std::move(mock_processor),
          /*enroll_signal_sender=*/base::DoNothing(),
          /*auth_signal_sender=*/base::DoNothing());
    }
    userdataauth_->set_biometrics_service(bio_service_.get());
    userdataauth_->set_features(&features_.object);
    // Empty token list by default.  The effect is that there are no
    // attempts to unload tokens unless a test explicitly sets up the token
    // list.
    ON_CALL(chaps_client_, GetTokenList(_, _)).WillByDefault(Return(true));
    // Skip CleanUpStaleMounts by default.
    ON_CALL(platform_, GetMountsBySourcePrefix(_, _))
        .WillByDefault(Return(false));
    // ARC Disk Quota initialization will do nothing.
    ON_CALL(arc_disk_quota_, Initialize()).WillByDefault(Return());
    // Low Disk space handler initialization will do nothing.
    ON_CALL(low_disk_space_handler_, Init(_)).WillByDefault(Return(true));
    ON_CALL(low_disk_space_handler_, disk_cleanup())
        .WillByDefault(Return(&disk_cleanup_));

    // Make sure FreeDiskSpaceDuringLogin is not called unexpectedly.
    EXPECT_CALL(disk_cleanup_, FreeDiskSpaceDuringLogin(_)).Times(0);
  }

  // Create a new session and store an unowned pointer to it in |session_|.
  std::unique_ptr<NiceMock<MockUserSession>> CreateSessionAndRememberPtr() {
    auto owned_session = std::make_unique<NiceMock<MockUserSession>>();
    session_ = owned_session.get();
    return owned_session;
  }

  // This is a utility function for tests to setup a mount for a particular
  // user. After calling this function, |session_| is available for use.
  void SetupMount(const std::string& username) {
    EXPECT_TRUE(userdataauth_->AddUserSessionForTest(
        Username(username), CreateSessionAndRememberPtr()));
  }

  // This is a helper function that compute the obfuscated username with the
  // fake salt.
  ObfuscatedUsername GetObfuscatedUsername(const Username& username) {
    return SanitizeUserName(username);
  }

  // Helper function for creating a brillo::Error
  static brillo::ErrorPtr CreateDefaultError(const base::Location& from_here) {
    brillo::ErrorPtr error;
    brillo::Error::AddTo(&error, from_here, brillo::errors::dbus::kDomain,
                         DBUS_ERROR_FAILED, "Here's a fake error");
    return error;
  }

 protected:
  // Mock KeysetManagent object, will be passed to UserDataAuth for its internal
  // use.
  NiceMock<MockKeysetManagement> keyset_management_;

  // Mock AuthBlockUtility object, will be passed to UserDataAuth for its
  // internal use.
  NiceMock<MockAuthBlockUtility> auth_block_utility_;

  // Mock UserOldestActivityTimestampManager, will be passed to UserDataAuth for
  // its internal use.
  NiceMock<MockUserOldestActivityTimestampManager>
      user_activity_timestamp_manager_;

  // Mock HomeDirs object, will be passed to UserDataAuth for its internal use.
  NiceMock<MockHomeDirs> homedirs_;

  // Mock DiskCleanup object, will be passed to UserDataAuth for its internal
  // use. Only FreeDiskSpaceDuringLogin should be called and it should not
  // be called more than necessary.
  NiceMock<MockDiskCleanup> disk_cleanup_;

  // Mock InstallAttributes object, will be passed to UserDataAuth for its
  // internal use.
  std::unique_ptr<NiceMock<MockInstallAttributes>> attrs_;

  // Mock Platform object, will be passed to UserDataAuth for its internal use.
  NiceMock<MockPlatform> platform_;

  // Mock HWSec factory object, will be passed to UserDataAuth for its internal
  // use.
  NiceMock<hwsec::MockFactory> hwsec_factory_;

  // Mock HWSec object, will be passed to UserDataAuth for its internal use.
  NiceMock<hwsec::MockCryptohomeFrontend> hwsec_;

  // Mock pinweaver object, will be passed to UserDataAuth for its internal use.
  NiceMock<hwsec::MockPinWeaverFrontend> pinweaver_;

  // Mock recovery crypto object, will be passed to UserDataAuth for its
  // internal use.
  NiceMock<hwsec::MockRecoveryCryptoFrontend> recovery_crypto_;

  // Mock Cryptohome Key Loader object, will be passed to UserDataAuth for its
  // internal use.
  NiceMock<MockCryptohomeKeysManager> cryptohome_keys_manager_;

  // Fake Crypto object, will be passed to UserDataAuth for its internal use.
  Crypto crypto_{&hwsec_, &pinweaver_, &cryptohome_keys_manager_,
                 &recovery_crypto_};

  // Mock ARC Disk Quota object, will be passed to UserDataAuth for its internal
  // use.
  NiceMock<MockArcDiskQuota> arc_disk_quota_;

  // Mock chaps token manager client, will be passed to UserDataAuth for its
  // internal use.
  NiceMock<chaps::TokenManagerClientMock> chaps_client_;

  // Mock PKCS#11 init object, will be passed to UserDataAuth for its internal
  // use.
  NiceMock<MockPkcs11Init> pkcs11_init_;

  // Mock Pcks11TokenFactory, will be passed to UserDataAuth for its internal
  // use.
  NiceMock<MockPkcs11TokenFactory> pkcs11_token_factory_;

  // Mock Firmware Management Parameters object, will be passed to UserDataAuth
  // for its internal use.
  NiceMock<MockFirmwareManagementParameters> fwmp_;

  // Mock Fingerprint Manager object, will be passed to UserDataAuth for its
  // internal use.
  NiceMock<MockFingerprintManager> fingerprint_manager_;

  // Biometrics service object and the mock biometrics command processor object
  // that it is wrapping, the service object will be passed into UserDataAuth.
  NiceMock<MockBiometricsCommandProcessor>* bio_processor_;
  std::unique_ptr<BiometricsAuthBlockService> bio_service_;

  // Mock challenge credential helper utility object, will be passed to
  // UserDataAuth for its internal use.
  NiceMock<MockChallengeCredentialsHelper> challenge_credentials_helper_;

  // Mock factory of key challenge services, will be passed to UserDataAuth for
  // its internal use.
  NiceMock<MockKeyChallengeServiceFactory> key_challenge_service_factory_;

  // Mock User Session Factory object.
  NiceMock<MockUserSessionFactory> user_session_factory_;

  // Mock Low Disk Space handler object, will be passed to UserDataAuth for its
  // internal use.
  NiceMock<MockLowDiskSpaceHandler> low_disk_space_handler_;

  // Mock DBus object on mount thread, will be passed to UserDataAuth for its
  // internal use.
  scoped_refptr<NiceMock<dbus::MockBus>> mount_bus_;

  // Unowned pointer to the session object.
  NiceMock<MockUserSession>* session_ = nullptr;

  // Fake PlatformFeatures object, will be passed to Features for its internal
  // use.
  FakeFeaturesForTesting features_;

  // Declare |userdataauth_| last so it gets destroyed before all the mocks.
  // This is important because otherwise the background thread may call into
  // mocks that have already been destroyed.
  std::unique_ptr<UserDataAuth> userdataauth_;

  const error::CryptohomeError::ErrorLocationPair kErrorLocationPlaceholder =
      error::CryptohomeError::ErrorLocationPair(
          static_cast<::cryptohome::error::CryptohomeError::ErrorLocation>(1),
          "Testing1");
};

// Test fixture that implements two task runners, which is similar to the task
// environment in UserDataAuth. Developers could fast forward the time in
// UserDataAuth, and prevent the flakiness caused by the real time clock. Note
// that this does not initialize |userdataauth_|. And using WaitableEvent in it
// may hang the test runner.
class UserDataAuthTestTasked : public UserDataAuthTestBase {
 public:
  UserDataAuthTestTasked() = default;
  UserDataAuthTestTasked(const UserDataAuthTestTasked&) = delete;
  UserDataAuthTestTasked& operator=(const UserDataAuthTestTasked&) = delete;

  ~UserDataAuthTestTasked() override = default;

  void SetUp() override {
    // Note: If anything is modified/added here, we might need to adjust
    // UserDataAuthApiTest::SetUp() as well.

    // Setup the usual stuff
    UserDataAuthTestBase::SetUp();
    SetupTasks();
  }

  void SetupTasks() {
    // We do the task runner stuff for this test fixture.
    userdataauth_->set_origin_task_runner(origin_task_runner_);
    userdataauth_->set_mount_task_runner(mount_task_runner_);

    ON_CALL(platform_, GetCurrentTime()).WillByDefault(Invoke([this]() {
      // The time between origin and mount task runner may have a skew when fast
      // forwarding the time. But current running task runner time must be the
      // biggest one.
      return std::max(origin_task_runner_->Now(), mount_task_runner_->Now());
    }));
  }

  void CreatePkcs11TokenInSession(NiceMock<MockUserSession>* session) {
    auto token = std::make_unique<FakePkcs11Token>();
    ON_CALL(*session, GetPkcs11Token()).WillByDefault(Return(token.get()));
    tokens_.insert(std::move(token));
  }

  void InitializePkcs11TokenInSession(NiceMock<MockUserSession>* session) {
    // PKCS#11 will initialization works only when it's mounted.
    ON_CALL(*session, IsActive()).WillByDefault(Return(true));

    userdataauth_->InitializePkcs11(session);
  }

  void TearDown() override {
    RunUntilIdle();
    // Destruct the |userdataauth_| object.
    userdataauth_.reset();
  }

  // Initialize |userdataauth_| in |origin_task_runner_|
  void InitializeUserDataAuth() {
    ASSERT_TRUE(userdataauth_->Initialize(mount_bus_));
    // Let all initialization tasks complete.
    RunUntilIdle();
  }

  // Fast-forwards virtual time by |delta|
  void FastForwardBy(base::TimeDelta delta) {
    // Keep running the loop until there is no virtual time remain.
    while (!delta.is_zero()) {
      const base::TimeDelta& origin_delay =
          origin_task_runner_->NextPendingTaskDelay();
      const base::TimeDelta& mount_delay =
          mount_task_runner_->NextPendingTaskDelay();

      // Find the earliest task/deadline to forward.
      const base::TimeDelta& delay =
          std::min(delta, std::min(origin_delay, mount_delay));

      // Forward and run the origin task runner
      origin_task_runner_->FastForwardBy(delay);

      // Forward and run the mount task runner
      mount_task_runner_->FastForwardBy(delay);

      // Decrease the virtual time.
      delta -= delay;
    }

    // Make sure there is no zero delay tasks remain.
    RunUntilIdle();
  }

  // Run the all of the task runners until they don't find any zero delay tasks
  // in their queues.
  void RunUntilIdle() {
    while (origin_task_runner_->NextPendingTaskDelay().is_zero() ||
           mount_task_runner_->NextPendingTaskDelay().is_zero()) {
      origin_task_runner_->RunUntilIdle();
      mount_task_runner_->RunUntilIdle();
    }
  }

 protected:
  // Holder for tokens to preserve life time.
  std::set<std::unique_ptr<FakePkcs11Token>> tokens_;

  // MockTimeTaskRunner for origin and mount thread.
  scoped_refptr<base::TestMockTimeTaskRunner> origin_task_runner_{
      new base::TestMockTimeTaskRunner(
          base::TestMockTimeTaskRunner::Type::kBoundToThread)};
  scoped_refptr<base::TestMockTimeTaskRunner> mount_task_runner_{
      new base::TestMockTimeTaskRunner()};
};

// Using UserDataAuthTestTasked for not initialized tests.
using UserDataAuthTestNotInitialized = UserDataAuthTestTasked;

// Variant of UserDataAuthTestNotInitialized for DeathTest. We should be careful
// in not creating threads in this class.
using UserDataAuthTestNotInitializedDeathTest = UserDataAuthTestNotInitialized;

// Standard, fully initialized UserDataAuth test fixture
class UserDataAuthTest : public UserDataAuthTestNotInitialized {
 public:
  UserDataAuthTest() = default;
  UserDataAuthTest(const UserDataAuthTest&) = delete;
  UserDataAuthTest& operator=(const UserDataAuthTest&) = delete;

  ~UserDataAuthTest() override = default;

  void SetUp() override {
    // Note: If anything is modified/added here, we might need to adjust
    // UserDataAuthApiTest::SetUp() as well.

    UserDataAuthTestNotInitialized::SetUp();
    InitializeUserDataAuth();
  }
};

namespace CryptohomeErrorCodeEquivalenceTest {
// This test is completely static, so it is not wrapped in the TEST_F() block.
static_assert(static_cast<int>(user_data_auth::CRYPTOHOME_ERROR_NOT_SET) ==
                  static_cast<int>(cryptohome::CRYPTOHOME_ERROR_NOT_SET),
              "Enum member CRYPTOHOME_ERROR_NOT_SET differs between "
              "user_data_auth:: and cryptohome::");
static_assert(
    static_cast<int>(user_data_auth::CRYPTOHOME_ERROR_ACCOUNT_NOT_FOUND) ==
        static_cast<int>(cryptohome::CRYPTOHOME_ERROR_ACCOUNT_NOT_FOUND),
    "Enum member CRYPTOHOME_ERROR_ACCOUNT_NOT_FOUND differs between "
    "user_data_auth:: and cryptohome::");
static_assert(
    static_cast<int>(
        user_data_auth::CRYPTOHOME_ERROR_AUTHORIZATION_KEY_NOT_FOUND) ==
        static_cast<int>(
            cryptohome::CRYPTOHOME_ERROR_AUTHORIZATION_KEY_NOT_FOUND),
    "Enum member CRYPTOHOME_ERROR_AUTHORIZATION_KEY_NOT_FOUND differs between "
    "user_data_auth:: and cryptohome::");
static_assert(
    static_cast<int>(
        user_data_auth::CRYPTOHOME_ERROR_AUTHORIZATION_KEY_FAILED) ==
        static_cast<int>(cryptohome::CRYPTOHOME_ERROR_AUTHORIZATION_KEY_FAILED),
    "Enum member CRYPTOHOME_ERROR_AUTHORIZATION_KEY_FAILED differs between "
    "user_data_auth:: and cryptohome::");
static_assert(
    static_cast<int>(user_data_auth::CRYPTOHOME_ERROR_NOT_IMPLEMENTED) ==
        static_cast<int>(cryptohome::CRYPTOHOME_ERROR_NOT_IMPLEMENTED),
    "Enum member CRYPTOHOME_ERROR_NOT_IMPLEMENTED differs between "
    "user_data_auth:: and cryptohome::");
static_assert(static_cast<int>(user_data_auth::CRYPTOHOME_ERROR_MOUNT_FATAL) ==
                  static_cast<int>(cryptohome::CRYPTOHOME_ERROR_MOUNT_FATAL),
              "Enum member CRYPTOHOME_ERROR_MOUNT_FATAL differs between "
              "user_data_auth:: and cryptohome::");
static_assert(
    static_cast<int>(user_data_auth::CRYPTOHOME_ERROR_MOUNT_MOUNT_POINT_BUSY) ==
        static_cast<int>(cryptohome::CRYPTOHOME_ERROR_MOUNT_MOUNT_POINT_BUSY),
    "Enum member CRYPTOHOME_ERROR_MOUNT_MOUNT_POINT_BUSY differs between "
    "user_data_auth:: and cryptohome::");
static_assert(
    static_cast<int>(user_data_auth::CRYPTOHOME_ERROR_TPM_COMM_ERROR) ==
        static_cast<int>(cryptohome::CRYPTOHOME_ERROR_TPM_COMM_ERROR),
    "Enum member CRYPTOHOME_ERROR_TPM_COMM_ERROR differs between "
    "user_data_auth:: and cryptohome::");
static_assert(
    static_cast<int>(user_data_auth::CRYPTOHOME_ERROR_TPM_DEFEND_LOCK) ==
        static_cast<int>(cryptohome::CRYPTOHOME_ERROR_TPM_DEFEND_LOCK),
    "Enum member CRYPTOHOME_ERROR_TPM_DEFEND_LOCK differs between "
    "user_data_auth:: and cryptohome::");
static_assert(
    static_cast<int>(user_data_auth::CRYPTOHOME_ERROR_TPM_NEEDS_REBOOT) ==
        static_cast<int>(cryptohome::CRYPTOHOME_ERROR_TPM_NEEDS_REBOOT),
    "Enum member CRYPTOHOME_ERROR_TPM_NEEDS_REBOOT differs between "
    "user_data_auth:: and cryptohome::");
static_assert(
    static_cast<int>(
        user_data_auth::CRYPTOHOME_ERROR_AUTHORIZATION_KEY_DENIED) ==
        static_cast<int>(cryptohome::CRYPTOHOME_ERROR_AUTHORIZATION_KEY_DENIED),
    "Enum member CRYPTOHOME_ERROR_AUTHORIZATION_KEY_DENIED differs between "
    "user_data_auth:: and cryptohome::");
static_assert(
    static_cast<int>(user_data_auth::CRYPTOHOME_ERROR_KEY_QUOTA_EXCEEDED) ==
        static_cast<int>(cryptohome::CRYPTOHOME_ERROR_KEY_QUOTA_EXCEEDED),
    "Enum member CRYPTOHOME_ERROR_KEY_QUOTA_EXCEEDED differs between "
    "user_data_auth:: and cryptohome::");
static_assert(
    static_cast<int>(user_data_auth::CRYPTOHOME_ERROR_KEY_LABEL_EXISTS) ==
        static_cast<int>(cryptohome::CRYPTOHOME_ERROR_KEY_LABEL_EXISTS),
    "Enum member CRYPTOHOME_ERROR_KEY_LABEL_EXISTS differs between "
    "user_data_auth:: and cryptohome::");
static_assert(
    static_cast<int>(user_data_auth::CRYPTOHOME_ERROR_BACKING_STORE_FAILURE) ==
        static_cast<int>(cryptohome::CRYPTOHOME_ERROR_BACKING_STORE_FAILURE),
    "Enum member CRYPTOHOME_ERROR_BACKING_STORE_FAILURE differs between "
    "user_data_auth:: and cryptohome::");
static_assert(
    static_cast<int>(
        user_data_auth::CRYPTOHOME_ERROR_UPDATE_SIGNATURE_INVALID) ==
        static_cast<int>(cryptohome::CRYPTOHOME_ERROR_UPDATE_SIGNATURE_INVALID),
    "Enum member CRYPTOHOME_ERROR_UPDATE_SIGNATURE_INVALID differs between "
    "user_data_auth:: and cryptohome::");
static_assert(
    static_cast<int>(user_data_auth::CRYPTOHOME_ERROR_KEY_NOT_FOUND) ==
        static_cast<int>(cryptohome::CRYPTOHOME_ERROR_KEY_NOT_FOUND),
    "Enum member CRYPTOHOME_ERROR_KEY_NOT_FOUND differs between "
    "user_data_auth:: and cryptohome::");
static_assert(static_cast<int>(
                  user_data_auth::CRYPTOHOME_ERROR_LOCKBOX_SIGNATURE_INVALID) ==
                  static_cast<int>(
                      cryptohome::CRYPTOHOME_ERROR_LOCKBOX_SIGNATURE_INVALID),
              "Enum member CRYPTOHOME_ERROR_LOCKBOX_SIGNATURE_INVALID differs "
              "between user_data_auth:: and cryptohome::");
static_assert(
    static_cast<int>(user_data_auth::CRYPTOHOME_ERROR_LOCKBOX_CANNOT_SIGN) ==
        static_cast<int>(cryptohome::CRYPTOHOME_ERROR_LOCKBOX_CANNOT_SIGN),
    "Enum member CRYPTOHOME_ERROR_LOCKBOX_CANNOT_SIGN differs between "
    "user_data_auth:: and cryptohome::");
static_assert(
    static_cast<int>(
        user_data_auth::CRYPTOHOME_ERROR_BOOT_ATTRIBUTE_NOT_FOUND) ==
        static_cast<int>(cryptohome::CRYPTOHOME_ERROR_BOOT_ATTRIBUTE_NOT_FOUND),
    "Enum member CRYPTOHOME_ERROR_BOOT_ATTRIBUTE_NOT_FOUND differs between "
    "user_data_auth:: and cryptohome::");
static_assert(
    static_cast<int>(
        user_data_auth::CRYPTOHOME_ERROR_BOOT_ATTRIBUTES_CANNOT_SIGN) ==
        static_cast<int>(
            cryptohome::CRYPTOHOME_ERROR_BOOT_ATTRIBUTES_CANNOT_SIGN),
    "Enum member CRYPTOHOME_ERROR_BOOT_ATTRIBUTES_CANNOT_SIGN differs between "
    "user_data_auth:: and cryptohome::");
static_assert(
    static_cast<int>(user_data_auth::CRYPTOHOME_ERROR_TPM_EK_NOT_AVAILABLE) ==
        static_cast<int>(cryptohome::CRYPTOHOME_ERROR_TPM_EK_NOT_AVAILABLE),
    "Enum member CRYPTOHOME_ERROR_TPM_EK_NOT_AVAILABLE differs between "
    "user_data_auth:: and cryptohome::");
static_assert(
    static_cast<int>(user_data_auth::CRYPTOHOME_ERROR_ATTESTATION_NOT_READY) ==
        static_cast<int>(cryptohome::CRYPTOHOME_ERROR_ATTESTATION_NOT_READY),
    "Enum member CRYPTOHOME_ERROR_ATTESTATION_NOT_READY differs between "
    "user_data_auth:: and cryptohome::");
static_assert(
    static_cast<int>(user_data_auth::CRYPTOHOME_ERROR_CANNOT_CONNECT_TO_CA) ==
        static_cast<int>(cryptohome::CRYPTOHOME_ERROR_CANNOT_CONNECT_TO_CA),
    "Enum member CRYPTOHOME_ERROR_CANNOT_CONNECT_TO_CA differs between "
    "user_data_auth:: and cryptohome::");
static_assert(
    static_cast<int>(user_data_auth::CRYPTOHOME_ERROR_CA_REFUSED_ENROLLMENT) ==
        static_cast<int>(cryptohome::CRYPTOHOME_ERROR_CA_REFUSED_ENROLLMENT),
    "Enum member CRYPTOHOME_ERROR_CA_REFUSED_ENROLLMENT differs between "
    "user_data_auth:: and cryptohome::");
static_assert(
    static_cast<int>(user_data_auth::CRYPTOHOME_ERROR_CA_REFUSED_CERTIFICATE) ==
        static_cast<int>(cryptohome::CRYPTOHOME_ERROR_CA_REFUSED_CERTIFICATE),
    "Enum member CRYPTOHOME_ERROR_CA_REFUSED_CERTIFICATE differs between "
    "user_data_auth:: and cryptohome::");
static_assert(
    static_cast<int>(
        user_data_auth::CRYPTOHOME_ERROR_INTERNAL_ATTESTATION_ERROR) ==
        static_cast<int>(
            cryptohome::CRYPTOHOME_ERROR_INTERNAL_ATTESTATION_ERROR),
    "Enum member CRYPTOHOME_ERROR_INTERNAL_ATTESTATION_ERROR differs between "
    "user_data_auth:: and cryptohome::");
static_assert(
    static_cast<int>(
        user_data_auth::
            CRYPTOHOME_ERROR_FIRMWARE_MANAGEMENT_PARAMETERS_INVALID) ==
        static_cast<int>(
            cryptohome::
                CRYPTOHOME_ERROR_FIRMWARE_MANAGEMENT_PARAMETERS_INVALID),
    "Enum member CRYPTOHOME_ERROR_FIRMWARE_MANAGEMENT_PARAMETERS_INVALID "
    "differs between user_data_auth:: and cryptohome::");
static_assert(
    static_cast<int>(
        user_data_auth::
            CRYPTOHOME_ERROR_FIRMWARE_MANAGEMENT_PARAMETERS_CANNOT_STORE) ==
        static_cast<int>(
            cryptohome::
                CRYPTOHOME_ERROR_FIRMWARE_MANAGEMENT_PARAMETERS_CANNOT_STORE),
    "Enum member CRYPTOHOME_ERROR_FIRMWARE_MANAGEMENT_PARAMETERS_CANNOT_STORE "
    "differs between user_data_auth:: and cryptohome::");
static_assert(
    static_cast<int>(
        user_data_auth::
            CRYPTOHOME_ERROR_FIRMWARE_MANAGEMENT_PARAMETERS_CANNOT_REMOVE) ==
        static_cast<int>(
            cryptohome::
                CRYPTOHOME_ERROR_FIRMWARE_MANAGEMENT_PARAMETERS_CANNOT_REMOVE),
    "Enum member CRYPTOHOME_ERROR_FIRMWARE_MANAGEMENT_PARAMETERS_CANNOT_REMOVE "
    "differs between user_data_auth:: and cryptohome::");
static_assert(
    static_cast<int>(user_data_auth::CRYPTOHOME_ERROR_MOUNT_OLD_ENCRYPTION) ==
        static_cast<int>(cryptohome::CRYPTOHOME_ERROR_MOUNT_OLD_ENCRYPTION),
    "Enum member CRYPTOHOME_ERROR_MOUNT_OLD_ENCRYPTION differs between "
    "user_data_auth:: and cryptohome::");
static_assert(
    static_cast<int>(
        user_data_auth::CRYPTOHOME_ERROR_MOUNT_PREVIOUS_MIGRATION_INCOMPLETE) ==
        static_cast<int>(
            cryptohome::CRYPTOHOME_ERROR_MOUNT_PREVIOUS_MIGRATION_INCOMPLETE),
    "Enum member CRYPTOHOME_ERROR_MOUNT_PREVIOUS_MIGRATION_INCOMPLETE differs "
    "between user_data_auth:: and cryptohome::");
static_assert(
    static_cast<int>(user_data_auth::CRYPTOHOME_ERROR_MIGRATE_KEY_FAILED) ==
        static_cast<int>(cryptohome::CRYPTOHOME_ERROR_MIGRATE_KEY_FAILED),
    "Enum member CRYPTOHOME_ERROR_MIGRATE_KEY_FAILED differs between "
    "user_data_auth:: and cryptohome::");
static_assert(
    static_cast<int>(user_data_auth::CRYPTOHOME_ERROR_REMOVE_FAILED) ==
        static_cast<int>(cryptohome::CRYPTOHOME_ERROR_REMOVE_FAILED),
    "Enum member CRYPTOHOME_ERROR_REMOVE_FAILED differs between "
    "user_data_auth:: and cryptohome::");
static_assert(
    static_cast<int>(user_data_auth::CRYPTOHOME_ERROR_INVALID_ARGUMENT) ==
        static_cast<int>(cryptohome::CRYPTOHOME_ERROR_INVALID_ARGUMENT),
    "Enum member CRYPTOHOME_ERROR_INVALID_ARGUMENT differs between "
    "user_data_auth:: and cryptohome::");
static_assert(
    static_cast<int>(
        user_data_auth::CRYPTOHOME_ERROR_INSTALL_ATTRIBUTES_GET_FAILED) ==
        static_cast<int>(
            cryptohome::CRYPTOHOME_ERROR_INSTALL_ATTRIBUTES_GET_FAILED),
    "Enum member CRYPTOHOME_ERROR_INSTALL_ATTRIBUTES_GET_FAILED differs "
    "between user_data_auth:: and cryptohome::");
static_assert(
    static_cast<int>(
        user_data_auth::CRYPTOHOME_ERROR_INSTALL_ATTRIBUTES_SET_FAILED) ==
        static_cast<int>(
            cryptohome::CRYPTOHOME_ERROR_INSTALL_ATTRIBUTES_SET_FAILED),
    "Enum member CRYPTOHOME_ERROR_INSTALL_ATTRIBUTES_SET_FAILED differs "
    "between user_data_auth:: and cryptohome::");
static_assert(
    static_cast<int>(
        user_data_auth::CRYPTOHOME_ERROR_INSTALL_ATTRIBUTES_FINALIZE_FAILED) ==
        static_cast<int>(
            cryptohome::CRYPTOHOME_ERROR_INSTALL_ATTRIBUTES_FINALIZE_FAILED),
    "Enum member CRYPTOHOME_ERROR_INSTALL_ATTRIBUTES_FINALIZE_FAILED differs "
    "between user_data_auth:: and cryptohome::");
static_assert(
    static_cast<int>(
        user_data_auth::
            CRYPTOHOME_ERROR_UPDATE_USER_ACTIVITY_TIMESTAMP_FAILED) ==
        static_cast<int>(
            cryptohome::CRYPTOHOME_ERROR_UPDATE_USER_ACTIVITY_TIMESTAMP_FAILED),
    "Enum member CRYPTOHOME_ERROR_UPDATE_USER_ACTIVITY_TIMESTAMP_FAILED "
    "differs between user_data_auth:: and cryptohome::");
static_assert(
    static_cast<int>(user_data_auth::CRYPTOHOME_ERROR_FAILED_TO_READ_PCR) ==
        static_cast<int>(cryptohome::CRYPTOHOME_ERROR_FAILED_TO_READ_PCR),
    "Enum member CRYPTOHOME_ERROR_FAILED_TO_READ_PCR differs between "
    "user_data_auth:: and cryptohome::");
static_assert(
    static_cast<int>(user_data_auth::CRYPTOHOME_ERROR_PCR_ALREADY_EXTENDED) ==
        static_cast<int>(cryptohome::CRYPTOHOME_ERROR_PCR_ALREADY_EXTENDED),
    "Enum member CRYPTOHOME_ERROR_PCR_ALREADY_EXTENDED differs between "
    "user_data_auth:: and cryptohome::");
static_assert(
    static_cast<int>(user_data_auth::CRYPTOHOME_ERROR_FAILED_TO_EXTEND_PCR) ==
        static_cast<int>(cryptohome::CRYPTOHOME_ERROR_FAILED_TO_EXTEND_PCR),
    "Enum member CRYPTOHOME_ERROR_FAILED_TO_EXTEND_PCR differs between "
    "user_data_auth:: and cryptohome::");
static_assert(
    static_cast<int>(user_data_auth::CRYPTOHOME_ERROR_TPM_UPDATE_REQUIRED) ==
        static_cast<int>(cryptohome::CRYPTOHOME_ERROR_TPM_UPDATE_REQUIRED),
    "Enum member CRYPTOHOME_ERROR_TPM_UPDATE_REQUIRED differs between "
    "user_data_auth:: and cryptohome::");

static_assert(
    static_cast<int>(user_data_auth::CRYPTOHOME_ERROR_VAULT_UNRECOVERABLE) ==
        static_cast<int>(cryptohome::CRYPTOHOME_ERROR_VAULT_UNRECOVERABLE),
    "Enum member CRYPTOHOME_ERROR_VAULT_UNRECOVERABLE differs between "
    "user_data_auth:: and cryptohome::");

static_assert(
    static_cast<int>(user_data_auth::CRYPTOHOME_TOKEN_SERIALIZATION_FAILED) ==
        static_cast<int>(cryptohome::CRYPTOHOME_TOKEN_SERIALIZATION_FAILED),
    "Enum member CRYPTOHOME_TOKEN_SERIALIZATION_FAILED differs between "
    "user_data_auth:: and cryptohome::");

static_assert(
    static_cast<int>(user_data_auth::CRYPTOHOME_INVALID_AUTH_SESSION_TOKEN) ==
        static_cast<int>(cryptohome::CRYPTOHOME_INVALID_AUTH_SESSION_TOKEN),
    "Enum member CRYPTOHOME_INVALID_AUTH_SESSION_TOKEN differs between "
    "user_data_auth:: and cryptohome::");

static_assert(
    static_cast<int>(user_data_auth::CRYPTOHOME_ADD_CREDENTIALS_FAILED) ==
        static_cast<int>(cryptohome::CRYPTOHOME_ADD_CREDENTIALS_FAILED),
    "Enum member CRYPTOHOME_ADD_CREDENTIALS_FAILED differs between "
    "user_data_auth:: and cryptohome::");
static_assert(
    static_cast<int>(
        user_data_auth::CRYPTOHOME_ERROR_UNAUTHENTICATED_AUTH_SESSION) ==
        static_cast<int>(
            cryptohome::CRYPTOHOME_ERROR_UNAUTHENTICATED_AUTH_SESSION),
    "Enum member CRYPTOHOME_ERROR_UNAUTHENTICATED_AUTH_SESSION differs between "
    "user_data_auth:: and cryptohome::");
static_assert(
    static_cast<int>(user_data_auth::CRYPTOHOME_ERROR_UNKNOWN_LEGACY) ==
        static_cast<int>(cryptohome::CRYPTOHOME_ERROR_UNKNOWN_LEGACY),
    "Enum member CRYPTOHOME_ERROR_UNKNOWN_LEGACY differs between "
    "user_data_auth:: and cryptohome::");
static_assert(
    static_cast<int>(user_data_auth::CRYPTOHOME_ERROR_UNUSABLE_VAULT) ==
        static_cast<int>(cryptohome::CRYPTOHOME_ERROR_UNUSABLE_VAULT),
    "Enum member CRYPTOHOME_ERROR_UNUSABLE_VAULT differs between "
    "user_data_auth:: and cryptohome::");
static_assert(
    static_cast<int>(user_data_auth::CRYPTOHOME_REMOVE_CREDENTIALS_FAILED) ==
        static_cast<int>(cryptohome::CRYPTOHOME_REMOVE_CREDENTIALS_FAILED),
    "Enum member CRYPTOHOME_REMOVE_CREDENTIALS_FAILED differs between "
    "user_data_auth:: and cryptohome::");
static_assert(
    static_cast<int>(user_data_auth::CRYPTOHOME_UPDATE_CREDENTIALS_FAILED) ==
        static_cast<int>(cryptohome::CRYPTOHOME_UPDATE_CREDENTIALS_FAILED),
    "Enum member CRYPTOHOME_UPDATE_CREDENTIALS_FAILED differs between "
    "user_data_auth:: and cryptohome::");
static_assert(
    static_cast<int>(user_data_auth::CRYPTOHOME_ERROR_BIOMETRICS_BUSY) ==
        static_cast<int>(cryptohome::CRYPTOHOME_ERROR_BIOMETRICS_BUSY),
    "Enum member CRYPTOHOME_ERROR_BIOMETRICS_BUSY differs between "
    "user_data_auth:: and cryptohome::");
static_assert(
    static_cast<int>(user_data_auth::CRYPTOHOME_ERROR_CREDENTIAL_LOCKED) ==
        static_cast<int>(cryptohome::CRYPTOHOME_ERROR_CREDENTIAL_LOCKED),
    "Enum member CRYPTOHOME_ERROR_CREDENTIAL_LOCKED differs between "
    "user_data_auth:: and cryptohome::");
static_assert(
    static_cast<int>(user_data_auth::CRYPTOHOME_ERROR_CREDENTIAL_EXPIRED) ==
        static_cast<int>(cryptohome::CRYPTOHOME_ERROR_CREDENTIAL_EXPIRED),
    "Enum member CRYPTOHOME_ERROR_CREDENTIAL_EXPIRED differs between "
    "user_data_auth:: and cryptohome::");

static_assert(
    user_data_auth::CryptohomeErrorCode_MAX == 60,
    "user_data_auth::CryptohomeErrorCode's element count is incorrect");
static_assert(cryptohome::CryptohomeErrorCode_MAX == 60,
              "cryptohome::CryptohomeErrorCode's element count is incorrect");
}  // namespace CryptohomeErrorCodeEquivalenceTest

namespace SignatureAlgorithmEquivalenceTest {
// This test is completely static, so it is not wrapped in the TEST_F() block.
static_assert(static_cast<int>(user_data_auth::SmartCardSignatureAlgorithm::
                                   CHALLENGE_RSASSA_PKCS1_V1_5_SHA1) ==
                  static_cast<int>(cryptohome::ChallengeSignatureAlgorithm::
                                       CHALLENGE_RSASSA_PKCS1_V1_5_SHA1),
              "Enum member CHALLENGE_RSASSA_PKCS1_V1_5_SHA1 differs between "
              "user_data_auth:: and cryptohome::");
static_assert(static_cast<int>(user_data_auth::SmartCardSignatureAlgorithm::
                                   CHALLENGE_RSASSA_PKCS1_V1_5_SHA256) ==
                  static_cast<int>(cryptohome::ChallengeSignatureAlgorithm::
                                       CHALLENGE_RSASSA_PKCS1_V1_5_SHA256),
              "Enum member CHALLENGE_RSASSA_PKCS1_V1_5_SHA256 differs between "
              "user_data_auth:: and cryptohome::");
static_assert(static_cast<int>(user_data_auth::SmartCardSignatureAlgorithm::
                                   CHALLENGE_RSASSA_PKCS1_V1_5_SHA384) ==
                  static_cast<int>(cryptohome::ChallengeSignatureAlgorithm::
                                       CHALLENGE_RSASSA_PKCS1_V1_5_SHA384),
              "Enum member CHALLENGE_RSASSA_PKCS1_V1_5_SHA384 differs between "
              "user_data_auth:: and cryptohome::");
static_assert(static_cast<int>(user_data_auth::SmartCardSignatureAlgorithm::
                                   CHALLENGE_RSASSA_PKCS1_V1_5_SHA512) ==
                  static_cast<int>(cryptohome::ChallengeSignatureAlgorithm::
                                       CHALLENGE_RSASSA_PKCS1_V1_5_SHA512),
              "Enum member CHALLENGE_RSASSA_PKCS1_V1_5_SHA512 differs between "
              "user_data_auth:: and cryptohome::");
static_assert(
    user_data_auth::SmartCardSignatureAlgorithm_MAX == 4,
    "user_data_auth::CrytpohomeErrorCode's element count is incorrect");
static_assert(cryptohome::ChallengeSignatureAlgorithm_MAX == 4,
              "cryptohome::CrytpohomeErrorCode's element count is incorrect");
}  // namespace SignatureAlgorithmEquivalenceTest

TEST_F(UserDataAuthTest, IsMounted) {
  // By default there are no mount right after initialization
  EXPECT_FALSE(userdataauth_->IsMounted());
  EXPECT_FALSE(userdataauth_->IsMounted(Username("foo@gmail.com")));

  // Add a mount associated with foo@gmail.com
  SetupMount("foo@gmail.com");

  // Test the code path that doesn't specify a user, and when there's a mount
  // that's unmounted.
  EXPECT_CALL(*session_, IsActive()).WillOnce(Return(false));
  EXPECT_FALSE(userdataauth_->IsMounted());

  // Test to see if is_ephemeral works and test the code path that doesn't
  // specify a user.
  bool is_ephemeral = true;
  EXPECT_CALL(*session_, IsActive()).WillOnce(Return(true));
  EXPECT_CALL(*session_, IsEphemeral()).WillOnce(Return(false));
  EXPECT_TRUE(userdataauth_->IsMounted(Username(""), &is_ephemeral));
  EXPECT_FALSE(is_ephemeral);

  // Test to see if is_ephemeral works, and test the code path that specify the
  // user.
  EXPECT_CALL(*session_, IsActive()).WillOnce(Return(true));
  EXPECT_CALL(*session_, IsEphemeral()).WillOnce(Return(true));
  EXPECT_TRUE(
      userdataauth_->IsMounted(Username("foo@gmail.com"), &is_ephemeral));
  EXPECT_TRUE(is_ephemeral);

  // Note: IsMounted will not be called in this case.
  EXPECT_FALSE(
      userdataauth_->IsMounted(Username("bar@gmail.com"), &is_ephemeral));
  EXPECT_FALSE(is_ephemeral);
}

TEST_F(UserDataAuthTest, Unmount_AllDespiteFailures) {
  const Username kUsername1("foo@gmail.com");
  const Username kUsername2("bar@gmail.com");

  auto owned_session1 = std::make_unique<NiceMock<MockUserSession>>();
  auto* const session1 = owned_session1.get();
  EXPECT_TRUE(userdataauth_->AddUserSessionForTest(kUsername1,
                                                   std::move(owned_session1)));

  auto owned_session2 = std::make_unique<NiceMock<MockUserSession>>();
  auto* const session2 = owned_session2.get();
  EXPECT_TRUE(userdataauth_->AddUserSessionForTest(kUsername2,
                                                   std::move(owned_session2)));

  InSequence sequence;
  EXPECT_CALL(*session2, IsActive()).WillOnce(Return(true));
  EXPECT_CALL(*session2, Unmount()).WillOnce(Return(false));
  EXPECT_CALL(*session1, IsActive()).WillOnce(Return(true));
  EXPECT_CALL(*session1, Unmount()).WillOnce(Return(true));
  EXPECT_FALSE(userdataauth_->RemoveAllMounts());
}

TEST_F(UserDataAuthTest, Unmount_EphemeralNotEnabled) {
  // Unmount validity test.
  // The tests on whether stale mount are cleaned up is in another set of tests
  // called CleanUpStale_*

  // Add a mount associated with foo@gmail.com
  SetupMount("foo@gmail.com");

  // Unmount will be successful.
  EXPECT_CALL(*session_, Unmount()).WillOnce(Return(true));
  // If anyone asks, this mount is still mounted.
  ON_CALL(*session_, IsActive()).WillByDefault(Return(true));

  // Test that non-owner's vaults are not touched.
  policy::DevicePolicy::EphemeralSettings ephemeral_settings;
  ephemeral_settings.global_ephemeral_users_enabled = false;
  EXPECT_CALL(homedirs_, GetEphemeralSettings(_))
      .WillRepeatedly(SetEphemeralSettings(ephemeral_settings));
  EXPECT_CALL(homedirs_, RemoveCryptohomesBasedOnPolicy())
      .WillOnce(Return(HomeDirs::CryptohomesRemovedStatus::kNone));

  // Unmount should be successful.
  EXPECT_EQ(userdataauth_->Unmount().error_info().primary_action(),
            user_data_auth::PrimaryAction::PRIMARY_NO_ERROR);

  // It should be unmounted in the end.
  EXPECT_FALSE(userdataauth_->IsMounted());

  // Add another mount associated with bar@gmail.com
  SetupMount("bar@gmail.com");

  // Unmount will be unsuccessful.
  EXPECT_CALL(*session_, Unmount()).WillOnce(Return(false));
  // If anyone asks, this mount is still mounted.
  ON_CALL(*session_, IsActive()).WillByDefault(Return(true));

  // Test that non-owner's vaults are not touched.
  ephemeral_settings.global_ephemeral_users_enabled = false;
  EXPECT_CALL(homedirs_, GetEphemeralSettings(_))
      .WillRepeatedly(SetEphemeralSettings(ephemeral_settings));
  EXPECT_CALL(homedirs_, RemoveCryptohomesBasedOnPolicy())
      .WillOnce(Return(HomeDirs::CryptohomesRemovedStatus::kNone));

  // Unmount should be honest about failures.
  EXPECT_NE(userdataauth_->Unmount().error_info().primary_action(),
            user_data_auth::PrimaryAction::PRIMARY_NO_ERROR);

  // Unmount will remove all mounts even if it failed.
  EXPECT_FALSE(userdataauth_->IsMounted());
}

TEST_F(UserDataAuthTest, Unmount_EphemeralEnabled) {
  // Unmount validity test.
  // The tests on whether stale mount are cleaned up is in another set of tests
  // called CleanUpStale_*

  // Add a mount associated with foo@gmail.com
  SetupMount("foo@gmail.com");

  // Unmount will be successful.
  EXPECT_CALL(*session_, Unmount()).WillOnce(Return(true));
  // If anyone asks, this mount is still mounted.
  ON_CALL(*session_, IsActive()).WillByDefault(Return(true));

  // Test that non-owner's vaults are cleaned up.
  policy::DevicePolicy::EphemeralSettings ephemeral_settings;
  ephemeral_settings.global_ephemeral_users_enabled = true;
  EXPECT_CALL(homedirs_, GetEphemeralSettings(_))
      .WillRepeatedly(SetEphemeralSettings(ephemeral_settings));
  EXPECT_CALL(homedirs_, RemoveCryptohomesBasedOnPolicy())
      .WillOnce(Return(HomeDirs::CryptohomesRemovedStatus::kSome));

  // Unmount should be successful.
  EXPECT_EQ(userdataauth_->Unmount().error_info().primary_action(),
            user_data_auth::PrimaryAction::PRIMARY_NO_ERROR);

  // It should be unmounted in the end.
  EXPECT_FALSE(userdataauth_->IsMounted());

  // Add another mount associated with bar@gmail.com
  SetupMount("bar@gmail.com");

  // Unmount will be unsuccessful.
  EXPECT_CALL(*session_, Unmount()).WillOnce(Return(false));
  // If anyone asks, this mount is still mounted.
  ON_CALL(*session_, IsActive()).WillByDefault(Return(true));

  // Test that non-owner's vaults are cleaned up anyway.
  ephemeral_settings.global_ephemeral_users_enabled = true;
  EXPECT_CALL(homedirs_, GetEphemeralSettings(_))
      .WillRepeatedly(SetEphemeralSettings(ephemeral_settings));
  EXPECT_CALL(homedirs_, RemoveCryptohomesBasedOnPolicy())
      .WillOnce(Return(HomeDirs::CryptohomesRemovedStatus::kSome));

  // Unmount should be honest about failures.
  EXPECT_NE(userdataauth_->Unmount().error_info().primary_action(),
            user_data_auth::PrimaryAction::PRIMARY_NO_ERROR);

  // Unmount will remove all mounts even if it failed.
  EXPECT_FALSE(userdataauth_->IsMounted());
}

TEST_F(UserDataAuthTest, InitializePkcs11Success) {
  // This test the most common success case for PKCS#11 initialization.

  EXPECT_FALSE(userdataauth_->IsMounted());

  // Add a mount associated with foo@gmail.com
  SetupMount("foo@gmail.com");

  CreatePkcs11TokenInSession(session_);

  // At first the token is not ready
  EXPECT_FALSE(session_->GetPkcs11Token()->IsReady());

  InitializePkcs11TokenInSession(session_);

  EXPECT_TRUE(session_->GetPkcs11Token()->IsReady());
}

TEST_F(UserDataAuthTest, InitializePkcs11Unmounted) {
  // Add a mount associated with foo@gmail.com
  SetupMount("foo@gmail.com");

  CreatePkcs11TokenInSession(session_);

  // At first the token is not ready
  EXPECT_FALSE(session_->GetPkcs11Token()->IsReady());

  ON_CALL(*session_, IsActive()).WillByDefault(Return(false));
  // The initialization code should at least check, right?
  EXPECT_CALL(*session_, IsActive())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(false));

  userdataauth_->InitializePkcs11(session_);

  // Still not ready because already unmounted
  EXPECT_FALSE(session_->GetPkcs11Token()->IsReady());
}

TEST_F(UserDataAuthTest, Pkcs11IsTpmTokenReady) {
  // When there's no mount at all, it should be true.
  EXPECT_TRUE(userdataauth_->Pkcs11IsTpmTokenReady());

  const Username kUsername1("foo@gmail.com");
  const Username kUsername2("bar@gmail.com");

  auto owned_session1 = std::make_unique<NiceMock<MockUserSession>>();
  auto* const session1 = owned_session1.get();
  EXPECT_TRUE(userdataauth_->AddUserSessionForTest(kUsername1,
                                                   std::move(owned_session1)));
  CreatePkcs11TokenInSession(session1);

  auto owned_session2 = std::make_unique<NiceMock<MockUserSession>>();
  auto* const session2 = owned_session2.get();
  EXPECT_TRUE(userdataauth_->AddUserSessionForTest(kUsername2,
                                                   std::move(owned_session2)));
  CreatePkcs11TokenInSession(session2);

  // Both are uninitialized.
  EXPECT_FALSE(userdataauth_->Pkcs11IsTpmTokenReady());

  // Only one is initialized.
  InitializePkcs11TokenInSession(session2);
  EXPECT_FALSE(userdataauth_->Pkcs11IsTpmTokenReady());

  // Both is initialized.
  InitializePkcs11TokenInSession(session1);
  EXPECT_TRUE(userdataauth_->Pkcs11IsTpmTokenReady());
}

TEST_F(UserDataAuthTest, Pkcs11GetTpmTokenInfo) {
  user_data_auth::TpmTokenInfo info;

  constexpr CK_SLOT_ID kSlot = 42;
  const Username kUsername1("foo@gmail.com");

  // Check the system token case.
  EXPECT_CALL(pkcs11_init_, GetTpmTokenSlotForPath(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(kSlot), Return(true)));
  info = userdataauth_->Pkcs11GetTpmTokenInfo(Username());

  EXPECT_EQ(info.label(), Pkcs11Init::kDefaultSystemLabel);
  EXPECT_EQ(info.user_pin(), Pkcs11Init::kDefaultPin);
  EXPECT_EQ(info.slot(), kSlot);

  // Check the user token case.
  EXPECT_CALL(pkcs11_init_, GetTpmTokenSlotForPath(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(kSlot), Return(true)));
  info = userdataauth_->Pkcs11GetTpmTokenInfo(kUsername1);

  // Note that the label will usually be appended with a part of the sanitized
  // username. However, the sanitized username cannot be generated during
  // testing as we can't mock global functions in libbrillo. Therefore, we'll
  // only test that it is prefixed by prefix.
  EXPECT_EQ(info.label().substr(0, strlen(Pkcs11Init::kDefaultUserLabelPrefix)),
            Pkcs11Init::kDefaultUserLabelPrefix);
  EXPECT_EQ(info.user_pin(), Pkcs11Init::kDefaultPin);
  EXPECT_EQ(info.slot(), kSlot);

  // Verify that if GetTpmTokenSlotForPath fails, we'll get -1 for slot.
  EXPECT_CALL(pkcs11_init_, GetTpmTokenSlotForPath(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(kSlot), Return(false)));
  info = userdataauth_->Pkcs11GetTpmTokenInfo(Username());
  EXPECT_EQ(info.slot(), -1);

  EXPECT_CALL(pkcs11_init_, GetTpmTokenSlotForPath(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(kSlot), Return(false)));
  info = userdataauth_->Pkcs11GetTpmTokenInfo(kUsername1);
  EXPECT_EQ(info.slot(), -1);
}

TEST_F(UserDataAuthTest, Pkcs11Terminate) {
  // Check that it'll not crash when there's no mount
  userdataauth_->Pkcs11Terminate();

  // Check that we'll indeed get the Mount object to remove the PKCS#11 token.
  constexpr char kUsername1[] = "foo@gmail.com";
  SetupMount(kUsername1);
  CreatePkcs11TokenInSession(session_);
  InitializePkcs11TokenInSession(session_);

  EXPECT_TRUE(session_->GetPkcs11Token()->IsReady());

  userdataauth_->Pkcs11Terminate();

  EXPECT_FALSE(session_->GetPkcs11Token()->IsReady());
}

TEST_F(UserDataAuthTest, Pkcs11RestoreTpmTokens) {
  // This test the most common success case for PKCS#11 retrieving TPM tokens.

  // Add a mount associated with foo@gmail.com
  SetupMount("foo@gmail.com");

  CreatePkcs11TokenInSession(session_);

  // PKCS#11 will initialization works only when it's mounted.
  ON_CALL(*session_, IsActive()).WillByDefault(Return(true));
  // The initialization code should at least check, right?
  EXPECT_CALL(*session_, IsActive())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(true));

  EXPECT_FALSE(session_->GetPkcs11Token()->IsReady());

  userdataauth_->Pkcs11RestoreTpmTokens();

  EXPECT_TRUE(session_->GetPkcs11Token()->IsReady());
}

TEST_F(UserDataAuthTest, Pkcs11RestoreTpmTokensWaitingOnTPM) {
  // This test the most common success case for PKCS#11 retrieving TPM tokens
  // when it's waiting TPM ready.

  // Add a mount associated with foo@gmail.com
  SetupMount("foo@gmail.com");

  CreatePkcs11TokenInSession(session_);

  // PKCS#11 will initialization works only when it's mounted.
  ON_CALL(*session_, IsActive()).WillByDefault(Return(true));
  // The initialization code should at least check, right?
  EXPECT_CALL(*session_, IsActive())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(true));

  EXPECT_FALSE(session_->GetPkcs11Token()->IsReady());

  userdataauth_->Pkcs11RestoreTpmTokens();

  EXPECT_TRUE(session_->GetPkcs11Token()->IsReady());
}

TEST_F(UserDataAuthTestNotInitialized, InstallAttributesEnterpriseOwned) {
  EXPECT_CALL(*attrs_, Init()).WillOnce(Return(true));

  std::string str_true = "true";
  std::vector<uint8_t> blob_true(str_true.begin(), str_true.end());
  blob_true.push_back(0);

  EXPECT_CALL(*attrs_, Get("enterprise.owned", _))
      .WillOnce(DoAll(SetArgPointee<1>(blob_true), Return(true)));

  InitializeUserDataAuth();

  EXPECT_TRUE(userdataauth_->IsEnterpriseOwned());
}

TEST_F(UserDataAuthTestNotInitialized, InstallAttributesNotEnterpriseOwned) {
  EXPECT_CALL(*attrs_, Init()).WillOnce(Return(true));

  std::string str_true = "false";
  std::vector<uint8_t> blob_true(str_true.begin(), str_true.end());
  blob_true.push_back(0);

  EXPECT_CALL(*attrs_, Get("enterprise.owned", _))
      .WillOnce(DoAll(SetArgPointee<1>(blob_true), Return(true)));

  InitializeUserDataAuth();

  EXPECT_FALSE(userdataauth_->IsEnterpriseOwned());
}

TEST_F(UserDataAuthTestNotInitialized, LowDiskSpaceHandlerInit) {
  // Both callbacks need to be set before Init.
  EXPECT_CALL(low_disk_space_handler_,
              SetUpdateUserActivityTimestampCallback(_));
  EXPECT_CALL(low_disk_space_handler_, SetLowDiskSpaceCallback(_));

  InitializeUserDataAuth();
}

constexpr char kInstallAttributeName[] = "SomeAttribute";
constexpr uint8_t kInstallAttributeData[] = {0x01, 0x02, 0x00,
                                             0x03, 0xFF, 0xAB};

TEST_F(UserDataAuthTest, InstallAttributesGet) {
  // Test for successful case.
  EXPECT_CALL(*attrs_, Get(kInstallAttributeName, _))
      .WillOnce(
          Invoke([](const std::string& name, std::vector<uint8_t>* data_out) {
            *data_out = std::vector<uint8_t>(
                kInstallAttributeData,
                kInstallAttributeData + sizeof(kInstallAttributeData));
            return true;
          }));
  std::vector<uint8_t> data;
  EXPECT_TRUE(
      userdataauth_->InstallAttributesGet(kInstallAttributeName, &data));
  EXPECT_THAT(data, ElementsAreArray(kInstallAttributeData));

  // Test for unsuccessful case.
  EXPECT_CALL(*attrs_, Get(kInstallAttributeName, _)).WillOnce(Return(false));
  EXPECT_FALSE(
      userdataauth_->InstallAttributesGet(kInstallAttributeName, &data));
}

TEST_F(UserDataAuthTest, InstallAttributesSet) {
  // Test for successful case.
  EXPECT_CALL(*attrs_, Set(kInstallAttributeName,
                           ElementsAreArray(kInstallAttributeData)))
      .WillOnce(Return(true));

  std::vector<uint8_t> data(
      kInstallAttributeData,
      kInstallAttributeData + sizeof(kInstallAttributeData));
  EXPECT_TRUE(userdataauth_->InstallAttributesSet(kInstallAttributeName, data));

  // Test for unsuccessful case.
  EXPECT_CALL(*attrs_, Set(kInstallAttributeName,
                           ElementsAreArray(kInstallAttributeData)))
      .WillOnce(Return(false));
  EXPECT_FALSE(
      userdataauth_->InstallAttributesSet(kInstallAttributeName, data));
}

TEST_F(UserDataAuthTest, InstallAttributesFinalize) {
  // Test for successful case.
  EXPECT_CALL(*attrs_, Finalize()).WillOnce(Return(true));
  EXPECT_TRUE(userdataauth_->InstallAttributesFinalize());

  // Test for unsuccessful case.
  EXPECT_CALL(*attrs_, Finalize()).WillOnce(Return(false));
  EXPECT_FALSE(userdataauth_->InstallAttributesFinalize());
}

TEST_F(UserDataAuthTest, InstallAttributesCount) {
  constexpr int kCount = 42;  // The Answer!!
  EXPECT_CALL(*attrs_, Count()).WillOnce(Return(kCount));
  EXPECT_EQ(kCount, userdataauth_->InstallAttributesCount());
}

TEST_F(UserDataAuthTest, InstallAttributesIsSecure) {
  // Test for successful case.
  EXPECT_CALL(*attrs_, IsSecure()).WillOnce(Return(true));
  EXPECT_TRUE(userdataauth_->InstallAttributesIsSecure());

  // Test for unsuccessful case.
  EXPECT_CALL(*attrs_, IsSecure()).WillOnce(Return(false));
  EXPECT_FALSE(userdataauth_->InstallAttributesIsSecure());
}

TEST_F(UserDataAuthTest, InstallAttributesGetStatus) {
  std::vector<InstallAttributes::Status> status_list = {
      InstallAttributes::Status::kUnknown,
      InstallAttributes::Status::kTpmNotOwned,
      InstallAttributes::Status::kFirstInstall,
      InstallAttributes::Status::kValid, InstallAttributes::Status::kInvalid};

  for (auto& s : status_list) {
    EXPECT_CALL(*attrs_, status()).WillOnce(Return(s));
    EXPECT_EQ(s, userdataauth_->InstallAttributesGetStatus());
  }
}

TEST_F(UserDataAuthTestNotInitialized, InstallAttributesStatusToProtoEnum) {
  EXPECT_EQ(user_data_auth::InstallAttributesState::UNKNOWN,
            UserDataAuth::InstallAttributesStatusToProtoEnum(
                InstallAttributes::Status::kUnknown));
  EXPECT_EQ(user_data_auth::InstallAttributesState::TPM_NOT_OWNED,
            UserDataAuth::InstallAttributesStatusToProtoEnum(
                InstallAttributes::Status::kTpmNotOwned));
  EXPECT_EQ(user_data_auth::InstallAttributesState::FIRST_INSTALL,
            UserDataAuth::InstallAttributesStatusToProtoEnum(
                InstallAttributes::Status::kFirstInstall));
  EXPECT_EQ(user_data_auth::InstallAttributesState::VALID,
            UserDataAuth::InstallAttributesStatusToProtoEnum(
                InstallAttributes::Status::kValid));
  EXPECT_EQ(user_data_auth::InstallAttributesState::INVALID,
            UserDataAuth::InstallAttributesStatusToProtoEnum(
                InstallAttributes::Status::kInvalid));
  static_assert(
      user_data_auth::InstallAttributesState_MAX == 4,
      "Incorrect element count in user_data_auth::InstallAttributesState");
  static_assert(static_cast<int>(InstallAttributes::Status::COUNT) == 5,
                "Incorrect element count in InstallAttributes::Status");
}

TEST_F(UserDataAuthTestNotInitialized, InitializeArcDiskQuota) {
  EXPECT_CALL(arc_disk_quota_, Initialize()).Times(1);
  EXPECT_TRUE(userdataauth_->Initialize(mount_bus_));
}

TEST_F(UserDataAuthTestNotInitialized, IsArcQuotaSupported) {
  EXPECT_CALL(arc_disk_quota_, IsQuotaSupported()).WillOnce(Return(true));
  EXPECT_TRUE(userdataauth_->IsArcQuotaSupported());

  EXPECT_CALL(arc_disk_quota_, IsQuotaSupported()).WillOnce(Return(false));
  EXPECT_FALSE(userdataauth_->IsArcQuotaSupported());
}

TEST_F(UserDataAuthTestNotInitialized, GetCurrentSpaceFoArcUid) {
  constexpr uid_t kUID = 42;  // The Answer.
  constexpr int64_t kSpaceUsage = 98765432198765;

  EXPECT_CALL(arc_disk_quota_, GetCurrentSpaceForUid(kUID))
      .WillOnce(Return(kSpaceUsage));
  EXPECT_EQ(kSpaceUsage, userdataauth_->GetCurrentSpaceForArcUid(kUID));
}

TEST_F(UserDataAuthTestNotInitialized, GetCurrentSpaceForArcGid) {
  constexpr uid_t kGID = 42;  // Yet another answer.
  constexpr int64_t kSpaceUsage = 87654321987654;

  EXPECT_CALL(arc_disk_quota_, GetCurrentSpaceForGid(kGID))
      .WillOnce(Return(kSpaceUsage));
  EXPECT_EQ(kSpaceUsage, userdataauth_->GetCurrentSpaceForArcGid(kGID));
}

TEST_F(UserDataAuthTestNotInitialized, GetCurrentSpaceForArcProjectId) {
  constexpr int kProjectId = 1001;  // Yet another answer.
  constexpr int64_t kSpaceUsage = 87654321987654;

  EXPECT_CALL(arc_disk_quota_, GetCurrentSpaceForProjectId(kProjectId))
      .WillOnce(Return(kSpaceUsage));
  EXPECT_EQ(kSpaceUsage,
            userdataauth_->GetCurrentSpaceForArcProjectId(kProjectId));
}

TEST_F(UserDataAuthTest, SetMediaRWDataFileProjectId) {
  constexpr int kProjectId = 1001;
  constexpr int kFd = 1234;
  int error = 0;

  EXPECT_CALL(arc_disk_quota_,
              SetMediaRWDataFileProjectId(kProjectId, kFd, &error))
      .WillOnce(Return(true));
  EXPECT_TRUE(
      userdataauth_->SetMediaRWDataFileProjectId(kProjectId, kFd, &error));
}

TEST_F(UserDataAuthTest, SetMediaRWDataFileProjectInheritanceFlag) {
  constexpr bool kEnable = true;
  constexpr int kFd = 1234;
  int error = 0;

  EXPECT_CALL(arc_disk_quota_,
              SetMediaRWDataFileProjectInheritanceFlag(kEnable, kFd, &error))
      .WillOnce(Return(true));
  EXPECT_TRUE(userdataauth_->SetMediaRWDataFileProjectInheritanceFlag(
      kEnable, kFd, &error));
}

TEST_F(UserDataAuthTest, LockToSingleUserMountUntilRebootValidity) {
  const Username kUsername1("foo@gmail.com");
  AccountIdentifier account_id;
  account_id.set_account_id(*kUsername1);
  const ObfuscatedUsername kUsername1Obfuscated =
      GetObfuscatedUsername(kUsername1);

  EXPECT_CALL(homedirs_, SetLockedToSingleUser()).WillOnce(Return(true));
  EXPECT_CALL(hwsec_, IsCurrentUserSet()).WillOnce(ReturnValue(false));
  EXPECT_CALL(hwsec_, SetCurrentUser(*kUsername1Obfuscated))
      .WillOnce(ReturnOk<TPMError>());

  EXPECT_EQ(userdataauth_->LockToSingleUserMountUntilReboot(account_id),
            user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
}

TEST_F(UserDataAuthTest, LockToSingleUserMountUntilRebootReadPCRFail) {
  constexpr char kUsername1[] = "foo@gmail.com";
  AccountIdentifier account_id;
  account_id.set_account_id(kUsername1);

  ON_CALL(homedirs_, SetLockedToSingleUser()).WillByDefault(Return(true));
  EXPECT_CALL(hwsec_, IsCurrentUserSet())
      .WillOnce(ReturnError<TPMError>("fake", TPMRetryAction::kNoRetry));

  EXPECT_EQ(userdataauth_->LockToSingleUserMountUntilReboot(account_id),
            user_data_auth::CRYPTOHOME_ERROR_FAILED_TO_READ_PCR);
}

TEST_F(UserDataAuthTest, LockToSingleUserMountUntilRebootAlreadyExtended) {
  constexpr char kUsername1[] = "foo@gmail.com";
  AccountIdentifier account_id;
  account_id.set_account_id(kUsername1);

  ON_CALL(homedirs_, SetLockedToSingleUser()).WillByDefault(Return(true));
  EXPECT_CALL(hwsec_, IsCurrentUserSet()).WillOnce(ReturnValue(true));

  EXPECT_EQ(userdataauth_->LockToSingleUserMountUntilReboot(account_id),
            user_data_auth::CRYPTOHOME_ERROR_PCR_ALREADY_EXTENDED);
}

TEST_F(UserDataAuthTest, LockToSingleUserMountUntilRebootExtendFail) {
  const Username kUsername1("foo@gmail.com");
  AccountIdentifier account_id;
  account_id.set_account_id(*kUsername1);
  const ObfuscatedUsername kUsername1Obfuscated =
      GetObfuscatedUsername(kUsername1);

  EXPECT_CALL(homedirs_, SetLockedToSingleUser()).WillOnce(Return(true));
  EXPECT_CALL(hwsec_, IsCurrentUserSet()).WillOnce(ReturnValue(false));
  EXPECT_CALL(hwsec_, SetCurrentUser(*kUsername1Obfuscated))
      .WillOnce(ReturnError<TPMError>("fake", TPMRetryAction::kNoRetry));

  EXPECT_EQ(userdataauth_->LockToSingleUserMountUntilReboot(account_id),
            user_data_auth::CRYPTOHOME_ERROR_FAILED_TO_EXTEND_PCR);
}

TEST_F(UserDataAuthTest, GetEncryptionInfoEnabledTest) {
  EXPECT_CALL(homedirs_, KeylockerForStorageEncryptionEnabled())
      .WillRepeatedly(Return(true));

  // Verify that a request produces encryption info.
  user_data_auth::GetEncryptionInfoRequest request;
  user_data_auth::GetEncryptionInfoReply reply =
      userdataauth_->GetEncryptionInfo(request);
  ASSERT_EQ(reply.error(), user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  ASSERT_TRUE(reply.keylocker_supported());
}

// ================== Firmware Management Parameters tests ==================

TEST_F(UserDataAuthTest, GetFirmwareManagementParametersSuccess) {
  const std::string kHash = "its_a_hash";
  std::vector<uint8_t> hash(kHash.begin(), kHash.end());
  constexpr uint32_t kFlag = 0x1234;

  EXPECT_CALL(fwmp_, Load()).WillOnce(Return(true));
  EXPECT_CALL(fwmp_, GetFlags(_))
      .WillRepeatedly(DoAll(SetArgPointee<0>(kFlag), Return(true)));
  EXPECT_CALL(fwmp_, GetDeveloperKeyHash(_))
      .WillRepeatedly(DoAll(SetArgPointee<0>(hash), Return(true)));

  user_data_auth::FirmwareManagementParameters fwmp;
  EXPECT_EQ(user_data_auth::CRYPTOHOME_ERROR_NOT_SET,
            userdataauth_->GetFirmwareManagementParameters(&fwmp));

  EXPECT_EQ(kFlag, fwmp.flags());
  EXPECT_EQ(kHash, fwmp.developer_key_hash());
}

TEST_F(UserDataAuthTest, GetFirmwareManagementParametersError) {
  constexpr uint32_t kFlag = 0x1234;

  // Test Load() fail.
  EXPECT_CALL(fwmp_, Load()).WillRepeatedly(Return(false));

  user_data_auth::FirmwareManagementParameters fwmp;
  EXPECT_EQ(
      user_data_auth::CRYPTOHOME_ERROR_FIRMWARE_MANAGEMENT_PARAMETERS_INVALID,
      userdataauth_->GetFirmwareManagementParameters(&fwmp));

  // Test GetFlags() fail.
  EXPECT_CALL(fwmp_, Load()).WillRepeatedly(Return(true));
  EXPECT_CALL(fwmp_, GetFlags(_)).WillRepeatedly(Return(false));

  EXPECT_EQ(
      user_data_auth::CRYPTOHOME_ERROR_FIRMWARE_MANAGEMENT_PARAMETERS_INVALID,
      userdataauth_->GetFirmwareManagementParameters(&fwmp));

  // Test GetDeveloperKeyHash fail.
  EXPECT_CALL(fwmp_, Load()).WillRepeatedly(Return(true));
  EXPECT_CALL(fwmp_, GetFlags(_))
      .WillRepeatedly(DoAll(SetArgPointee<0>(kFlag), Return(true)));
  EXPECT_CALL(fwmp_, GetDeveloperKeyHash(_)).WillRepeatedly(Return(false));

  EXPECT_EQ(
      user_data_auth::CRYPTOHOME_ERROR_FIRMWARE_MANAGEMENT_PARAMETERS_INVALID,
      userdataauth_->GetFirmwareManagementParameters(&fwmp));
}

TEST_F(UserDataAuthTest, SetFirmwareManagementParametersSuccess) {
  const std::string kHash = "its_a_hash";
  std::vector<uint8_t> hash(kHash.begin(), kHash.end());
  constexpr uint32_t kFlag = 0x1234;

  std::vector<uint8_t> out_hash;

  EXPECT_CALL(fwmp_, Create()).WillOnce(Return(true));
  EXPECT_CALL(fwmp_, Store(kFlag, _))
      .WillOnce(DoAll(SaveArgPointee<1>(&out_hash), Return(true)));

  user_data_auth::FirmwareManagementParameters fwmp;
  fwmp.set_flags(kFlag);
  fwmp.set_developer_key_hash(kHash);

  EXPECT_EQ(user_data_auth::CRYPTOHOME_ERROR_NOT_SET,
            userdataauth_->SetFirmwareManagementParameters(fwmp));

  EXPECT_EQ(hash, out_hash);
}

TEST_F(UserDataAuthTest, SetFirmwareManagementParametersNoHash) {
  constexpr uint32_t kFlag = 0x1234;

  EXPECT_CALL(fwmp_, Create()).WillOnce(Return(true));
  EXPECT_CALL(fwmp_, Store(kFlag, nullptr)).WillOnce(Return(true));

  user_data_auth::FirmwareManagementParameters fwmp;
  fwmp.set_flags(kFlag);

  EXPECT_EQ(user_data_auth::CRYPTOHOME_ERROR_NOT_SET,
            userdataauth_->SetFirmwareManagementParameters(fwmp));
}

TEST_F(UserDataAuthTest, SetFirmwareManagementParametersCreateError) {
  const std::string kHash = "its_a_hash";
  constexpr uint32_t kFlag = 0x1234;

  EXPECT_CALL(fwmp_, Create()).WillOnce(Return(false));

  user_data_auth::FirmwareManagementParameters fwmp;
  fwmp.set_flags(kFlag);
  fwmp.set_developer_key_hash(kHash);

  EXPECT_EQ(user_data_auth::
                CRYPTOHOME_ERROR_FIRMWARE_MANAGEMENT_PARAMETERS_CANNOT_STORE,
            userdataauth_->SetFirmwareManagementParameters(fwmp));
}

TEST_F(UserDataAuthTest, SetFirmwareManagementParametersStoreError) {
  const std::string kHash = "its_a_hash";
  constexpr uint32_t kFlag = 0x1234;

  EXPECT_CALL(fwmp_, Create()).WillOnce(Return(true));
  EXPECT_CALL(fwmp_, Store(_, _)).WillOnce(Return(false));

  user_data_auth::FirmwareManagementParameters fwmp;
  fwmp.set_flags(kFlag);
  fwmp.set_developer_key_hash(kHash);

  EXPECT_EQ(user_data_auth::
                CRYPTOHOME_ERROR_FIRMWARE_MANAGEMENT_PARAMETERS_CANNOT_STORE,
            userdataauth_->SetFirmwareManagementParameters(fwmp));
}

TEST_F(UserDataAuthTest, RemoveFirmwareManagementParametersSuccess) {
  EXPECT_CALL(fwmp_, Destroy()).WillOnce(Return(true));

  EXPECT_TRUE(userdataauth_->RemoveFirmwareManagementParameters());
}

TEST_F(UserDataAuthTest, RemoveFirmwareManagementParametersError) {
  EXPECT_CALL(fwmp_, Destroy()).WillOnce(Return(false));

  EXPECT_FALSE(userdataauth_->RemoveFirmwareManagementParameters());
}

TEST_F(UserDataAuthTest, GetSystemSaltSucess) {
  EXPECT_EQ(brillo::SecureBlob(*brillo::cryptohome::home::GetSystemSalt()),
            userdataauth_->GetSystemSalt());
}

TEST_F(UserDataAuthTestNotInitializedDeathTest, GetSystemSaltUninitialized) {
  EXPECT_DEBUG_DEATH(userdataauth_->GetSystemSalt(),
                     "Cannot call GetSystemSalt before initialization");
}

TEST_F(UserDataAuthTest, HwsecReadyCallbackSuccess) {
  base::OnceCallback<void(hwsec::Status)> callback;

  // Called by Initialize().
  EXPECT_CALL(hwsec_, RegisterOnReadyCallback)
      .WillOnce([&](base::OnceCallback<void(hwsec::Status)> cb) {
        callback = std::move(cb);
      });

  InitializeUserDataAuth();

  EXPECT_FALSE(callback.is_null());

  SetupMount("foo@gmail.com");

  // Called by EnsureCryptohomeKeys().
  EXPECT_CALL(cryptohome_keys_manager_, HasAnyCryptohomeKey())
      .WillOnce(Return(true));
  // Called by InitializeInstallAttributes()
  EXPECT_CALL(*attrs_, Init()).WillOnce(Return(true));

  std::move(callback).Run(hwsec::OkStatus());
}

TEST_F(UserDataAuthTest, HwsecReadyCallbackFail) {
  base::OnceCallback<void(hwsec::Status)> callback;

  // Called by Initialize().
  EXPECT_CALL(hwsec_, RegisterOnReadyCallback)
      .WillOnce([&](base::OnceCallback<void(hwsec::Status)> cb) {
        callback = std::move(cb);
      });

  InitializeUserDataAuth();

  EXPECT_FALSE(callback.is_null());

  SetupMount("foo@gmail.com");

  // This function will not be called.
  EXPECT_CALL(cryptohome_keys_manager_, HasAnyCryptohomeKey()).Times(0);
  EXPECT_CALL(*attrs_, Init()).Times(0);

  std::move(callback).Run(
      MakeStatus<hwsec::TPMError>("fake", TPMRetryAction::kNoRetry));
}

TEST_F(UserDataAuthTest, UpdateCurrentUserActivityTimestampSuccess) {
  constexpr int kTimeshift = 5;

  // Test case for single mount
  SetupMount("foo@gmail.com");

  EXPECT_CALL(*session_, IsActive()).WillOnce(Return(true));
  EXPECT_CALL(*session_, IsEphemeral()).WillOnce(Return(false));
  EXPECT_CALL(user_activity_timestamp_manager_,
              UpdateTimestamp(_, base::Seconds(kTimeshift)))
      .WillOnce(Return(true));

  EXPECT_TRUE(userdataauth_->UpdateCurrentUserActivityTimestamp(kTimeshift));

  // Test case for multiple mounts
  NiceMock<MockUserSession>* const prev_session = session_;
  SetupMount("bar@gmail.com");

  EXPECT_CALL(*session_, IsActive()).WillOnce(Return(true));
  EXPECT_CALL(*session_, IsEphemeral()).WillOnce(Return(false));
  EXPECT_CALL(*prev_session, IsActive()).WillOnce(Return(true));
  EXPECT_CALL(*prev_session, IsEphemeral()).WillOnce(Return(false));
  EXPECT_CALL(user_activity_timestamp_manager_,
              UpdateTimestamp(_, base::Seconds(kTimeshift)))
      .Times(2)
      .WillRepeatedly(Return(true));

  EXPECT_TRUE(userdataauth_->UpdateCurrentUserActivityTimestamp(kTimeshift));
}

TEST_F(UserDataAuthTest, UpdateCurrentUserActivityTimestampFailure) {
  constexpr int kTimeshift = 5;

  // Test case for single mount
  SetupMount("foo@gmail.com");

  EXPECT_CALL(*session_, IsActive()).WillOnce(Return(true));
  EXPECT_CALL(*session_, IsEphemeral()).WillOnce(Return(false));
  EXPECT_CALL(user_activity_timestamp_manager_,
              UpdateTimestamp(_, base::Seconds(kTimeshift)))
      .WillOnce(Return(false));

  EXPECT_FALSE(userdataauth_->UpdateCurrentUserActivityTimestamp(kTimeshift));
}

// ======================= CleanUpStaleMounts tests ==========================

namespace {

struct Mounts {
  const FilePath src;
  const FilePath dst;
};

const std::vector<Mounts> kShadowMounts = {
    {FilePath("/home/.shadow/a"), FilePath("/home/root/0")},
    {FilePath("/home/.shadow/a"), FilePath("/home/user/0")},
    {FilePath("/home/.shadow/a"), FilePath("/home/chronos/user")},
    {FilePath("/home/.shadow/a/Downloads"),
     FilePath("/home/chronos/user/MyFiles/Downloads")},
    {FilePath("/home/.shadow/a/server/run"),
     FilePath("/daemon-store/server/a")},
    {FilePath("/home/.shadow/b"), FilePath("/home/root/1")},
    {FilePath("/home/.shadow/b"), FilePath("/home/user/1")},
    {FilePath("/home/.shadow/b/Downloads"),
     FilePath("/home/chronos/u-b/MyFiles/Downloads")},
    {FilePath("/home/.shadow/b/Downloads"),
     FilePath("/home/user/b/MyFiles/Downloads")},
    {FilePath("/home/.shadow/b/server/run"),
     FilePath("/daemon-store/server/b")},
};

const std::vector<Mounts> kDmcryptMounts = {
    {FilePath("/dev/mapper/dmcrypt-4567-data"), FilePath("/home/root/1")},
    {FilePath("/dev/mapper/dmcrypt-4567-data"), FilePath("/home/user/1")},
    {FilePath("/dev/mapper/dmcrypt-1234-data"), FilePath("/home/root/0")},
    {FilePath("/dev/mapper/dmcrypt-1234-data"), FilePath("/home/user/0")},
    {FilePath("/dev/mapper/dmcrypt-1234-data"), FilePath("/home/chronos/user")},
    {FilePath("/dev/mapper/dmcrypt-1234-data"),
     FilePath("/home/chronos/user/MyFiles/Downloads")},
    {FilePath("/dev/mapper/dmcrypt-1234-data"),
     FilePath("/daemon-store/server/a")},
    {FilePath("/dev/mapper/dmcrypt-1234-data"),
     FilePath("/home/chronos/u-b/MyFiles/Downloads")},
    {FilePath("/dev/mapper/dmcrypt-1234-data"),
     FilePath("/home/user/b/MyFiles/Downloads")},
    {FilePath("/dev/mapper/dmcrypt-1234-data"),
     FilePath("/daemon-store/server/b")},
    {FilePath("/dev/mapper/dmcrypt-1234-data"),
     FilePath("/home/chronos/user/Cache")},
    {FilePath("/dev/mapper/dmcrypt-1234-data"),
     FilePath("/home/chronos/user/GCache")},
    {FilePath("/dev/mapper/dmcrypt-1234-data"),
     FilePath("/home/chronos/u-1234/Cache")},
    {FilePath("/dev/mapper/dmcrypt-1234-data"),
     FilePath("/home/chronos/u-1234/GCache")},
    {FilePath("/dev/mapper/dmcrypt-1234-data"),
     FilePath("/home/user/1234/Cache")},
    {FilePath("/dev/mapper/dmcrypt-1234-data"),
     FilePath("/home/user/1234/GCache")},
};

// Ephemeral mounts must be at the beginning.
const std::vector<Mounts> kLoopDevMounts = {
    {FilePath("/dev/loop7"), FilePath("/run/cryptohome/ephemeral_mount/1")},
    {FilePath("/dev/loop7"), FilePath("/home/user/0")},
    {FilePath("/dev/loop7"), FilePath("/home/root/0")},
    {FilePath("/dev/loop7"), FilePath("/home/chronos/u-1")},
    {FilePath("/dev/loop7"), FilePath("/home/chronos/user")},
    {FilePath("/dev/loop1"), FilePath("/opt/google/containers")},
    {FilePath("/dev/loop2"), FilePath("/home/root/1")},
    {FilePath("/dev/loop2"), FilePath("/home/user/1")},
};

// 5 Mounts in the above are from /dev/loop7, which is ephemeral as seen
// in kLoopDevices.
const int kEphemeralMountsCount = 5;

// Constants used by CleanUpStaleMounts tests.
const std::vector<Platform::LoopDevice> kLoopDevices = {
    {FilePath("/mnt/stateful_partition/encrypted.block"),
     FilePath("/dev/loop0")},
    {FilePath("/run/cryptohome/ephemeral_data/1"), FilePath("/dev/loop7")},
};

const std::vector<FilePath> kSparseFiles = {
    FilePath("/run/cryptohome/ephemeral_data/2"),
    FilePath("/run/cryptohome/ephemeral_data/1"),
};

// Utility functions used by CleanUpStaleMounts tests.
bool StaleShadowMounts(const FilePath& from_prefix,
                       std::multimap<const FilePath, const FilePath>* mounts) {
  int i = 0;

  for (const auto& m : kShadowMounts) {
    if (m.src.value().find(from_prefix.value()) == 0) {
      i++;
      if (mounts)
        mounts->insert(std::make_pair(m.src, m.dst));
    }
  }
  return i > 0;
}

bool DmcryptDeviceMounts(
    const std::string& from_prefix,
    std::multimap<const FilePath, const FilePath>* mounts) {
  if (!mounts)
    return false;
  for (const auto& m : kDmcryptMounts)
    mounts->insert(std::make_pair(m.src, m.dst));
  return true;
}

bool LoopDeviceMounts(std::multimap<const FilePath, const FilePath>* mounts) {
  if (!mounts)
    return false;
  for (const auto& m : kLoopDevMounts)
    mounts->insert(std::make_pair(m.src, m.dst));
  return true;
}

bool EnumerateSparseFiles(const base::FilePath& path,
                          bool is_recursive,
                          std::vector<base::FilePath>* ent_list) {
  if (path != FilePath(kEphemeralCryptohomeDir).Append(kSparseFileDir))
    return false;
  ent_list->insert(ent_list->begin(), kSparseFiles.begin(), kSparseFiles.end());
  return true;
}

}  // namespace

TEST_F(UserDataAuthTest, CleanUpStale_NoOpenFiles_Dmcrypt) {
  // Check that when we have dm-crypt mounts, no active mounts,
  // and no open filehandles, all stale mounts are unmounted.

  EXPECT_CALL(platform_, GetMountsByDevicePrefix("/dev/mapper/dmcrypt", _))
      .WillOnce(Invoke(DmcryptDeviceMounts));

  EXPECT_CALL(platform_, ExpireMount(_))
      .Times(kDmcryptMounts.size())
      .WillRepeatedly(Return(ExpireMountResult::kMarked));

  for (int i = 0; i < kDmcryptMounts.size(); ++i) {
    EXPECT_CALL(platform_, Unmount(kDmcryptMounts[i].dst, true, _))
        .WillRepeatedly(Return(true));
  }

  EXPECT_FALSE(userdataauth_->CleanUpStaleMounts(false));
}

TEST_F(UserDataAuthTest, CleanUpStale_OpenFiles_Dmcrypt) {
  // Check that when we have dm-crypt mounts, files open on dm-crypt cryptohome
  // for one user and no open filehandles, all stale mounts for the second user
  // are unmounted.
  EXPECT_CALL(platform_, GetMountsByDevicePrefix("/dev/mapper/dmcrypt", _))
      .WillOnce(Invoke(DmcryptDeviceMounts));

  // The number of expired mounts depends on when the first busy mount is
  // traversed through. In this case, /home/chronos/user is the 3rd mount in
  // the list, so ExpireMount() is called for the first two non-busy mounts for
  // user 1234 and then for the non-busy stale mounts for user 4567.
  const int kBusyMountIndex = 4;
  EXPECT_CALL(platform_, ExpireMount(_))
      .Times(kBusyMountIndex)
      .WillRepeatedly(Return(ExpireMountResult::kMarked));

  EXPECT_CALL(platform_, ExpireMount(kDmcryptMounts[kBusyMountIndex].dst))
      .Times(1)
      .WillRepeatedly(Return(ExpireMountResult::kBusy));

  // Only user 4567's mounts will be unmounted.
  for (int i = 0; i < 2; ++i) {
    EXPECT_CALL(platform_, Unmount(kDmcryptMounts[i].dst, true, _))
        .WillRepeatedly(Return(true));
  }

  EXPECT_TRUE(userdataauth_->CleanUpStaleMounts(false));
}

TEST_F(UserDataAuthTest, CleanUpStale_OpenFiles_Dmcrypt_Forced) {
  // Check that when we have dm-crypt mounts, files open on dm-crypt
  // and no open filehandles, all stale mounts are unmounted.

  EXPECT_CALL(platform_, GetMountsByDevicePrefix("/dev/mapper/dmcrypt", _))
      .WillOnce(Invoke(DmcryptDeviceMounts));
  EXPECT_CALL(platform_, ExpireMount(_)).Times(0);

  for (int i = 0; i < kDmcryptMounts.size(); ++i) {
    EXPECT_CALL(platform_, Unmount(kDmcryptMounts[i].dst, true, _))
        .WillRepeatedly(Return(true));
  }

  EXPECT_FALSE(userdataauth_->CleanUpStaleMounts(true));
}

TEST_F(UserDataAuthTest, CleanUpStale_NoOpenFiles_Ephemeral) {
  // Check that when we have ephemeral mounts, no active mounts,
  // and no open filehandles, all stale mounts are unmounted, loop device is
  // detached and sparse file is deleted.

  EXPECT_CALL(platform_, GetMountsBySourcePrefix(_, _)).WillOnce(Return(false));
  EXPECT_CALL(platform_, GetAttachedLoopDevices())
      .WillRepeatedly(Return(kLoopDevices));
  EXPECT_CALL(platform_, GetLoopDeviceMounts(_))
      .WillOnce(Invoke(LoopDeviceMounts));
  EXPECT_CALL(
      platform_,
      EnumerateDirectoryEntries(
          FilePath(kEphemeralCryptohomeDir).Append(kSparseFileDir), _, _))
      .WillOnce(Invoke(EnumerateSparseFiles));
  EXPECT_CALL(platform_, ExpireMount(_))
      .Times(kEphemeralMountsCount)
      .WillRepeatedly(Return(ExpireMountResult::kMarked));

  for (int i = 0; i < kEphemeralMountsCount; ++i) {
    EXPECT_CALL(platform_, Unmount(kLoopDevMounts[i].dst, true, _))
        .WillRepeatedly(Return(true));
  }
  EXPECT_CALL(platform_, DetachLoop(FilePath("/dev/loop7")))
      .WillOnce(Return(true));
  EXPECT_CALL(platform_, DeleteFile(kSparseFiles[0])).WillOnce(Return(true));
  EXPECT_CALL(platform_, DeleteFile(kSparseFiles[1])).WillOnce(Return(true));
  EXPECT_CALL(platform_, DeletePathRecursively(kLoopDevMounts[0].dst))
      .WillOnce(Return(true));
  EXPECT_FALSE(userdataauth_->CleanUpStaleMounts(false));
}

TEST_F(UserDataAuthTest, CleanUpStale_OpenLegacy_Ephemeral) {
  // Check that when we have ephemeral mounts, no active mounts,
  // and some open filehandles to the legacy homedir, everything is kept.

  EXPECT_CALL(platform_, GetMountsBySourcePrefix(_, _)).WillOnce(Return(false));
  EXPECT_CALL(platform_, GetAttachedLoopDevices())
      .WillRepeatedly(Return(kLoopDevices));
  EXPECT_CALL(platform_, GetLoopDeviceMounts(_))
      .WillOnce(Invoke(LoopDeviceMounts));
  EXPECT_CALL(
      platform_,
      EnumerateDirectoryEntries(
          FilePath(kEphemeralCryptohomeDir).Append(kSparseFileDir), _, _))
      .WillOnce(Invoke(EnumerateSparseFiles));
  EXPECT_CALL(platform_, ExpireMount(_))
      .Times(kEphemeralMountsCount - 1)
      .WillRepeatedly(Return(ExpireMountResult::kMarked));
  EXPECT_CALL(platform_, ExpireMount(FilePath("/home/chronos/user")))
      .Times(1)
      .WillRepeatedly(Return(ExpireMountResult::kBusy));

  EXPECT_CALL(platform_, GetMountsBySourcePrefix(FilePath("/dev/loop7"), _))
      .WillOnce(Return(false));

  EXPECT_CALL(platform_, Unmount(_, _, _)).Times(0);
  EXPECT_TRUE(userdataauth_->CleanUpStaleMounts(false));
}

TEST_F(UserDataAuthTest, CleanUpStale_OpenLegacy_Ephemeral_Forced) {
  // Check that when we have ephemeral mounts, no active mounts,
  // and some open filehandles to the legacy homedir, but cleanup is forced,
  // all mounts are unmounted, loop device is detached and file is deleted.

  EXPECT_CALL(platform_, GetMountsBySourcePrefix(_, _)).WillOnce(Return(false));
  EXPECT_CALL(platform_, GetAttachedLoopDevices())
      .WillRepeatedly(Return(kLoopDevices));
  EXPECT_CALL(platform_, GetLoopDeviceMounts(_))
      .WillOnce(Invoke(LoopDeviceMounts));
  EXPECT_CALL(
      platform_,
      EnumerateDirectoryEntries(
          FilePath(kEphemeralCryptohomeDir).Append(kSparseFileDir), _, _))
      .WillOnce(Invoke(EnumerateSparseFiles));
  EXPECT_CALL(platform_, ExpireMount(_)).Times(0);

  for (int i = 0; i < kEphemeralMountsCount; ++i) {
    EXPECT_CALL(platform_, Unmount(kLoopDevMounts[i].dst, true, _))
        .WillRepeatedly(Return(true));
  }
  EXPECT_CALL(platform_, DetachLoop(FilePath("/dev/loop7")))
      .WillOnce(Return(true));
  EXPECT_CALL(platform_, DeleteFile(kSparseFiles[0])).WillOnce(Return(true));
  EXPECT_CALL(platform_, DeleteFile(kSparseFiles[1])).WillOnce(Return(true));
  EXPECT_CALL(platform_, DeletePathRecursively(kLoopDevMounts[0].dst))
      .WillOnce(Return(true));
  EXPECT_FALSE(userdataauth_->CleanUpStaleMounts(true));
}

TEST_F(UserDataAuthTest, CleanUpStale_EmptyMap_NoOpenFiles_ShadowOnly) {
  // Check that when we have a bunch of stale shadow mounts, no active mounts,
  // and no open filehandles, all stale mounts are unmounted.

  EXPECT_CALL(platform_, GetMountsBySourcePrefix(_, _))
      .WillOnce(Invoke(StaleShadowMounts));
  EXPECT_CALL(platform_, GetAttachedLoopDevices())
      .WillRepeatedly(Return(std::vector<Platform::LoopDevice>()));
  EXPECT_CALL(platform_, GetLoopDeviceMounts(_)).WillOnce(Return(false));
  EXPECT_CALL(
      platform_,
      EnumerateDirectoryEntries(
          FilePath(kEphemeralCryptohomeDir).Append(kSparseFileDir), _, _))
      .WillOnce(Return(false));
  EXPECT_CALL(platform_, ExpireMount(_))
      .Times(kShadowMounts.size())
      .WillRepeatedly(Return(ExpireMountResult::kMarked));
  EXPECT_CALL(platform_, Unmount(_, true, _))
      .Times(kShadowMounts.size())
      .WillRepeatedly(Return(true));
  EXPECT_FALSE(userdataauth_->CleanUpStaleMounts(false));
}

TEST_F(UserDataAuthTest, CleanUpStale_EmptyMap_NoOpenFiles_ShadowOnly_Forced) {
  // Check that when we have a bunch of stale shadow mounts, no active mounts,
  // and no open filehandles, all stale mounts are unmounted and we attempt
  // to clear the encryption key for fscrypt/ecryptfs mounts.

  EXPECT_CALL(platform_, GetMountsBySourcePrefix(_, _))
      .WillOnce(Invoke(StaleShadowMounts));
  EXPECT_CALL(platform_, GetAttachedLoopDevices())
      .WillRepeatedly(Return(std::vector<Platform::LoopDevice>()));
  EXPECT_CALL(platform_, GetLoopDeviceMounts(_)).WillOnce(Return(false));
  EXPECT_CALL(
      platform_,
      EnumerateDirectoryEntries(
          FilePath(kEphemeralCryptohomeDir).Append(kSparseFileDir), _, _))
      .WillOnce(Return(false));
  EXPECT_CALL(platform_, Unmount(_, true, _))
      .Times(kShadowMounts.size())
      .WillRepeatedly(Return(true));

  // Expect the cleanup to clear user keys.
  EXPECT_CALL(platform_, ClearUserKeyring()).WillOnce(Return(true));
  EXPECT_CALL(platform_, InvalidateDirCryptoKey(_, _))
      .Times(kShadowMounts.size())
      .WillRepeatedly(Return(true));

  EXPECT_FALSE(userdataauth_->CleanUpStaleMounts(true));
}

TEST_F(UserDataAuthTest, CleanUpStale_EmptyMap_OpenLegacy_ShadowOnly) {
  // Check that when we have a bunch of stale shadow mounts, no active mounts,
  // and some open filehandles to the legacy homedir, all mounts without
  // filehandles are unmounted.

  // Called by CleanUpStaleMounts and each time a directory is excluded.
  EXPECT_CALL(platform_, GetMountsBySourcePrefix(_, _))
      .Times(4)
      .WillRepeatedly(Invoke(StaleShadowMounts));
  EXPECT_CALL(platform_, GetAttachedLoopDevices())
      .WillRepeatedly(Return(std::vector<Platform::LoopDevice>()));
  EXPECT_CALL(platform_, GetLoopDeviceMounts(_)).WillOnce(Return(false));
  EXPECT_CALL(
      platform_,
      EnumerateDirectoryEntries(
          FilePath(kEphemeralCryptohomeDir).Append(kSparseFileDir), _, _))
      .WillOnce(Return(false));
  EXPECT_CALL(platform_,
              ExpireMount(Property(&FilePath::value, EndsWith("/0"))))
      .WillRepeatedly(Return(ExpireMountResult::kBusy));
  EXPECT_CALL(platform_, ExpireMount(FilePath("/home/chronos/user")))
      .WillRepeatedly(Return(ExpireMountResult::kBusy));
  EXPECT_CALL(platform_,
              ExpireMount(Property(
                  &FilePath::value,
                  AnyOf(EndsWith("/1"), EndsWith("b/MyFiles/Downloads")))))
      .Times(4)
      .WillRepeatedly(Return(ExpireMountResult::kMarked));
  EXPECT_CALL(platform_, ExpireMount(FilePath("/daemon-store/server/b")))
      .WillOnce(Return(ExpireMountResult::kMarked));
  // Given /home/chronos/user and a is marked as active, only b mounts should be
  // removed.
  EXPECT_CALL(
      platform_,
      Unmount(Property(&FilePath::value,
                       AnyOf(EndsWith("/1"), EndsWith("b/MyFiles/Downloads"))),
              true, _))
      .Times(4)
      .WillRepeatedly(Return(true));
  EXPECT_CALL(platform_, Unmount(FilePath("/daemon-store/server/b"), true, _))
      .WillOnce(Return(true));
  EXPECT_CALL(platform_,
              Unmount(Property(&FilePath::value, EndsWith("/0")), true, _))
      .Times(0);
  EXPECT_CALL(platform_, Unmount(FilePath("/home/chronos/user"), true, _))
      .Times(0);
  EXPECT_TRUE(userdataauth_->CleanUpStaleMounts(false));
}

TEST_F(UserDataAuthTest, CleanUpStale_FilledMap_NoOpenFiles_ShadowOnly) {
  constexpr char kUser[] = "foo@bar.net";

  // Checks that when we have a bunch of stale shadow mounts, some active
  // mounts, and no open filehandles, all inactive mounts are unmounted.

  // Override the optional USS experiment flag with any value to avoid extra
  // FileExists checks on USS flag files.
  SetUserSecretStashExperimentForTesting(/*enabled*/ true);
  EXPECT_CALL(platform_, FileExists(base::FilePath("/home/.shadow/salt")))
      .WillOnce(Return(true));
  EXPECT_CALL(platform_,
              FileExists(base::FilePath("/run/cryptohome/not_first_boot")))
      .WillOnce(Return(true));

  EXPECT_CALL(platform_, GetMountsBySourcePrefix(_, _)).WillOnce(Return(false));
  EXPECT_CALL(platform_, GetAttachedLoopDevices())
      .WillRepeatedly(Return(std::vector<Platform::LoopDevice>()));
  EXPECT_CALL(platform_, GetLoopDeviceMounts(_)).WillOnce(Return(false));

  InitializeUserDataAuth();

  EXPECT_CALL(user_session_factory_, New(Username(kUser), _, _))
      .WillOnce(Return(ByMove(CreateSessionAndRememberPtr())));
  EXPECT_CALL(homedirs_, Exists(_)).WillOnce(Return(true));
  EXPECT_CALL(disk_cleanup_, FreeDiskSpaceDuringLogin(_));
  EXPECT_CALL(*session_, MountVault(_, _, _))
      .WillOnce(ReturnError<CryptohomeMountError>());
  EXPECT_CALL(platform_, GetMountsBySourcePrefix(_, _)).WillOnce(Return(false));
  EXPECT_CALL(platform_, GetAttachedLoopDevices())
      .WillRepeatedly(Return(std::vector<Platform::LoopDevice>()));
  EXPECT_CALL(platform_, GetLoopDeviceMounts(_)).WillOnce(Return(false));

  // StartAuthSession for new user.
  user_data_auth::StartAuthSessionRequest start_session_req;
  start_session_req.mutable_account_id()->set_account_id(kUser);
  start_session_req.set_flags(
      user_data_auth::AuthSessionFlags::AUTH_SESSION_FLAGS_NONE);
  start_session_req.set_intent(user_data_auth::AuthIntent::AUTH_INTENT_DECRYPT);

  TestFuture<user_data_auth::StartAuthSessionReply> reply_future;
  userdataauth_->StartAuthSession(
      start_session_req,
      reply_future.GetCallback<const user_data_auth::StartAuthSessionReply&>());
  EXPECT_EQ(reply_future.Get().error(),
            user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  std::optional<base::UnguessableToken> auth_session_id =
      AuthSession::GetTokenFromSerializedString(
          reply_future.Get().auth_session_id());
  ASSERT_TRUE(auth_session_id.has_value());

  // Get the session into an authenticated state by treating it as if we just
  // freshly created the user.
  {
    InUseAuthSession auth_session =
        userdataauth_->auth_session_manager_->FindAuthSession(
            auth_session_id.value());
    ASSERT_THAT(auth_session.AuthSessionStatus(), IsOk());
    EXPECT_THAT(auth_session->OnUserCreated(), IsOk());
  }

  // Mount user vault.
  user_data_auth::PreparePersistentVaultRequest prepare_request;
  prepare_request.set_auth_session_id(reply_future.Get().auth_session_id());
  TestFuture<user_data_auth::PreparePersistentVaultReply> prepare_future;

  userdataauth_->PreparePersistentVault(
      prepare_request,
      prepare_future
          .GetCallback<const user_data_auth::PreparePersistentVaultReply&>());
  ASSERT_EQ(prepare_future.Get().error_info().primary_action(),
            user_data_auth::PrimaryAction::PRIMARY_NO_ERROR);

  // Test CleanUpStaleMounts.

  EXPECT_CALL(platform_, GetMountsBySourcePrefix(_, _))
      .Times(4)
      .WillRepeatedly(Invoke(StaleShadowMounts));
  EXPECT_CALL(platform_, GetAttachedLoopDevices())
      .WillRepeatedly(Return(std::vector<Platform::LoopDevice>()));
  EXPECT_CALL(platform_, GetLoopDeviceMounts(_)).WillOnce(Return(false));
  EXPECT_CALL(
      platform_,
      EnumerateDirectoryEntries(
          FilePath(kEphemeralCryptohomeDir).Append(kSparseFileDir), _, _))
      .WillOnce(Return(false));
  // Only 5 look ups: user/1 and root/1 are owned, children of these
  // directories are excluded. ExpireMount is expected to run on exactly the
  // same mount points that are expected to be unmounted below. But it is
  // important to check the number of calls here to make sure ExpireMount
  // doesn't run on any other mount points.
  EXPECT_CALL(platform_, ExpireMount(_))
      .Times(5)
      .WillRepeatedly(Return(ExpireMountResult::kMarked));

  EXPECT_CALL(*session_, OwnsMountPoint(_)).WillRepeatedly(Return(false));
  EXPECT_CALL(*session_, OwnsMountPoint(FilePath("/home/user/1")))
      .WillOnce(Return(true));
  EXPECT_CALL(*session_, OwnsMountPoint(FilePath("/home/root/1")))
      .WillOnce(Return(true));

  EXPECT_CALL(platform_,
              Unmount(Property(&FilePath::value, EndsWith("/0")), true, _))
      .Times(2)
      .WillRepeatedly(Return(true));
  EXPECT_CALL(platform_, Unmount(FilePath("/home/chronos/user"), true, _))
      .WillOnce(Return(true));
  EXPECT_CALL(platform_, Unmount(Property(&FilePath::value,
                                          EndsWith("user/MyFiles/Downloads")),
                                 true, _))
      .WillOnce(Return(true));
  EXPECT_CALL(platform_, Unmount(FilePath("/daemon-store/server/a"), true, _))
      .WillOnce(Return(true));

  std::vector<std::string> fake_token_list;
  fake_token_list.push_back("/home/chronos/user/token");
  fake_token_list.push_back("/home/user/1/token");
  fake_token_list.push_back("/home/root/1/token");
  EXPECT_CALL(chaps_client_, GetTokenList(_, _))
      .WillRepeatedly(DoAll(SetArgPointee<1>(fake_token_list), Return(true)));

  EXPECT_CALL(chaps_client_,
              UnloadToken(_, FilePath("/home/chronos/user/token")))
      .Times(1);
  // Expect that CleanUpStaleMounts() tells us it skipped mounts since 1 is
  // still logged in.
  EXPECT_TRUE(userdataauth_->CleanUpStaleMounts(false));

  SetUserSecretStashExperimentForTesting(/*enabled*/ std::nullopt);
}

TEST_F(UserDataAuthTest,
       CleanUpStale_FilledMap_NoOpenFiles_ShadowOnly_FirstBoot) {
  constexpr char kUser[] = "foo@bar.net";

  // Checks that when we have a bunch of stale shadow mounts, some active
  // mounts, and no open filehandles, all inactive mounts are unmounted.
  // Override the optional USS experiment flag with any value to avoid extra
  // FileExists checks on USS flag files.
  SetUserSecretStashExperimentForTesting(/*enabled*/ true);
  EXPECT_CALL(platform_, FileExists(base::FilePath("/home/.shadow/salt")))
      .WillOnce(Return(false));
  EXPECT_CALL(platform_,
              FileExists(base::FilePath("/run/cryptohome/not_first_boot")))
      .WillOnce(Return(false));
  EXPECT_CALL(platform_, GetMountsBySourcePrefix(_, _)).Times(0);
  EXPECT_CALL(platform_, GetAttachedLoopDevices()).Times(0);
  EXPECT_CALL(platform_, GetLoopDeviceMounts(_)).Times(0);

  InitializeUserDataAuth();

  EXPECT_CALL(user_session_factory_, New(Username(kUser), _, _))
      .WillOnce(Return(ByMove(CreateSessionAndRememberPtr())));
  EXPECT_CALL(homedirs_, Exists(_)).WillOnce(ReturnValue(true));
  EXPECT_CALL(disk_cleanup_, FreeDiskSpaceDuringLogin(_));
  EXPECT_CALL(*session_, MountVault(_, _, _))
      .WillOnce(ReturnError<CryptohomeMountError>());
  EXPECT_CALL(platform_, GetMountsBySourcePrefix(_, _)).WillOnce(Return(false));
  EXPECT_CALL(platform_, GetAttachedLoopDevices())
      .WillRepeatedly(Return(std::vector<Platform::LoopDevice>()));
  EXPECT_CALL(platform_, GetLoopDeviceMounts(_)).WillOnce(Return(false));

  // StartAuthSession for new user
  user_data_auth::StartAuthSessionRequest start_session_req;
  start_session_req.mutable_account_id()->set_account_id(kUser);
  start_session_req.set_flags(
      user_data_auth::AuthSessionFlags::AUTH_SESSION_FLAGS_NONE);
  start_session_req.set_intent(user_data_auth::AuthIntent::AUTH_INTENT_DECRYPT);

  TestFuture<user_data_auth::StartAuthSessionReply> reply_future;
  userdataauth_->StartAuthSession(
      start_session_req,
      reply_future.GetCallback<const user_data_auth::StartAuthSessionReply&>());
  EXPECT_EQ(reply_future.Get().error(),
            user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  std::optional<base::UnguessableToken> auth_session_id =
      AuthSession::GetTokenFromSerializedString(
          reply_future.Get().auth_session_id());
  ASSERT_TRUE(auth_session_id.has_value());

  // Get the session into an authenticated state by treating it as if we just
  // freshly created the user.
  {
    InUseAuthSession auth_session =
        userdataauth_->auth_session_manager_->FindAuthSession(
            auth_session_id.value());
    ASSERT_THAT(auth_session.AuthSessionStatus(), IsOk());
    EXPECT_THAT(auth_session->OnUserCreated(), IsOk());
  }

  // Mount user vault.
  user_data_auth::PreparePersistentVaultRequest prepare_request;
  prepare_request.set_auth_session_id(reply_future.Get().auth_session_id());
  TestFuture<user_data_auth::PreparePersistentVaultReply> prepare_future;

  userdataauth_->PreparePersistentVault(
      prepare_request,
      prepare_future
          .GetCallback<const user_data_auth::PreparePersistentVaultReply&>());
  ASSERT_EQ(prepare_future.Get().error_info().primary_action(),
            user_data_auth::PrimaryAction::PRIMARY_NO_ERROR);

  EXPECT_CALL(platform_, GetMountsBySourcePrefix(_, _))
      .Times(4)
      .WillRepeatedly(Invoke(StaleShadowMounts));
  EXPECT_CALL(platform_, GetAttachedLoopDevices())
      .WillRepeatedly(Return(std::vector<Platform::LoopDevice>()));
  EXPECT_CALL(platform_, GetLoopDeviceMounts(_)).WillOnce(Return(false));
  EXPECT_CALL(
      platform_,
      EnumerateDirectoryEntries(
          FilePath(kEphemeralCryptohomeDir).Append(kSparseFileDir), _, _))
      .WillOnce(Return(false));

  // Only 5 look ups: user/1 and root/1 are owned, children of these
  // directories are excluded. ExpireMount is expected to run on exactly the
  // same mount points that are expected to be unmounted below. But it is
  // important to check the number of calls here to make sure ExpireMount
  // doesn't run on any other mount points.
  EXPECT_CALL(platform_, ExpireMount(_)).Times(5);

  EXPECT_CALL(*session_, OwnsMountPoint(_)).WillRepeatedly(Return(false));
  EXPECT_CALL(*session_, OwnsMountPoint(FilePath("/home/user/1")))
      .WillOnce(Return(true));
  EXPECT_CALL(*session_, OwnsMountPoint(FilePath("/home/root/1")))
      .WillOnce(Return(true));

  EXPECT_CALL(platform_,
              Unmount(Property(&FilePath::value, EndsWith("/0")), true, _))
      .Times(2)
      .WillRepeatedly(Return(true));
  EXPECT_CALL(platform_, Unmount(FilePath("/home/chronos/user"), true, _))
      .WillOnce(Return(true));
  EXPECT_CALL(platform_, Unmount(Property(&FilePath::value,
                                          EndsWith("user/MyFiles/Downloads")),
                                 true, _))
      .WillOnce(Return(true));
  EXPECT_CALL(platform_, Unmount(FilePath("/daemon-store/server/a"), true, _))
      .WillOnce(Return(true));

  std::vector<std::string> fake_token_list;
  fake_token_list.push_back("/home/chronos/user/token");
  fake_token_list.push_back("/home/user/1/token");
  fake_token_list.push_back("/home/root/1/token");
  EXPECT_CALL(chaps_client_, GetTokenList(_, _))
      .WillRepeatedly(DoAll(SetArgPointee<1>(fake_token_list), Return(true)));

  EXPECT_CALL(chaps_client_,
              UnloadToken(_, FilePath("/home/chronos/user/token")))
      .Times(1);

  // Expect that CleanUpStaleMounts() tells us it skipped mounts since 1 is
  // still logged in.
  EXPECT_TRUE(userdataauth_->CleanUpStaleMounts(false));

  SetUserSecretStashExperimentForTesting(/*enabled*/ std::nullopt);
}

TEST_F(UserDataAuthTest, StartMigrateToDircryptoValidity) {
  constexpr char kUsername1[] = "foo@gmail.com";

  user_data_auth::StartMigrateToDircryptoRequest request;
  request.mutable_account_id()->set_account_id(kUsername1);
  request.set_minimal_migration(false);

  SetupMount(kUsername1);

  EXPECT_CALL(*session_, MigrateVault(_, MigrationType::FULL))
      .WillOnce(Return(true));

  int success_cnt = 0;
  {
    userdataauth_->StartMigrateToDircrypto(
        request,
        base::BindRepeating(
            [](int* success_cnt_ptr,
               const user_data_auth::DircryptoMigrationProgress& progress) {
              EXPECT_EQ(progress.status(),
                        user_data_auth::DIRCRYPTO_MIGRATION_SUCCESS);
              (*success_cnt_ptr)++;
            },
            base::Unretained(&success_cnt)));
  }
  EXPECT_EQ(success_cnt, 1);
}

TEST_F(UserDataAuthTest, StartMigrateToDircryptoFailure) {
  constexpr char kUsername1[] = "foo@gmail.com";

  user_data_auth::StartMigrateToDircryptoRequest request;
  request.mutable_account_id()->set_account_id(kUsername1);
  request.set_minimal_migration(false);

  // Test mount non-existent.
  int call_cnt = 0;
  {
    userdataauth_->StartMigrateToDircrypto(
        request,
        base::BindRepeating(
            [](int* call_cnt_ptr,
               const user_data_auth::DircryptoMigrationProgress& progress) {
              EXPECT_EQ(progress.status(),
                        user_data_auth::DIRCRYPTO_MIGRATION_FAILED);
              (*call_cnt_ptr)++;
            },
            base::Unretained(&call_cnt)));
  }
  EXPECT_EQ(call_cnt, 1);

  // Test MigrateToDircrypto failed
  SetupMount(kUsername1);

  EXPECT_CALL(*session_, MigrateVault(_, MigrationType::FULL))
      .WillOnce(Return(false));

  call_cnt = 0;
  {
    userdataauth_->StartMigrateToDircrypto(
        request,
        base::BindRepeating(
            [](int* call_cnt_ptr,
               const user_data_auth::DircryptoMigrationProgress& progress) {
              EXPECT_EQ(progress.status(),
                        user_data_auth::DIRCRYPTO_MIGRATION_FAILED);
              (*call_cnt_ptr)++;
            },
            base::Unretained(&call_cnt)));
  }

  EXPECT_EQ(call_cnt, 1);
}

TEST_F(UserDataAuthTest, NeedsDircryptoMigration) {
  bool result;
  AccountIdentifier account;
  account.set_account_id("foo@gmail.com");

  // Test the case when we are forced to use eCryptfs, and thus no migration is
  // needed.
  userdataauth_->set_force_ecryptfs(true);
  EXPECT_CALL(homedirs_, Exists(_)).WillOnce(Return(true));
  EXPECT_EQ(userdataauth_->NeedsDircryptoMigration(account, &result),
            user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  EXPECT_FALSE(result);

  // Test the case when dircrypto is already in use.
  userdataauth_->set_force_ecryptfs(false);
  EXPECT_CALL(homedirs_, NeedsDircryptoMigration(_)).WillOnce(Return(false));
  EXPECT_CALL(homedirs_, Exists(_)).WillOnce(Return(true));
  EXPECT_EQ(userdataauth_->NeedsDircryptoMigration(account, &result),
            user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  EXPECT_FALSE(result);

  // Test the case when eCryptfs is being used.
  userdataauth_->set_force_ecryptfs(false);
  EXPECT_CALL(homedirs_, NeedsDircryptoMigration(_)).WillOnce(Return(true));
  EXPECT_CALL(homedirs_, Exists(_)).WillOnce(Return(true));
  EXPECT_EQ(userdataauth_->NeedsDircryptoMigration(account, &result),
            user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  EXPECT_TRUE(result);

  // Test for account not found.
  EXPECT_CALL(homedirs_, Exists(_)).WillOnce(Return(false));
  EXPECT_EQ(userdataauth_->NeedsDircryptoMigration(account, &result),
            user_data_auth::CRYPTOHOME_ERROR_ACCOUNT_NOT_FOUND);
}

TEST_F(UserDataAuthTest, LowEntropyCredentialSupported) {
  EXPECT_CALL(hwsec_, IsPinWeaverEnabled()).WillRepeatedly(ReturnValue(false));
  EXPECT_FALSE(userdataauth_->IsLowEntropyCredentialSupported());

  EXPECT_CALL(hwsec_, IsPinWeaverEnabled()).WillRepeatedly(ReturnValue(true));
  EXPECT_TRUE(userdataauth_->IsLowEntropyCredentialSupported());
}

TEST_F(UserDataAuthTest, GetAccountDiskUsage) {
  // Test when the user is non-existent.
  AccountIdentifier account;
  account.set_account_id("non_existent_user");

  EXPECT_EQ(0, userdataauth_->GetAccountDiskUsage(account));

  // Test when the user exists and home directory is not empty.
  const Username kUsername1("foo@gmail.com");
  account.set_account_id(*kUsername1);

  constexpr int64_t kHomedirSize = 12345678912345;
  EXPECT_CALL(homedirs_, ComputeDiskUsage(kUsername1))
      .WillOnce(Return(kHomedirSize));
  EXPECT_EQ(kHomedirSize, userdataauth_->GetAccountDiskUsage(account));
}

TEST_F(UserDataAuthTest, LowDiskSpaceNotificationCallback) {
  EXPECT_CALL(low_disk_space_handler_, SetLowDiskSpaceCallback(_));
  userdataauth_->SetLowDiskSpaceCallback(base::BindRepeating([](uint64_t) {}));
}

TEST_F(UserDataAuthTest, LowDiskSpaceHandlerStopped) {
  EXPECT_CALL(low_disk_space_handler_, Stop());
}

// A test fixture with some utility functions for testing mount and keys related
// functionalities.
class UserDataAuthExTest : public UserDataAuthTest {
 public:
  UserDataAuthExTest() = default;
  UserDataAuthExTest(const UserDataAuthExTest&) = delete;
  UserDataAuthExTest& operator=(const UserDataAuthExTest&) = delete;

  ~UserDataAuthExTest() override = default;

  std::unique_ptr<VaultKeyset> GetNiceMockVaultKeyset(
      const ObfuscatedUsername& obfuscated_username,
      const std::string& key_label) const {
    // Note that technically speaking this is not strictly a mock, and probably
    // closer to a stub. However, the underlying class is
    // NiceMock<MockVaultKeyset>, thus we name the method accordingly.
    std::unique_ptr<VaultKeyset> mvk(new NiceMock<MockVaultKeyset>);
    mvk->SetKeyDataLabel(key_label);

    SerializedVaultKeyset::SignatureChallengeInfo sig_challenge_info;
    mvk->SetSignatureChallengeInfo(sig_challenge_info);

    return mvk;
  }

 protected:
  void PrepareArguments() {
    list_keys_req_ = std::make_unique<user_data_auth::ListKeysRequest>();
    remove_homedir_req_ = std::make_unique<user_data_auth::RemoveRequest>();
    start_auth_session_req_ =
        std::make_unique<user_data_auth::StartAuthSessionRequest>();
  }

  template <class ProtoBuf>
  brillo::Blob BlobFromProtobuf(const ProtoBuf& pb) {
    std::string serialized;
    CHECK(pb.SerializeToString(&serialized));
    return brillo::BlobFromString(serialized);
  }

  template <class ProtoBuf>
  brillo::SecureBlob SecureBlobFromProtobuf(const ProtoBuf& pb) {
    std::string serialized;
    CHECK(pb.SerializeToString(&serialized));
    return brillo::SecureBlob(serialized);
  }

  std::unique_ptr<user_data_auth::ListKeysRequest> list_keys_req_;
  std::unique_ptr<user_data_auth::RemoveRequest> remove_homedir_req_;
  std::unique_ptr<user_data_auth::StartAuthSessionRequest>
      start_auth_session_req_;

  const Username kUser{"chromeos-user"};
  static constexpr char kKey[] = "274146c6e8886a843ddfea373e2dc71b";
};

constexpr char UserDataAuthExTest::kKey[];

TEST_F(UserDataAuthExTest,
       StartMigrateToDircryptoWithAuthenticatedAuthSession) {
  // Setup.
  PrepareArguments();
  constexpr char kUsername1[] = "foo@gmail.com";

  start_auth_session_req_->mutable_account_id()->set_account_id(kUsername1);
  TestFuture<user_data_auth::StartAuthSessionReply> auth_session_reply_future;
  userdataauth_->StartAuthSession(
      *start_auth_session_req_,
      auth_session_reply_future
          .GetCallback<const user_data_auth::StartAuthSessionReply&>());
  EXPECT_EQ(auth_session_reply_future.Get().error(),
            user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  std::optional<base::UnguessableToken> auth_session_id =
      AuthSession::GetTokenFromSerializedString(
          auth_session_reply_future.Get().auth_session_id());
  ASSERT_TRUE(auth_session_id.has_value());

  // Get the session into an authenticated state by treating it as if we just
  // freshly created the user.
  {
    InUseAuthSession auth_session =
        userdataauth_->auth_session_manager_->FindAuthSession(
            auth_session_id.value());
    ASSERT_THAT(auth_session.AuthSessionStatus(), IsOk());
    EXPECT_THAT(auth_session->OnUserCreated(), IsOk());
  }

  user_data_auth::StartMigrateToDircryptoRequest request;
  request.set_auth_session_id(
      auth_session_reply_future.Get().auth_session_id());
  request.set_minimal_migration(false);

  SetupMount(kUsername1);

  EXPECT_CALL(*session_, MigrateVault(_, MigrationType::FULL))
      .WillOnce(Return(true));

  int success_cnt = 0;
  {
    userdataauth_->StartMigrateToDircrypto(
        request,
        base::BindRepeating(
            [](int* success_cnt_ptr,
               const user_data_auth::DircryptoMigrationProgress& progress) {
              EXPECT_EQ(progress.status(),
                        user_data_auth::DIRCRYPTO_MIGRATION_SUCCESS);
              (*success_cnt_ptr)++;
            },
            base::Unretained(&success_cnt)));
  }
  EXPECT_EQ(success_cnt, 1);
}

TEST_F(UserDataAuthExTest,
       StartMigrateToDircryptoWithUnAuthenticatedAuthSession) {
  // Setup.
  PrepareArguments();
  constexpr char kUsername1[] = "foo@gmail.com";

  start_auth_session_req_->mutable_account_id()->set_account_id(kUsername1);
  TestFuture<user_data_auth::StartAuthSessionReply> auth_session_reply_future;
  userdataauth_->StartAuthSession(
      *start_auth_session_req_,
      auth_session_reply_future
          .GetCallback<const user_data_auth::StartAuthSessionReply&>());
  EXPECT_EQ(auth_session_reply_future.Get().error(),
            user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  std::optional<base::UnguessableToken> auth_session_id =
      AuthSession::GetTokenFromSerializedString(
          auth_session_reply_future.Get().auth_session_id());
  ASSERT_TRUE(auth_session_id.has_value());

  InUseAuthSession auth_session =
      userdataauth_->auth_session_manager_->FindAuthSession(
          auth_session_id.value());
  ASSERT_TRUE(auth_session.AuthSessionStatus().ok());

  user_data_auth::StartMigrateToDircryptoRequest request;
  request.set_auth_session_id(
      auth_session_reply_future.Get().auth_session_id());
  request.set_minimal_migration(false);

  int called_ctr = 0;
  {
    userdataauth_->StartMigrateToDircrypto(
        request,
        base::BindRepeating(
            [](int* called_ctr_ptr,
               const user_data_auth::DircryptoMigrationProgress& progress) {
              EXPECT_EQ(progress.status(),
                        user_data_auth::DIRCRYPTO_MIGRATION_FAILED);
              (*called_ctr_ptr)++;
            },
            base::Unretained(&called_ctr)));
  }
  EXPECT_EQ(called_ctr, 1);
}

TEST_F(UserDataAuthExTest, StartMigrateToDircryptoWithInvalidAuthSession) {
  // Setup.
  PrepareArguments();
  constexpr char kFakeAuthSessionId[] = "foo";
  user_data_auth::StartMigrateToDircryptoRequest request;
  request.set_auth_session_id(kFakeAuthSessionId);
  request.set_minimal_migration(false);

  int called_ctr = 0;
  {
    userdataauth_->StartMigrateToDircrypto(
        request,
        base::BindRepeating(
            [](int* called_ctr_ptr,
               const user_data_auth::DircryptoMigrationProgress& progress) {
              EXPECT_EQ(progress.status(),
                        user_data_auth::DIRCRYPTO_MIGRATION_FAILED);
              (*called_ctr_ptr)++;
            },
            base::Unretained(&called_ctr)));
  }
  EXPECT_EQ(called_ctr, 1);
}

constexpr char ListKeysValidityTest_label1[] = "Label 1";
constexpr char ListKeysValidityTest_label2[] = "Yet another label";

TEST_F(UserDataAuthExTest, ListKeysValidity) {
  PrepareArguments();

  list_keys_req_->mutable_account_id()->set_account_id("foo@gmail.com");
  // Note that authorization request in ListKeyRequest is currently not
  // required.

  // Success case.
  EXPECT_CALL(homedirs_, Exists(_)).WillOnce(Return(true));
  EXPECT_CALL(keyset_management_, GetVaultKeysetLabels(_, _, _))
      .WillOnce(
          Invoke([](const ObfuscatedUsername& ignored, bool include_le_labels,
                    std::vector<std::string>* output) {
            output->clear();
            output->push_back(ListKeysValidityTest_label1);
            output->push_back(ListKeysValidityTest_label2);
            return true;
          }));

  user_data_auth::ListKeysReply reply =
      userdataauth_->ListKeys(*list_keys_req_);
  EXPECT_EQ(reply.error_info().primary_action(),
            user_data_auth::PrimaryAction::PRIMARY_NO_ERROR);

  EXPECT_THAT(reply.labels(), ElementsAre(ListKeysValidityTest_label1,
                                          ListKeysValidityTest_label2));

  // Test for account not found case.
  EXPECT_CALL(homedirs_, Exists(_)).WillOnce(Return(false));
  EXPECT_NE(
      userdataauth_->ListKeys(*list_keys_req_).error_info().primary_action(),
      user_data_auth::PrimaryAction::PRIMARY_NO_ERROR);

  // Test for key not found case.
  EXPECT_CALL(homedirs_, Exists(_)).WillOnce(Return(true));
  EXPECT_CALL(keyset_management_, GetVaultKeysetLabels(_, _, _))
      .WillOnce(Return(false));
  EXPECT_NE(
      userdataauth_->ListKeys(*list_keys_req_).error_info().primary_action(),
      user_data_auth::PrimaryAction::PRIMARY_NO_ERROR);
}

TEST_F(UserDataAuthExTest, ListKeysInvalidArgs) {
  PrepareArguments();

  // No Email.
  EXPECT_NE(
      userdataauth_->ListKeys(*list_keys_req_).error_info().primary_action(),
      user_data_auth::PrimaryAction::PRIMARY_NO_ERROR);

  // Empty email.
  list_keys_req_->mutable_account_id()->set_account_id("");
  EXPECT_NE(
      userdataauth_->ListKeys(*list_keys_req_).error_info().primary_action(),
      user_data_auth::PrimaryAction::PRIMARY_NO_ERROR);
}

TEST_F(UserDataAuthExTest, RemoveValidity) {
  PrepareArguments();

  const Username kUsername1("foo@gmail.com");

  remove_homedir_req_->mutable_identifier()->set_account_id(*kUsername1);

  // Test for successful case.
  EXPECT_CALL(homedirs_, Remove(GetObfuscatedUsername(kUsername1)))
      .WillOnce(Return(true));
  EXPECT_EQ(
      userdataauth_->Remove(*remove_homedir_req_).error_info().primary_action(),
      user_data_auth::PrimaryAction::PRIMARY_NO_ERROR);

  // Test for unsuccessful case.
  EXPECT_CALL(homedirs_, Remove(GetObfuscatedUsername(kUsername1)))
      .WillOnce(Return(false));
  EXPECT_NE(
      userdataauth_->Remove(*remove_homedir_req_).error_info().primary_action(),
      user_data_auth::PrimaryAction::PRIMARY_NO_ERROR);
}

TEST_F(UserDataAuthExTest, RemoveBusyMounted) {
  PrepareArguments();
  SetupMount(*kUser);
  remove_homedir_req_->mutable_identifier()->set_account_id(*kUser);
  ON_CALL(*session_, IsActive()).WillByDefault(Return(true));
  EXPECT_NE(
      userdataauth_->Remove(*remove_homedir_req_).error_info().primary_action(),
      user_data_auth::PrimaryAction::PRIMARY_NO_ERROR);
}

TEST_F(UserDataAuthExTest, RemoveInvalidArguments) {
  PrepareArguments();

  // No account_id and AuthSession ID
  EXPECT_NE(
      userdataauth_->Remove(*remove_homedir_req_).error_info().primary_action(),
      user_data_auth::PrimaryAction::PRIMARY_NO_ERROR);

  // Empty account_id
  remove_homedir_req_->mutable_identifier()->set_account_id("");
  EXPECT_NE(
      userdataauth_->Remove(*remove_homedir_req_).error_info().primary_action(),
      user_data_auth::PrimaryAction::PRIMARY_NO_ERROR);
}

TEST_F(UserDataAuthExTest, RemoveInvalidAuthSession) {
  PrepareArguments();
  std::string invalid_token = "invalid_token_16";
  remove_homedir_req_->set_auth_session_id(invalid_token);

  // Test.
  EXPECT_NE(
      userdataauth_->Remove(*remove_homedir_req_).error_info().primary_action(),
      user_data_auth::PrimaryAction::PRIMARY_NO_ERROR);
}

TEST_F(UserDataAuthExTest, RemoveValidityWithAuthSession) {
  PrepareArguments();

  // Setup
  const Username kUsername1("foo@gmail.com");

  start_auth_session_req_->mutable_account_id()->set_account_id(*kUsername1);
  TestFuture<user_data_auth::StartAuthSessionReply> auth_session_reply_future;
  userdataauth_->StartAuthSession(
      *start_auth_session_req_,
      auth_session_reply_future
          .GetCallback<const user_data_auth::StartAuthSessionReply&>());
  EXPECT_EQ(auth_session_reply_future.Get().error(),
            user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  const std::string auth_session_id =
      auth_session_reply_future.Get().auth_session_id();

  // Test
  remove_homedir_req_->set_auth_session_id(auth_session_id);
  EXPECT_CALL(homedirs_, Remove(GetObfuscatedUsername(kUsername1)))
      .WillOnce(Return(true));
  EXPECT_EQ(
      userdataauth_->Remove(*remove_homedir_req_).error_info().primary_action(),
      user_data_auth::PrimaryAction::PRIMARY_NO_ERROR);

  // Verify
  InUseAuthSession auth_session =
      userdataauth_->auth_session_manager_->FindAuthSession(auth_session_id);
  EXPECT_FALSE(auth_session.AuthSessionStatus().ok());
}

TEST_F(UserDataAuthExTest, StartAuthSession) {
  PrepareArguments();
  start_auth_session_req_->mutable_account_id()->set_account_id(
      "foo@example.com");
  TestFuture<user_data_auth::StartAuthSessionReply> auth_session_reply_future;
  userdataauth_->StartAuthSession(
      *start_auth_session_req_,
      auth_session_reply_future
          .GetCallback<const user_data_auth::StartAuthSessionReply&>());
  EXPECT_EQ(auth_session_reply_future.Get().error(),
            user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  std::optional<base::UnguessableToken> auth_session_id =
      AuthSession::GetTokenFromSerializedString(
          auth_session_reply_future.Get().auth_session_id());
  ASSERT_TRUE(auth_session_id.has_value());
  InUseAuthSession auth_session =
      userdataauth_->auth_session_manager_->FindAuthSession(
          auth_session_id.value());
  ASSERT_TRUE(auth_session.AuthSessionStatus().ok());
  EXPECT_EQ(auth_session->token(), *auth_session_id);
  std::optional<base::UnguessableToken> broadcast_id =
      AuthSession::GetTokenFromSerializedString(
          auth_session_reply_future.Get().broadcast_id());
  ASSERT_TRUE(broadcast_id.has_value());
  EXPECT_EQ(auth_session->public_token(), *broadcast_id);
}

TEST_F(UserDataAuthExTest, StartAuthSessionUnusableClobber) {
  PrepareArguments();
  start_auth_session_req_->mutable_account_id()->set_account_id(
      "foo@example.com");
  EXPECT_CALL(keyset_management_, UserExists(_)).WillOnce(Return(true));
  EXPECT_CALL(platform_, GetFileEnumerator(_, _, _))
      .WillOnce(Return(new NiceMock<MockFileEnumerator>));
  TestFuture<user_data_auth::StartAuthSessionReply> auth_session_reply_future;
  userdataauth_->StartAuthSession(
      *start_auth_session_req_,
      auth_session_reply_future
          .GetCallback<const user_data_auth::StartAuthSessionReply&>());
  EXPECT_EQ(auth_session_reply_future.Get().error(),
            user_data_auth::CRYPTOHOME_ERROR_UNUSABLE_VAULT);
  std::optional<base::UnguessableToken> auth_session_id =
      AuthSession::GetTokenFromSerializedString(
          auth_session_reply_future.Get().auth_session_id());
  EXPECT_TRUE(auth_session_id.has_value());
  InUseAuthSession auth_session =
      userdataauth_->auth_session_manager_->FindAuthSession(
          auth_session_id.value());
  EXPECT_TRUE(auth_session.AuthSessionStatus().ok());
}

TEST_F(UserDataAuthExTest, InvalidateAuthSession) {
  // Setup.
  PrepareArguments();
  start_auth_session_req_->mutable_account_id()->set_account_id(
      "foo@example.com");
  TestFuture<user_data_auth::StartAuthSessionReply> auth_session_reply_future;
  userdataauth_->StartAuthSession(
      *start_auth_session_req_,
      auth_session_reply_future
          .GetCallback<const user_data_auth::StartAuthSessionReply&>());
  EXPECT_EQ(auth_session_reply_future.Get().error(),
            user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  std::optional<base::UnguessableToken> auth_session_id =
      AuthSession::GetTokenFromSerializedString(
          auth_session_reply_future.Get().auth_session_id());
  EXPECT_TRUE(auth_session_id.has_value());
  InUseAuthSession auth_session =
      userdataauth_->auth_session_manager_->FindAuthSession(
          auth_session_id.value());
  EXPECT_TRUE(auth_session.AuthSessionStatus().ok());

  // Test.
  user_data_auth::InvalidateAuthSessionRequest inv_auth_session_req;
  inv_auth_session_req.set_auth_session_id(
      auth_session_reply_future.Get().auth_session_id());

  // Invalidate the AuthSession immediately.
  TestFuture<user_data_auth::InvalidateAuthSessionReply> reply_future;
  userdataauth_->InvalidateAuthSession(
      inv_auth_session_req,
      reply_future
          .GetCallback<const user_data_auth::InvalidateAuthSessionReply&>());
  EXPECT_EQ(reply_future.Get().error(),
            user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  auth_session = userdataauth_->auth_session_manager_->FindAuthSession(
      auth_session_id.value());
  EXPECT_FALSE(auth_session.AuthSessionStatus().ok());
}

TEST_F(UserDataAuthExTest, ExtendAuthSession) {
  // Setup.
  PrepareArguments();

  start_auth_session_req_->mutable_account_id()->set_account_id(
      "foo@example.com");
  TestFuture<user_data_auth::StartAuthSessionReply> auth_session_reply_future;
  userdataauth_->StartAuthSession(
      *start_auth_session_req_,
      auth_session_reply_future
          .GetCallback<const user_data_auth::StartAuthSessionReply&>());
  EXPECT_EQ(auth_session_reply_future.Get().error(),
            user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  std::optional<base::UnguessableToken> auth_session_id =
      AuthSession::GetTokenFromSerializedString(
          auth_session_reply_future.Get().auth_session_id());
  EXPECT_TRUE(auth_session_id.has_value());

  // Get the session into an authenticated state by treating it as if we just
  // freshly created the user.
  {
    InUseAuthSession auth_session =
        userdataauth_->auth_session_manager_->FindAuthSession(
            auth_session_id.value());
    ASSERT_THAT(auth_session.AuthSessionStatus(), IsOk());
    EXPECT_THAT(auth_session->OnUserCreated(), IsOk());
  }

  // Test.
  user_data_auth::ExtendAuthSessionRequest ext_auth_session_req;
  ext_auth_session_req.set_auth_session_id(
      auth_session_reply_future.Get().auth_session_id());
  ext_auth_session_req.set_extension_duration(kAuthSessionExtensionDuration);

  // Extend the AuthSession.
  TestFuture<user_data_auth::ExtendAuthSessionReply> reply_future;
  userdataauth_->ExtendAuthSession(
      ext_auth_session_req,
      reply_future
          .GetCallback<const user_data_auth::ExtendAuthSessionReply&>());
  EXPECT_EQ(reply_future.Get().error(),
            user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  EXPECT_TRUE(reply_future.Get().has_seconds_left());
  EXPECT_GT(reply_future.Get().seconds_left(), kAuthSessionExtensionDuration);

  // Verify that timer has changed, within a resaonsable degree of error.
  InUseAuthSession auth_session =
      userdataauth_->auth_session_manager_->FindAuthSession(
          auth_session_id.value());
  auto requested_delay = auth_session->GetRemainingTime();
  auto time_difference =
      (kAuthSessionTimeout + kAuthSessionExtension) - requested_delay;
  EXPECT_LT(time_difference, base::Seconds(1));
}

TEST_F(UserDataAuthExTest, ExtendUnAuthenticatedAuthSessionFail) {
  // Setup.
  PrepareArguments();

  start_auth_session_req_->mutable_account_id()->set_account_id(
      "foo@example.com");
  TestFuture<user_data_auth::StartAuthSessionReply> auth_session_reply_future;
  userdataauth_->StartAuthSession(
      *start_auth_session_req_,
      auth_session_reply_future
          .GetCallback<const user_data_auth::StartAuthSessionReply&>());
  EXPECT_EQ(auth_session_reply_future.Get().error(),
            user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  std::optional<base::UnguessableToken> auth_session_id =
      AuthSession::GetTokenFromSerializedString(
          auth_session_reply_future.Get().auth_session_id());
  EXPECT_TRUE(auth_session_id.has_value());

  {
    InUseAuthSession auth_session =
        userdataauth_->auth_session_manager_->FindAuthSession(
            auth_session_id.value());
    ASSERT_TRUE(auth_session.AuthSessionStatus().ok());
  }

  // Test.
  user_data_auth::ExtendAuthSessionRequest ext_auth_session_req;
  ext_auth_session_req.set_auth_session_id(
      auth_session_reply_future.Get().auth_session_id());
  ext_auth_session_req.set_extension_duration(kAuthSessionExtensionDuration);

  // Extend the AuthSession.
  TestFuture<user_data_auth::ExtendAuthSessionReply> reply_future;
  userdataauth_->ExtendAuthSession(
      ext_auth_session_req,
      reply_future
          .GetCallback<const user_data_auth::ExtendAuthSessionReply&>());
  EXPECT_EQ(reply_future.Get().error(),
            user_data_auth::CRYPTOHOME_ERROR_INVALID_ARGUMENT);
  EXPECT_FALSE(reply_future.Get().has_seconds_left());
}

TEST_F(UserDataAuthExTest, CheckTimeoutTimerSetAfterAuthentication) {
  // Setup.
  PrepareArguments();

  start_auth_session_req_->mutable_account_id()->set_account_id(
      "foo@example.com");
  TestFuture<user_data_auth::StartAuthSessionReply> auth_session_reply_future;
  userdataauth_->StartAuthSession(
      *start_auth_session_req_,
      auth_session_reply_future
          .GetCallback<const user_data_auth::StartAuthSessionReply&>());
  EXPECT_EQ(auth_session_reply_future.Get().error(),
            user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  std::optional<base::UnguessableToken> auth_session_id =
      AuthSession::GetTokenFromSerializedString(
          auth_session_reply_future.Get().auth_session_id());
  EXPECT_TRUE(auth_session_id.has_value());

  InUseAuthSession auth_session =
      userdataauth_->auth_session_manager_->FindAuthSession(
          auth_session_id.value());
  ASSERT_THAT(auth_session.AuthSessionStatus(), IsOk());

  // Timer is not set before authentication.
  EXPECT_TRUE(auth_session->GetRemainingTime().is_max());

  // Extension only happens for authenticated auth session.
  EXPECT_THAT(auth_session->OnUserCreated(), IsOk());

  // Test timer is correctly set after authentication.
  EXPECT_FALSE(auth_session->GetRemainingTime().is_max());
}

TEST_F(UserDataAuthExTest, StartAuthSessionReplyCheck) {
  PrepareArguments();
  // Setup
  start_auth_session_req_->mutable_account_id()->set_account_id(
      "foo@example.com");

  KeyData key_data;
  key_data.set_label(kFakeLabel);
  key_data.set_type(KeyData::KEY_TYPE_PASSWORD);
  KeyLabelMap keyLabelData = {{kFakeLabel, key_data}};

  EXPECT_CALL(keyset_management_, UserExists(_)).WillRepeatedly(Return(true));
  std::vector<int> vk_indicies = {0};
  EXPECT_CALL(keyset_management_, GetVaultKeysets(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(vk_indicies), Return(true)));
  EXPECT_CALL(keyset_management_, LoadVaultKeysetForUser(_, 0))
      .WillOnce([key_data](const ObfuscatedUsername&, int) {
        auto vk = std::make_unique<VaultKeyset>();
        vk->SetFlags(SerializedVaultKeyset::TPM_WRAPPED |
                     SerializedVaultKeyset::PCR_BOUND);
        vk->SetKeyData(key_data);
        vk->SetTPMKey(SecureBlob("fake tpm key"));
        vk->SetExtendedTPMKey(SecureBlob("fake extended tpm key"));
        return vk;
      });

  TestFuture<user_data_auth::StartAuthSessionReply>
      start_auth_session_reply_future;
  userdataauth_->StartAuthSession(
      *start_auth_session_req_,
      start_auth_session_reply_future
          .GetCallback<const user_data_auth::StartAuthSessionReply&>());
  const user_data_auth::StartAuthSessionReply& start_auth_session_reply =
      start_auth_session_reply_future.Get();

  EXPECT_THAT(start_auth_session_reply.auth_factors().size(), 1);
  EXPECT_THAT(start_auth_session_reply.auth_factors().at(0).label(),
              kFakeLabel);
  EXPECT_THAT(start_auth_session_reply.auth_factors().at(0).type(),
              user_data_auth::AUTH_FACTOR_TYPE_PASSWORD);

  EXPECT_THAT(
      start_auth_session_reply.configured_auth_factors_with_status().size(), 1);
  EXPECT_THAT(start_auth_session_reply.configured_auth_factors_with_status()
                  .at(0)
                  .auth_factor()
                  .label(),
              kFakeLabel);
  EXPECT_THAT(start_auth_session_reply.configured_auth_factors_with_status()
                  .at(0)
                  .auth_factor()
                  .type(),
              user_data_auth::AUTH_FACTOR_TYPE_PASSWORD);
  EXPECT_THAT(start_auth_session_reply.configured_auth_factors_with_status()
                  .at(0)
                  .available_for_intents(),
              UnorderedElementsAre(user_data_auth::AUTH_INTENT_VERIFY_ONLY,
                                   user_data_auth::AUTH_INTENT_DECRYPT,
                                   user_data_auth::AUTH_INTENT_WEBAUTHN));
}

TEST_F(UserDataAuthExTest, StartAuthSessionVerifyOnlyFactors) {
  PrepareArguments();
  SetupMount("foo@example.com");
  // Setup
  start_auth_session_req_->mutable_account_id()->set_account_id(
      "foo@example.com");
  start_auth_session_req_->set_intent(user_data_auth::AUTH_INTENT_VERIFY_ONLY);

  KeyData key_data;
  key_data.set_label(kFakeLabel);
  key_data.set_type(KeyData::KEY_TYPE_PASSWORD);

  // Add persistent auth factors.
  EXPECT_CALL(keyset_management_, UserExists(_)).WillRepeatedly(Return(true));
  std::vector<int> vk_indicies = {0};
  EXPECT_CALL(keyset_management_, GetVaultKeysets(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(vk_indicies), Return(true)));
  EXPECT_CALL(keyset_management_, LoadVaultKeysetForUser(_, 0))
      .WillOnce([key_data](const ObfuscatedUsername&, int) {
        auto vk = std::make_unique<VaultKeyset>();
        vk->SetFlags(SerializedVaultKeyset::TPM_WRAPPED |
                     SerializedVaultKeyset::PCR_BOUND);
        vk->SetKeyData(key_data);
        vk->SetTPMKey(SecureBlob("fake tpm key"));
        vk->SetExtendedTPMKey(SecureBlob("fake extended tpm key"));
        return vk;
      });
  // Add a verifier as well.
  session_->AddCredentialVerifier(std::make_unique<MockCredentialVerifier>(
      AuthFactorType::kPassword, kFakeLabel,
      AuthFactorMetadata{.metadata = auth_factor::PasswordMetadata()}));

  TestFuture<user_data_auth::StartAuthSessionReply>
      start_auth_session_reply_future;
  userdataauth_->StartAuthSession(
      *start_auth_session_req_,
      start_auth_session_reply_future
          .GetCallback<const user_data_auth::StartAuthSessionReply&>());
  const user_data_auth::StartAuthSessionReply& start_auth_session_reply =
      start_auth_session_reply_future.Get();

  EXPECT_EQ(start_auth_session_reply.error(),
            user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  ASSERT_THAT(start_auth_session_reply.auth_factors().size(), 1);
  // We should only find one factor, not two. There's a persistent factor and a
  // verifier but they have the same label.
  EXPECT_THAT(start_auth_session_reply.auth_factors().at(0).label(),
              kFakeLabel);
  EXPECT_THAT(start_auth_session_reply.auth_factors().at(0).type(),
              user_data_auth::AUTH_FACTOR_TYPE_PASSWORD);
  EXPECT_THAT(
      start_auth_session_reply.configured_auth_factors_with_status().size(), 1);
  EXPECT_THAT(start_auth_session_reply.configured_auth_factors_with_status()
                  .at(0)
                  .auth_factor()
                  .label(),
              kFakeLabel);
  EXPECT_THAT(start_auth_session_reply.configured_auth_factors_with_status()
                  .at(0)
                  .auth_factor()
                  .type(),
              user_data_auth::AUTH_FACTOR_TYPE_PASSWORD);
  EXPECT_THAT(start_auth_session_reply.configured_auth_factors_with_status()
                  .at(0)
                  .available_for_intents(),
              UnorderedElementsAre(user_data_auth::AUTH_INTENT_VERIFY_ONLY,
                                   user_data_auth::AUTH_INTENT_DECRYPT,
                                   user_data_auth::AUTH_INTENT_WEBAUTHN));
}

TEST_F(UserDataAuthExTest, StartAuthSessionEphemeralFactors) {
  PrepareArguments();
  SetupMount("foo@example.com");
  // Setup
  start_auth_session_req_->mutable_account_id()->set_account_id(
      "foo@example.com");
  start_auth_session_req_->set_intent(user_data_auth::AUTH_INTENT_VERIFY_ONLY);
  start_auth_session_req_->set_flags(
      user_data_auth::AUTH_SESSION_FLAGS_EPHEMERAL_USER);

  EXPECT_CALL(keyset_management_, UserExists(_)).WillRepeatedly(Return(false));
  session_->AddCredentialVerifier(std::make_unique<MockCredentialVerifier>(
      AuthFactorType::kPassword, "password-verifier-label",
      AuthFactorMetadata{.metadata = auth_factor::PasswordMetadata()}));

  TestFuture<user_data_auth::StartAuthSessionReply>
      start_auth_session_reply_future;
  userdataauth_->StartAuthSession(
      *start_auth_session_req_,
      start_auth_session_reply_future
          .GetCallback<const user_data_auth::StartAuthSessionReply&>());
  const user_data_auth::StartAuthSessionReply& start_auth_session_reply =
      start_auth_session_reply_future.Get();

  EXPECT_EQ(start_auth_session_reply.error(),
            user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  ASSERT_THAT(start_auth_session_reply.auth_factors().size(), 1);
  EXPECT_THAT(start_auth_session_reply.auth_factors().at(0).label(),
              "password-verifier-label");
  EXPECT_THAT(start_auth_session_reply.auth_factors().at(0).type(),
              user_data_auth::AUTH_FACTOR_TYPE_PASSWORD);

  EXPECT_THAT(
      start_auth_session_reply.configured_auth_factors_with_status().size(), 1);
  EXPECT_THAT(start_auth_session_reply.configured_auth_factors_with_status()
                  .at(0)
                  .auth_factor()
                  .label(),
              "password-verifier-label");
  EXPECT_THAT(start_auth_session_reply.configured_auth_factors_with_status()
                  .at(0)
                  .auth_factor()
                  .type(),
              user_data_auth::AUTH_FACTOR_TYPE_PASSWORD);
  EXPECT_THAT(start_auth_session_reply.configured_auth_factors_with_status()
                  .at(0)
                  .available_for_intents(),
              UnorderedElementsAre(user_data_auth::AUTH_INTENT_VERIFY_ONLY));
}

TEST_F(UserDataAuthExTest, ListAuthFactorsUserDoesNotExist) {
  EXPECT_CALL(keyset_management_, UserExists(_)).WillOnce(Return(false));

  user_data_auth::ListAuthFactorsRequest list_request;
  list_request.mutable_account_id()->set_account_id("foo@example.com");
  TestFuture<user_data_auth::ListAuthFactorsReply> list_reply_future;
  userdataauth_->ListAuthFactors(
      list_request,
      list_reply_future
          .GetCallback<const user_data_auth::ListAuthFactorsReply&>());

  EXPECT_EQ(list_reply_future.Get().error(),
            user_data_auth::CRYPTOHOME_ERROR_INVALID_ARGUMENT);
}

TEST_F(UserDataAuthExTest, ListAuthFactorsUserIsPersistentButHasNoStorage) {
  SetupMount("foo@example.com");
  EXPECT_CALL(*session_, IsEphemeral()).WillRepeatedly(Return(false));

  user_data_auth::ListAuthFactorsRequest list_request;
  list_request.mutable_account_id()->set_account_id("foo@example.com");
  TestFuture<user_data_auth::ListAuthFactorsReply> list_reply_future;
  userdataauth_->ListAuthFactors(
      list_request,
      list_reply_future
          .GetCallback<const user_data_auth::ListAuthFactorsReply&>());
  const user_data_auth::ListAuthFactorsReply& list_reply =
      list_reply_future.Get();

  EXPECT_EQ(list_reply.error(), user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  EXPECT_THAT(list_reply.configured_auth_factors_with_status(), IsEmpty());
  EXPECT_THAT(
      list_reply.supported_auth_factors(),
      UnorderedElementsAre(user_data_auth::AUTH_FACTOR_TYPE_PASSWORD,
                           user_data_auth::AUTH_FACTOR_TYPE_CRYPTOHOME_RECOVERY,
                           user_data_auth::AUTH_FACTOR_TYPE_KIOSK,
                           user_data_auth::AUTH_FACTOR_TYPE_SMART_CARD));

  std::vector<user_data_auth::AuthFactorType> types_with_intents;
  for (const auto& intents_for_type : list_reply.auth_intents_for_types()) {
    types_with_intents.push_back(intents_for_type.type());
    EXPECT_THAT(intents_for_type.current(),
                UnorderedElementsAre(user_data_auth::AUTH_INTENT_DECRYPT,
                                     user_data_auth::AUTH_INTENT_VERIFY_ONLY,
                                     user_data_auth::AUTH_INTENT_WEBAUTHN));
  }
  EXPECT_THAT(
      types_with_intents,
      UnorderedElementsAre(user_data_auth::AUTH_FACTOR_TYPE_PASSWORD,
                           user_data_auth::AUTH_FACTOR_TYPE_CRYPTOHOME_RECOVERY,
                           user_data_auth::AUTH_FACTOR_TYPE_KIOSK,
                           user_data_auth::AUTH_FACTOR_TYPE_SMART_CARD));
}

TEST_F(UserDataAuthExTest, ListAuthFactorsUserIsEphemeralWithoutVerifier) {
  EXPECT_CALL(keyset_management_, UserExists(_)).WillOnce(Return(false));
  // Add a mount (and user session) for the ephemeral user.
  SetupMount("foo@example.com");
  EXPECT_CALL(*session_, IsEphemeral()).WillRepeatedly(Return(true));

  user_data_auth::ListAuthFactorsRequest list_request;
  list_request.mutable_account_id()->set_account_id("foo@example.com");
  TestFuture<user_data_auth::ListAuthFactorsReply> list_reply_future;
  userdataauth_->ListAuthFactors(
      list_request,
      list_reply_future
          .GetCallback<const user_data_auth::ListAuthFactorsReply&>());
  const user_data_auth::ListAuthFactorsReply& list_reply =
      list_reply_future.Get();

  EXPECT_EQ(list_reply.error(), user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  EXPECT_THAT(list_reply.configured_auth_factors_with_status(), IsEmpty());
  EXPECT_THAT(list_reply.supported_auth_factors(),
              UnorderedElementsAre(
                  user_data_auth::AUTH_FACTOR_TYPE_PASSWORD,
                  user_data_auth::AUTH_FACTOR_TYPE_SMART_CARD,
                  user_data_auth::AUTH_FACTOR_TYPE_LEGACY_FINGERPRINT));

  std::vector<user_data_auth::AuthFactorType> types_with_intents;
  for (const auto& intents_for_type : list_reply.auth_intents_for_types()) {
    types_with_intents.push_back(intents_for_type.type());
    if (intents_for_type.type() ==
        user_data_auth::AUTH_FACTOR_TYPE_LEGACY_FINGERPRINT) {
      EXPECT_THAT(intents_for_type.current(),
                  UnorderedElementsAre(user_data_auth::AUTH_INTENT_VERIFY_ONLY,
                                       user_data_auth::AUTH_INTENT_WEBAUTHN));
    } else {
      EXPECT_THAT(
          intents_for_type.current(),
          UnorderedElementsAre(user_data_auth::AUTH_INTENT_VERIFY_ONLY));
    }
  }
  EXPECT_THAT(types_with_intents,
              UnorderedElementsAre(
                  user_data_auth::AUTH_FACTOR_TYPE_PASSWORD,
                  user_data_auth::AUTH_FACTOR_TYPE_SMART_CARD,
                  user_data_auth::AUTH_FACTOR_TYPE_LEGACY_FINGERPRINT));
}

TEST_F(UserDataAuthExTest, ListAuthFactorsUserIsEphemeralWithVerifier) {
  EXPECT_CALL(keyset_management_, UserExists(_)).WillOnce(Return(false));
  // Add a mount (and user session) for the ephemeral user.
  SetupMount("foo@example.com");
  EXPECT_CALL(*session_, IsEphemeral()).WillRepeatedly(Return(true));
  session_->AddCredentialVerifier(std::make_unique<MockCredentialVerifier>(
      AuthFactorType::kPassword, "password-label",
      AuthFactorMetadata{.metadata = auth_factor::PasswordMetadata()}));

  user_data_auth::ListAuthFactorsRequest list_request;
  list_request.mutable_account_id()->set_account_id("foo@example.com");
  TestFuture<user_data_auth::ListAuthFactorsReply> list_reply_future;
  userdataauth_->ListAuthFactors(
      list_request,
      list_reply_future
          .GetCallback<const user_data_auth::ListAuthFactorsReply&>());
  const user_data_auth::ListAuthFactorsReply& list_reply =
      list_reply_future.Get();

  EXPECT_EQ(list_reply.error(), user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  ASSERT_EQ(list_reply.configured_auth_factors_with_status_size(), 1);
  EXPECT_EQ(
      list_reply.configured_auth_factors_with_status(0).auth_factor().type(),
      user_data_auth::AUTH_FACTOR_TYPE_PASSWORD);
  EXPECT_EQ(
      list_reply.configured_auth_factors_with_status(0).auth_factor().label(),
      "password-label");
  EXPECT_TRUE(list_reply.configured_auth_factors_with_status(0)
                  .auth_factor()
                  .has_password_metadata());
  EXPECT_TRUE(list_reply.configured_auth_factors_with_status(0)
                  .auth_factor()
                  .has_common_metadata());
  EXPECT_EQ(list_reply.configured_auth_factors_with_status(0)
                .auth_factor()
                .common_metadata()
                .lockout_policy(),
            user_data_auth::LOCKOUT_POLICY_NONE);
  EXPECT_THAT(list_reply.supported_auth_factors(),
              UnorderedElementsAre(
                  user_data_auth::AUTH_FACTOR_TYPE_PASSWORD,
                  user_data_auth::AUTH_FACTOR_TYPE_SMART_CARD,
                  user_data_auth::AUTH_FACTOR_TYPE_LEGACY_FINGERPRINT));

  std::vector<user_data_auth::AuthFactorType> types_with_intents;
  for (const auto& intents_for_type : list_reply.auth_intents_for_types()) {
    types_with_intents.push_back(intents_for_type.type());
    if (intents_for_type.type() ==
        user_data_auth::AUTH_FACTOR_TYPE_LEGACY_FINGERPRINT) {
      EXPECT_THAT(intents_for_type.current(),
                  UnorderedElementsAre(user_data_auth::AUTH_INTENT_VERIFY_ONLY,
                                       user_data_auth::AUTH_INTENT_WEBAUTHN));
    } else {
      EXPECT_THAT(
          intents_for_type.current(),
          UnorderedElementsAre(user_data_auth::AUTH_INTENT_VERIFY_ONLY));
    }
  }
  EXPECT_THAT(types_with_intents,
              UnorderedElementsAre(
                  user_data_auth::AUTH_FACTOR_TYPE_PASSWORD,
                  user_data_auth::AUTH_FACTOR_TYPE_SMART_CARD,
                  user_data_auth::AUTH_FACTOR_TYPE_LEGACY_FINGERPRINT));
}

TEST_F(UserDataAuthExTest, ListAuthFactorsUserExistsWithoutPinweaver) {
  EXPECT_CALL(keyset_management_, UserExists(_)).WillOnce(Return(true));

  user_data_auth::ListAuthFactorsRequest list_request;
  list_request.mutable_account_id()->set_account_id("foo@example.com");
  TestFuture<user_data_auth::ListAuthFactorsReply> list_reply_future;
  userdataauth_->ListAuthFactors(
      list_request,
      list_reply_future
          .GetCallback<const user_data_auth::ListAuthFactorsReply&>());
  const user_data_auth::ListAuthFactorsReply& list_reply =
      list_reply_future.Get();

  EXPECT_EQ(list_reply.error(), user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  EXPECT_THAT(list_reply.configured_auth_factors_with_status(), IsEmpty());
  EXPECT_THAT(
      list_reply.supported_auth_factors(),
      UnorderedElementsAre(user_data_auth::AUTH_FACTOR_TYPE_PASSWORD,
                           user_data_auth::AUTH_FACTOR_TYPE_CRYPTOHOME_RECOVERY,
                           user_data_auth::AUTH_FACTOR_TYPE_KIOSK,
                           user_data_auth::AUTH_FACTOR_TYPE_SMART_CARD));
}

TEST_F(UserDataAuthExTest, ListAuthFactorsUserExistsWithPinweaver) {
  EXPECT_CALL(keyset_management_, UserExists(_)).WillOnce(Return(true));
  EXPECT_CALL(hwsec_, IsPinWeaverEnabled()).WillRepeatedly(ReturnValue(true));

  user_data_auth::ListAuthFactorsRequest list_request;
  list_request.mutable_account_id()->set_account_id("foo@example.com");
  TestFuture<user_data_auth::ListAuthFactorsReply> list_reply_future;
  userdataauth_->ListAuthFactors(
      list_request,
      list_reply_future
          .GetCallback<const user_data_auth::ListAuthFactorsReply&>());
  const user_data_auth::ListAuthFactorsReply& list_reply =
      list_reply_future.Get();

  EXPECT_EQ(list_reply.error(), user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  EXPECT_THAT(list_reply.configured_auth_factors_with_status(), IsEmpty());
  EXPECT_THAT(
      list_reply.supported_auth_factors(),
      UnorderedElementsAre(user_data_auth::AUTH_FACTOR_TYPE_PASSWORD,
                           user_data_auth::AUTH_FACTOR_TYPE_PIN,
                           user_data_auth::AUTH_FACTOR_TYPE_CRYPTOHOME_RECOVERY,
                           user_data_auth::AUTH_FACTOR_TYPE_KIOSK,
                           user_data_auth::AUTH_FACTOR_TYPE_SMART_CARD));
}

TEST_F(UserDataAuthExTest,
       ListAuthFactorsUserExistsWithNoFactorsButUssEnabled) {
  SetUserSecretStashExperimentForTesting(true);
  EXPECT_CALL(keyset_management_, UserExists(_)).WillOnce(Return(true));
  EXPECT_CALL(hwsec_, IsPinWeaverEnabled()).WillRepeatedly(ReturnValue(true));

  user_data_auth::ListAuthFactorsRequest list_request;
  list_request.mutable_account_id()->set_account_id("foo@example.com");
  TestFuture<user_data_auth::ListAuthFactorsReply> list_reply_future;
  userdataauth_->ListAuthFactors(
      list_request,
      list_reply_future
          .GetCallback<const user_data_auth::ListAuthFactorsReply&>());
  const user_data_auth::ListAuthFactorsReply& list_reply =
      list_reply_future.Get();

  EXPECT_EQ(list_reply.error(), user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  EXPECT_THAT(list_reply.configured_auth_factors_with_status(), IsEmpty());
  EXPECT_THAT(
      list_reply.supported_auth_factors(),
      UnorderedElementsAre(user_data_auth::AUTH_FACTOR_TYPE_PASSWORD,
                           user_data_auth::AUTH_FACTOR_TYPE_PIN,
                           user_data_auth::AUTH_FACTOR_TYPE_CRYPTOHOME_RECOVERY,
                           user_data_auth::AUTH_FACTOR_TYPE_KIOSK,
                           user_data_auth::AUTH_FACTOR_TYPE_SMART_CARD));
  SetUserSecretStashExperimentForTesting(std::nullopt);
}

TEST_F(UserDataAuthExTest, ListAuthFactorsUserExistsWithFactorsFromVks) {
  const Username kUser("foo@example.com");
  const ObfuscatedUsername kObfuscatedUser = SanitizeUserName(kUser);
  EXPECT_CALL(keyset_management_, UserExists(_)).WillOnce(Return(true));

  // Set up mocks for a few of VKs. We deliberately have the second not work to
  // test that the listing correctly skips it.
  std::vector<int> vk_indicies = {0, 1, 2};
  EXPECT_CALL(keyset_management_, GetVaultKeysets(kObfuscatedUser, _))
      .WillOnce(DoAll(SetArgPointee<1>(vk_indicies), Return(true)));
  EXPECT_CALL(keyset_management_, LoadVaultKeysetForUser(kObfuscatedUser, 0))
      .WillOnce([](const ObfuscatedUsername&, int) {
        auto vk = std::make_unique<VaultKeyset>();
        vk->SetFlags(SerializedVaultKeyset::TPM_WRAPPED |
                     SerializedVaultKeyset::PCR_BOUND);
        KeyData key_data;
        key_data.set_type(KeyData::KEY_TYPE_PASSWORD);
        key_data.set_label("password-label");
        vk->SetKeyData(key_data);
        vk->SetTPMKey(SecureBlob("fake tpm key"));
        vk->SetExtendedTPMKey(SecureBlob("fake extended tpm key"));
        return vk;
      });
  EXPECT_CALL(keyset_management_, LoadVaultKeysetForUser(kObfuscatedUser, 1))
      .WillOnce(Return(ByMove(nullptr)));
  EXPECT_CALL(keyset_management_, LoadVaultKeysetForUser(kObfuscatedUser, 2))
      .WillOnce([](const ObfuscatedUsername&, int) {
        auto vk = std::make_unique<VaultKeyset>();
        vk->SetFlags(SerializedVaultKeyset::SCRYPT_WRAPPED);
        KeyData key_data;
        key_data.set_type(KeyData::KEY_TYPE_PASSWORD);
        key_data.set_label("password-scrypt-label");
        vk->SetKeyData(key_data);
        const brillo::Blob kScryptPlaintext =
            brillo::BlobFromString("plaintext");
        const auto blob_to_encrypt = brillo::SecureBlob(brillo::CombineBlobs(
            {kScryptPlaintext, hwsec_foundation::Sha1(kScryptPlaintext)}));
        brillo::SecureBlob wrapped_keyset;
        brillo::SecureBlob wrapped_chaps_key;
        brillo::SecureBlob wrapped_reset_seed;
        brillo::SecureBlob derived_key = {
            0x67, 0xeb, 0xcd, 0x84, 0x49, 0x5e, 0xa2, 0xf3, 0xb1, 0xe6, 0xe7,
            0x5b, 0x13, 0xb9, 0x16, 0x2f, 0x5a, 0x39, 0xc8, 0xfe, 0x6a, 0x60,
            0xd4, 0x7a, 0xd8, 0x2b, 0x44, 0xc4, 0x45, 0x53, 0x1a, 0x85, 0x4a,
            0x97, 0x9f, 0x2d, 0x06, 0xf5, 0xd0, 0xd3, 0xa6, 0xe7, 0xac, 0x9b,
            0x02, 0xaf, 0x3c, 0x08, 0xce, 0x43, 0x46, 0x32, 0x6d, 0xd7, 0x2b,
            0xe9, 0xdf, 0x8b, 0x38, 0x0e, 0x60, 0x3d, 0x64, 0x12};
        brillo::SecureBlob scrypt_salt = brillo::SecureBlob("salt");
        brillo::SecureBlob chaps_salt = brillo::SecureBlob("chaps_salt");
        brillo::SecureBlob reset_seed_salt =
            brillo::SecureBlob("reset_seed_salt");
        scrypt_salt.resize(hwsec_foundation::kLibScryptSaltSize);
        chaps_salt.resize(hwsec_foundation::kLibScryptSaltSize);
        reset_seed_salt.resize(hwsec_foundation::kLibScryptSaltSize);
        if (hwsec_foundation::LibScryptCompat::Encrypt(
                derived_key, scrypt_salt, blob_to_encrypt,
                hwsec_foundation::kDefaultScryptParams, &wrapped_keyset)) {
          vk->SetWrappedKeyset(wrapped_keyset);
        }
        if (hwsec_foundation::LibScryptCompat::Encrypt(
                derived_key, chaps_salt, blob_to_encrypt,
                hwsec_foundation::kDefaultScryptParams, &wrapped_chaps_key)) {
          vk->SetWrappedChapsKey(wrapped_chaps_key);
        }
        if (hwsec_foundation::LibScryptCompat::Encrypt(
                derived_key, reset_seed_salt, blob_to_encrypt,
                hwsec_foundation::kDefaultScryptParams, &wrapped_reset_seed)) {
          vk->SetWrappedResetSeed(wrapped_reset_seed);
        }
        return vk;
      });

  user_data_auth::ListAuthFactorsRequest list_request;
  list_request.mutable_account_id()->set_account_id(*kUser);
  TestFuture<user_data_auth::ListAuthFactorsReply> list_reply_future;
  userdataauth_->ListAuthFactors(
      list_request,
      list_reply_future
          .GetCallback<const user_data_auth::ListAuthFactorsReply&>());
  const user_data_auth::ListAuthFactorsReply& list_reply =
      list_reply_future.Get();

  EXPECT_EQ(list_reply.error(), user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  ASSERT_EQ(list_reply.configured_auth_factors_with_status_size(), 2);
  EXPECT_EQ(
      list_reply.configured_auth_factors_with_status(0).auth_factor().label(),
      "password-label");
  EXPECT_TRUE(list_reply.configured_auth_factors_with_status(0)
                  .auth_factor()
                  .has_password_metadata());
  EXPECT_TRUE(list_reply.configured_auth_factors_with_status(0)
                  .auth_factor()
                  .has_common_metadata());
  EXPECT_EQ(list_reply.configured_auth_factors_with_status(0)
                .auth_factor()
                .common_metadata()
                .lockout_policy(),
            user_data_auth::LOCKOUT_POLICY_NONE);
  EXPECT_EQ(
      list_reply.configured_auth_factors_with_status(1).auth_factor().label(),
      "password-scrypt-label");
  EXPECT_TRUE(list_reply.configured_auth_factors_with_status(1)
                  .auth_factor()
                  .has_password_metadata());
  EXPECT_TRUE(list_reply.configured_auth_factors_with_status(1)
                  .auth_factor()
                  .has_common_metadata());
  EXPECT_EQ(list_reply.configured_auth_factors_with_status(1)
                .auth_factor()
                .common_metadata()
                .lockout_policy(),
            user_data_auth::LOCKOUT_POLICY_NONE);
  EXPECT_THAT(
      list_reply.supported_auth_factors(),
      UnorderedElementsAre(user_data_auth::AUTH_FACTOR_TYPE_PASSWORD,
                           user_data_auth::AUTH_FACTOR_TYPE_CRYPTOHOME_RECOVERY,
                           user_data_auth::AUTH_FACTOR_TYPE_SMART_CARD));
}

TEST_F(UserDataAuthExTest, ListAuthFactorsWithFactorsFromUss) {
  const Username kUser("foo@example.com");
  const ObfuscatedUsername kObfuscatedUser = SanitizeUserName(kUser);
  AuthFactorManager manager(&platform_);
  userdataauth_->set_auth_factor_manager_for_testing(&manager);
  SetUserSecretStashExperimentForTesting(false);
  EXPECT_CALL(hwsec_, IsPinWeaverEnabled()).WillRepeatedly(ReturnValue(true));

  EXPECT_CALL(keyset_management_, UserExists(_)).WillRepeatedly(Return(true));

  // Set up standard list auth factor parameters, we'll be calling this a few
  // times during the test.
  user_data_auth::ListAuthFactorsRequest list_request;
  list_request.mutable_account_id()->set_account_id(*kUser);
  TestFuture<user_data_auth::ListAuthFactorsReply> list_reply_future_1;

  // List all the auth factors, there should be none at the start.
  userdataauth_->ListAuthFactors(
      list_request,
      list_reply_future_1
          .GetCallback<const user_data_auth::ListAuthFactorsReply&>());
  EXPECT_EQ(list_reply_future_1.Get().error(),
            user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  EXPECT_THAT(list_reply_future_1.Get().configured_auth_factors_with_status(),
              IsEmpty());
  EXPECT_THAT(
      list_reply_future_1.Get().supported_auth_factors(),
      UnorderedElementsAre(user_data_auth::AUTH_FACTOR_TYPE_PASSWORD,
                           user_data_auth::AUTH_FACTOR_TYPE_PIN,
                           user_data_auth::AUTH_FACTOR_TYPE_KIOSK,
                           user_data_auth::AUTH_FACTOR_TYPE_SMART_CARD));

  // Add uss auth factors, we should be able to list them.
  auto password_factor = std::make_unique<AuthFactor>(
      AuthFactorType::kPassword, "password-label",
      AuthFactorMetadata{.metadata = auth_factor::PasswordMetadata()},
      AuthBlockState{
          .state = TpmBoundToPcrAuthBlockState{
              .scrypt_derived = false,
              .salt = SecureBlob("fake salt"),
              .tpm_key = SecureBlob("fake tpm key"),
              .extended_tpm_key = SecureBlob("fake extended tpm key"),
              .tpm_public_key_hash = SecureBlob("fake tpm public key hash"),
          }});
  ASSERT_THAT(manager.SaveAuthFactor(kObfuscatedUser, *password_factor),
              IsOk());
  auto pin_factor = std::make_unique<AuthFactor>(
      AuthFactorType::kPin, "pin-label",
      AuthFactorMetadata{.metadata = auth_factor::PinMetadata()},
      AuthBlockState{.state = PinWeaverAuthBlockState{
                         .le_label = 0xbaadf00d,
                         .salt = SecureBlob("fake salt"),
                         .chaps_iv = SecureBlob("fake chaps IV"),
                         .fek_iv = SecureBlob("fake file encryption IV"),
                         .reset_salt = SecureBlob("more fake salt"),
                     }});
  ASSERT_THAT(manager.SaveAuthFactor(kObfuscatedUser, *pin_factor), IsOk());

  // ListAuthFactors() load the factors according to the USS experiment status.
  SetUserSecretStashExperimentForTesting(true);
  TestFuture<user_data_auth::ListAuthFactorsReply> list_reply_future_2;
  userdataauth_->ListAuthFactors(
      list_request,
      list_reply_future_2
          .GetCallback<const user_data_auth::ListAuthFactorsReply&>());
  user_data_auth::ListAuthFactorsReply list_reply_2 =
      list_reply_future_2.Take();
  EXPECT_EQ(list_reply_2.error(), user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  std::sort(
      list_reply_2.mutable_configured_auth_factors_with_status()
          ->pointer_begin(),
      list_reply_2.mutable_configured_auth_factors_with_status()->pointer_end(),
      [](const user_data_auth::AuthFactorWithStatus* lhs,
         const user_data_auth::AuthFactorWithStatus* rhs) {
        return lhs->auth_factor().label() < rhs->auth_factor().label();
      });
  ASSERT_EQ(list_reply_2.configured_auth_factors_with_status_size(), 2);
  EXPECT_EQ(
      list_reply_2.configured_auth_factors_with_status(0).auth_factor().label(),
      "password-label");
  EXPECT_TRUE(list_reply_2.configured_auth_factors_with_status(0)
                  .auth_factor()
                  .has_password_metadata());
  EXPECT_TRUE(list_reply_2.configured_auth_factors_with_status(0)
                  .auth_factor()
                  .has_common_metadata());
  EXPECT_EQ(list_reply_2.configured_auth_factors_with_status(0)
                .auth_factor()
                .common_metadata()
                .lockout_policy(),
            user_data_auth::LOCKOUT_POLICY_NONE);
  EXPECT_EQ(
      list_reply_2.configured_auth_factors_with_status(1).auth_factor().label(),
      "pin-label");
  EXPECT_TRUE(list_reply_2.configured_auth_factors_with_status(1)
                  .auth_factor()
                  .has_pin_metadata());
  EXPECT_TRUE(list_reply_2.configured_auth_factors_with_status(1)
                  .auth_factor()
                  .has_common_metadata());
  EXPECT_EQ(list_reply_2.configured_auth_factors_with_status(1)
                .auth_factor()
                .common_metadata()
                .lockout_policy(),
            user_data_auth::LOCKOUT_POLICY_ATTEMPT_LIMITED);
  EXPECT_THAT(
      list_reply_2.supported_auth_factors(),
      UnorderedElementsAre(user_data_auth::AUTH_FACTOR_TYPE_PASSWORD,
                           user_data_auth::AUTH_FACTOR_TYPE_PIN,
                           user_data_auth::AUTH_FACTOR_TYPE_CRYPTOHOME_RECOVERY,
                           user_data_auth::AUTH_FACTOR_TYPE_SMART_CARD));

  // Remove an auth factor, we should still be able to list the remaining one.
  TestFuture<CryptohomeStatus> remove_result;
  manager.RemoveAuthFactor(kObfuscatedUser, *pin_factor, &auth_block_utility_,
                           remove_result.GetCallback());
  EXPECT_THAT(remove_result.Take(), IsOk());
  TestFuture<user_data_auth::ListAuthFactorsReply> list_reply_future_3;
  userdataauth_->ListAuthFactors(
      list_request,
      list_reply_future_3
          .GetCallback<const user_data_auth::ListAuthFactorsReply&>());
  const user_data_auth::ListAuthFactorsReply& list_reply_3 =
      list_reply_future_3.Get();
  EXPECT_EQ(list_reply_3.error(), user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  ASSERT_EQ(list_reply_3.configured_auth_factors_with_status_size(), 1);
  EXPECT_EQ(
      list_reply_3.configured_auth_factors_with_status(0).auth_factor().label(),
      "password-label");
  EXPECT_TRUE(list_reply_3.configured_auth_factors_with_status(0)
                  .auth_factor()
                  .has_password_metadata());
  EXPECT_TRUE(list_reply_3.configured_auth_factors_with_status(0)
                  .auth_factor()
                  .has_common_metadata());
  EXPECT_EQ(list_reply_3.configured_auth_factors_with_status(0)
                .auth_factor()
                .common_metadata()
                .lockout_policy(),
            user_data_auth::LOCKOUT_POLICY_NONE);
  EXPECT_THAT(
      list_reply_3.supported_auth_factors(),
      UnorderedElementsAre(user_data_auth::AUTH_FACTOR_TYPE_PASSWORD,
                           user_data_auth::AUTH_FACTOR_TYPE_PIN,
                           user_data_auth::AUTH_FACTOR_TYPE_CRYPTOHOME_RECOVERY,
                           user_data_auth::AUTH_FACTOR_TYPE_SMART_CARD));
  ResetUserSecretStashExperimentForTesting();
}

TEST_F(UserDataAuthExTest, StartAuthSessionPinLockedLegacy) {
  // Setup.
  const Username kUser("foo@example.com");
  const ObfuscatedUsername kObfuscatedUser = SanitizeUserName(kUser);
  AuthFactorManager manager(&platform_);
  auto mock_le_manager = std::make_unique<MockLECredentialManager>();
  MockLECredentialManager* mock_le_manager_ptr = mock_le_manager.get();

  SetUserSecretStashExperimentForTesting(true);
  userdataauth_->set_auth_factor_manager_for_testing(&manager);
  crypto_.set_le_manager_for_testing(std::move(mock_le_manager));

  EXPECT_CALL(hwsec_, IsPinWeaverEnabled()).WillRepeatedly(ReturnValue(true));
  EXPECT_CALL(keyset_management_, UserExists(_)).WillRepeatedly(Return(false));

  // Set up standard start authsession parameters, we'll be calling this a few
  // times during the test.
  user_data_auth::StartAuthSessionRequest start_request;
  start_request.mutable_account_id()->set_account_id(*kUser);
  TestFuture<user_data_auth::StartAuthSessionReply> start_reply_future_1;

  // List all the auth factors, there should be none at the start.
  userdataauth_->StartAuthSession(
      start_request,
      start_reply_future_1
          .GetCallback<const user_data_auth::StartAuthSessionReply&>());
  EXPECT_EQ(start_reply_future_1.Get().error(),
            user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  EXPECT_THAT(start_reply_future_1.Get().configured_auth_factors_with_status(),
              IsEmpty());
  EXPECT_THAT(start_reply_future_1.Get().user_exists(), false);

  // Now that we are starting to save AuthFactors, let's assume user exists.
  EXPECT_CALL(keyset_management_, UserExists(_)).WillRepeatedly(Return(true));
  // Add uss auth factors, we should be able to list them.
  auto password_factor = std::make_unique<AuthFactor>(
      AuthFactorType::kPassword, "password-label",
      AuthFactorMetadata{.metadata = auth_factor::PasswordMetadata()},
      AuthBlockState{
          .state = TpmBoundToPcrAuthBlockState{
              .scrypt_derived = false,
              .salt = SecureBlob("fake salt"),
              .tpm_key = SecureBlob("fake tpm key"),
              .extended_tpm_key = SecureBlob("fake extended tpm key"),
              .tpm_public_key_hash = SecureBlob("fake tpm public key hash"),
          }});
  ASSERT_THAT(manager.SaveAuthFactor(kObfuscatedUser, *password_factor),
              IsOk());
  auto pin_factor = std::make_unique<AuthFactor>(
      AuthFactorType::kPin, "pin-label",
      AuthFactorMetadata{.metadata = auth_factor::PinMetadata()},
      AuthBlockState{.state = PinWeaverAuthBlockState{
                         .le_label = 0xbaadf00d,
                         .salt = SecureBlob("fake salt"),
                         .chaps_iv = SecureBlob("fake chaps IV"),
                         .fek_iv = SecureBlob("fake file encryption IV"),
                         .reset_salt = SecureBlob("more fake salt"),
                     }});
  ASSERT_THAT(manager.SaveAuthFactor(kObfuscatedUser, *pin_factor), IsOk());

  EXPECT_CALL(*mock_le_manager_ptr, GetDelayInSeconds).WillRepeatedly([](auto) {
    return UINT32_MAX;
  });

  TestFuture<user_data_auth::StartAuthSessionReply> start_reply_future_2;
  userdataauth_->StartAuthSession(
      start_request,
      start_reply_future_2
          .GetCallback<const user_data_auth::StartAuthSessionReply&>());
  user_data_auth::StartAuthSessionReply start_reply =
      start_reply_future_2.Take();
  EXPECT_EQ(start_reply.error(), user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  std::sort(
      start_reply.mutable_configured_auth_factors_with_status()
          ->pointer_begin(),
      start_reply.mutable_configured_auth_factors_with_status()->pointer_end(),
      [](const user_data_auth::AuthFactorWithStatus* lhs,
         const user_data_auth::AuthFactorWithStatus* rhs) {
        return lhs->auth_factor().label() < rhs->auth_factor().label();
      });
  ASSERT_EQ(start_reply.configured_auth_factors_with_status_size(), 2);
  EXPECT_EQ(
      start_reply.configured_auth_factors_with_status(0).auth_factor().label(),
      "password-label");
  EXPECT_TRUE(start_reply.configured_auth_factors_with_status(0)
                  .auth_factor()
                  .has_password_metadata());
  EXPECT_TRUE(start_reply.configured_auth_factors_with_status(0)
                  .auth_factor()
                  .has_common_metadata());
  EXPECT_EQ(start_reply.configured_auth_factors_with_status(0)
                .auth_factor()
                .common_metadata()
                .lockout_policy(),
            user_data_auth::LOCKOUT_POLICY_NONE);
  EXPECT_EQ(
      start_reply.configured_auth_factors_with_status(1).auth_factor().label(),
      "pin-label");
  EXPECT_TRUE(start_reply.configured_auth_factors_with_status(1)
                  .auth_factor()
                  .has_pin_metadata());
  EXPECT_TRUE(start_reply.configured_auth_factors_with_status(1)
                  .auth_factor()
                  .has_common_metadata());
  EXPECT_EQ(start_reply.configured_auth_factors_with_status(1)
                .auth_factor()
                .common_metadata()
                .lockout_policy(),
            user_data_auth::LOCKOUT_POLICY_ATTEMPT_LIMITED);
  EXPECT_TRUE(
      start_reply.configured_auth_factors_with_status(1).has_status_info());
  EXPECT_EQ(start_reply.configured_auth_factors_with_status(1)
                .status_info()
                .time_available_in(),
            std::numeric_limits<uint64_t>::max());
  EXPECT_TRUE(start_reply.user_exists());
  ResetUserSecretStashExperimentForTesting();
}

TEST_F(UserDataAuthExTest, StartAuthSessionPinLockedModern) {
  // Setup.
  const Username kUser("foo@example.com");
  const ObfuscatedUsername kObfuscatedUser = SanitizeUserName(kUser);
  AuthFactorManager manager(&platform_);
  auto mock_le_manager = std::make_unique<MockLECredentialManager>();
  MockLECredentialManager* mock_le_manager_ptr = mock_le_manager.get();

  SetUserSecretStashExperimentForTesting(true);
  userdataauth_->set_auth_factor_manager_for_testing(&manager);
  crypto_.set_le_manager_for_testing(std::move(mock_le_manager));
  features_.SetDefaultForFeature(Features::kModernPin, true);

  EXPECT_CALL(hwsec_, IsPinWeaverEnabled()).WillRepeatedly(ReturnValue(true));
  EXPECT_CALL(keyset_management_, UserExists(_)).WillRepeatedly(Return(false));

  // Set up standard start authsession parameters, we'll be calling this a few
  // times during the test.
  user_data_auth::StartAuthSessionRequest start_request;
  start_request.mutable_account_id()->set_account_id(*kUser);
  TestFuture<user_data_auth::StartAuthSessionReply> start_reply_future_1;

  // List all the auth factors, there should be none at the start.
  userdataauth_->StartAuthSession(
      start_request,
      start_reply_future_1
          .GetCallback<const user_data_auth::StartAuthSessionReply&>());
  EXPECT_EQ(start_reply_future_1.Get().error(),
            user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  EXPECT_THAT(start_reply_future_1.Get().configured_auth_factors_with_status(),
              IsEmpty());
  EXPECT_THAT(start_reply_future_1.Get().user_exists(), false);

  // Now that we are starting to save AuthFactors, let's assume user exists.
  EXPECT_CALL(keyset_management_, UserExists(_)).WillRepeatedly(Return(true));
  // Add uss auth factors, we should be able to list them.

  // Add uss auth factors, we should be able to list them.
  auto password_factor = std::make_unique<AuthFactor>(
      AuthFactorType::kPassword, "password-label",
      AuthFactorMetadata{.metadata = auth_factor::PasswordMetadata()},
      AuthBlockState{
          .state = TpmBoundToPcrAuthBlockState{
              .scrypt_derived = false,
              .salt = SecureBlob("fake salt"),
              .tpm_key = SecureBlob("fake tpm key"),
              .extended_tpm_key = SecureBlob("fake extended tpm key"),
              .tpm_public_key_hash = SecureBlob("fake tpm public key hash"),
          }});
  ASSERT_THAT(manager.SaveAuthFactor(kObfuscatedUser, *password_factor),
              IsOk());
  auto pin_factor = std::make_unique<AuthFactor>(
      AuthFactorType::kPin, "pin-label",
      AuthFactorMetadata{
          .common =
              auth_factor::CommonMetadata{
                  .lockout_policy = auth_factor::LockoutPolicy::TIME_LIMITED},
          .metadata = auth_factor::PinMetadata()},
      AuthBlockState{.state = PinWeaverAuthBlockState{
                         .le_label = 0xbaadf00d,
                         .salt = SecureBlob("fake salt"),
                         .chaps_iv = SecureBlob("fake chaps IV"),
                         .fek_iv = SecureBlob("fake file encryption IV"),
                         .reset_salt = SecureBlob("more fake salt"),
                     }});
  ASSERT_THAT(manager.SaveAuthFactor(kObfuscatedUser, *pin_factor), IsOk());

  EXPECT_CALL(*mock_le_manager_ptr, GetDelayInSeconds).WillRepeatedly([](auto) {
    return 30;
  });

  TestFuture<user_data_auth::StartAuthSessionReply> start_reply_future_2;
  userdataauth_->StartAuthSession(
      start_request,
      start_reply_future_2
          .GetCallback<const user_data_auth::StartAuthSessionReply&>());
  user_data_auth::StartAuthSessionReply start_reply =
      start_reply_future_2.Take();
  EXPECT_EQ(start_reply.error(), user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  std::sort(
      start_reply.mutable_configured_auth_factors_with_status()
          ->pointer_begin(),
      start_reply.mutable_configured_auth_factors_with_status()->pointer_end(),
      [](const user_data_auth::AuthFactorWithStatus* lhs,
         const user_data_auth::AuthFactorWithStatus* rhs) {
        return lhs->auth_factor().label() < rhs->auth_factor().label();
      });
  ASSERT_EQ(start_reply.configured_auth_factors_with_status_size(), 2);
  EXPECT_EQ(
      start_reply.configured_auth_factors_with_status(0).auth_factor().label(),
      "password-label");
  EXPECT_TRUE(start_reply.configured_auth_factors_with_status(0)
                  .auth_factor()
                  .has_password_metadata());
  EXPECT_TRUE(start_reply.configured_auth_factors_with_status(0)
                  .auth_factor()
                  .has_common_metadata());
  EXPECT_EQ(start_reply.configured_auth_factors_with_status(0)
                .auth_factor()
                .common_metadata()
                .lockout_policy(),
            user_data_auth::LOCKOUT_POLICY_NONE);
  EXPECT_EQ(
      start_reply.configured_auth_factors_with_status(1).auth_factor().label(),
      "pin-label");
  EXPECT_TRUE(start_reply.configured_auth_factors_with_status(1)
                  .auth_factor()
                  .has_pin_metadata());
  EXPECT_TRUE(start_reply.configured_auth_factors_with_status(1)
                  .auth_factor()
                  .has_common_metadata());
  EXPECT_EQ(start_reply.configured_auth_factors_with_status(1)
                .auth_factor()
                .common_metadata()
                .lockout_policy(),
            user_data_auth::LOCKOUT_POLICY_TIME_LIMITED);
  EXPECT_TRUE(
      start_reply.configured_auth_factors_with_status(1).has_status_info());
  EXPECT_EQ(start_reply.configured_auth_factors_with_status(1)
                .status_info()
                .time_available_in(),
            30000);
  ResetUserSecretStashExperimentForTesting();
}

TEST_F(UserDataAuthExTest, ListAuthFactorsWithFactorsFromUssPinLockedLegacy) {
  // Setup.
  const Username kUser("foo@example.com");
  const ObfuscatedUsername kObfuscatedUser = SanitizeUserName(kUser);
  AuthFactorManager manager(&platform_);
  auto mock_le_manager = std::make_unique<MockLECredentialManager>();
  MockLECredentialManager* mock_le_manager_ptr = mock_le_manager.get();

  SetUserSecretStashExperimentForTesting(true);
  userdataauth_->set_auth_factor_manager_for_testing(&manager);
  crypto_.set_le_manager_for_testing(std::move(mock_le_manager));

  EXPECT_CALL(hwsec_, IsPinWeaverEnabled()).WillRepeatedly(ReturnValue(true));
  EXPECT_CALL(keyset_management_, UserExists(_)).WillRepeatedly(Return(true));

  // Set up standard list auth factor parameters, we'll be calling this a few
  // times during the test.
  user_data_auth::ListAuthFactorsRequest list_request;
  list_request.mutable_account_id()->set_account_id(*kUser);
  TestFuture<user_data_auth::ListAuthFactorsReply> list_reply_future_1;

  // List all the auth factors, there should be none at the start.
  userdataauth_->ListAuthFactors(
      list_request,
      list_reply_future_1
          .GetCallback<const user_data_auth::ListAuthFactorsReply&>());
  EXPECT_EQ(list_reply_future_1.Get().error(),
            user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  EXPECT_THAT(list_reply_future_1.Get().configured_auth_factors_with_status(),
              IsEmpty());
  EXPECT_THAT(list_reply_future_1.Get().supported_auth_factors(),
              UnorderedElementsAre(
                  user_data_auth::AUTH_FACTOR_TYPE_PASSWORD,
                  user_data_auth::AUTH_FACTOR_TYPE_PIN,
                  user_data_auth::AUTH_FACTOR_TYPE_KIOSK,
                  user_data_auth::AUTH_FACTOR_TYPE_SMART_CARD,
                  user_data_auth::AUTH_FACTOR_TYPE_CRYPTOHOME_RECOVERY));

  // Add uss auth factors, we should be able to list them.
  auto password_factor = std::make_unique<AuthFactor>(
      AuthFactorType::kPassword, "password-label",
      AuthFactorMetadata{.metadata = auth_factor::PasswordMetadata()},
      AuthBlockState{
          .state = TpmBoundToPcrAuthBlockState{
              .scrypt_derived = false,
              .salt = SecureBlob("fake salt"),
              .tpm_key = SecureBlob("fake tpm key"),
              .extended_tpm_key = SecureBlob("fake extended tpm key"),
              .tpm_public_key_hash = SecureBlob("fake tpm public key hash"),
          }});
  ASSERT_THAT(manager.SaveAuthFactor(kObfuscatedUser, *password_factor),
              IsOk());
  auto pin_factor = std::make_unique<AuthFactor>(
      AuthFactorType::kPin, "pin-label",
      AuthFactorMetadata{.metadata = auth_factor::PinMetadata()},
      AuthBlockState{.state = PinWeaverAuthBlockState{
                         .le_label = 0xbaadf00d,
                         .salt = SecureBlob("fake salt"),
                         .chaps_iv = SecureBlob("fake chaps IV"),
                         .fek_iv = SecureBlob("fake file encryption IV"),
                         .reset_salt = SecureBlob("more fake salt"),
                     }});
  ASSERT_THAT(manager.SaveAuthFactor(kObfuscatedUser, *pin_factor), IsOk());

  EXPECT_CALL(*mock_le_manager_ptr, GetDelayInSeconds).WillRepeatedly([](auto) {
    return UINT32_MAX;
  });

  // ListAuthFactors() load the factors according to the USS experiment status.
  SetUserSecretStashExperimentForTesting(true);
  TestFuture<user_data_auth::ListAuthFactorsReply> list_reply_future_2;
  userdataauth_->ListAuthFactors(
      list_request,
      list_reply_future_2
          .GetCallback<const user_data_auth::ListAuthFactorsReply&>());
  user_data_auth::ListAuthFactorsReply list_reply_2 =
      list_reply_future_2.Take();
  EXPECT_EQ(list_reply_2.error(), user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  std::sort(
      list_reply_2.mutable_configured_auth_factors_with_status()
          ->pointer_begin(),
      list_reply_2.mutable_configured_auth_factors_with_status()->pointer_end(),
      [](const user_data_auth::AuthFactorWithStatus* lhs,
         const user_data_auth::AuthFactorWithStatus* rhs) {
        return lhs->auth_factor().label() < rhs->auth_factor().label();
      });
  ASSERT_EQ(list_reply_2.configured_auth_factors_with_status_size(), 2);
  EXPECT_EQ(
      list_reply_2.configured_auth_factors_with_status(0).auth_factor().label(),
      "password-label");
  EXPECT_TRUE(list_reply_2.configured_auth_factors_with_status(0)
                  .auth_factor()
                  .has_password_metadata());
  EXPECT_TRUE(list_reply_2.configured_auth_factors_with_status(0)
                  .auth_factor()
                  .has_common_metadata());
  EXPECT_EQ(list_reply_2.configured_auth_factors_with_status(0)
                .auth_factor()
                .common_metadata()
                .lockout_policy(),
            user_data_auth::LOCKOUT_POLICY_NONE);
  EXPECT_EQ(
      list_reply_2.configured_auth_factors_with_status(1).auth_factor().label(),
      "pin-label");
  EXPECT_TRUE(list_reply_2.configured_auth_factors_with_status(1)
                  .auth_factor()
                  .has_pin_metadata());
  EXPECT_TRUE(list_reply_2.configured_auth_factors_with_status(1)
                  .auth_factor()
                  .has_common_metadata());
  EXPECT_EQ(list_reply_2.configured_auth_factors_with_status(1)
                .auth_factor()
                .common_metadata()
                .lockout_policy(),
            user_data_auth::LOCKOUT_POLICY_ATTEMPT_LIMITED);
  EXPECT_TRUE(
      list_reply_2.configured_auth_factors_with_status(1).has_status_info());
  EXPECT_EQ(list_reply_2.configured_auth_factors_with_status(1)
                .status_info()
                .time_available_in(),
            std::numeric_limits<uint64_t>::max());
  EXPECT_THAT(
      list_reply_2.supported_auth_factors(),
      UnorderedElementsAre(user_data_auth::AUTH_FACTOR_TYPE_PASSWORD,
                           user_data_auth::AUTH_FACTOR_TYPE_PIN,
                           user_data_auth::AUTH_FACTOR_TYPE_CRYPTOHOME_RECOVERY,
                           user_data_auth::AUTH_FACTOR_TYPE_SMART_CARD));

  ResetUserSecretStashExperimentForTesting();
}

TEST_F(UserDataAuthExTest, ListAuthFactorsWithFactorsFromUssPinLockedModern) {
  // Setup.
  const Username kUser("foo@example.com");
  const ObfuscatedUsername kObfuscatedUser = SanitizeUserName(kUser);
  auto mock_le_manager = std::make_unique<MockLECredentialManager>();
  MockLECredentialManager* mock_le_manager_ptr = mock_le_manager.get();
  AuthFactorManager manager(&platform_);

  SetUserSecretStashExperimentForTesting(true);
  userdataauth_->set_auth_factor_manager_for_testing(&manager);
  crypto_.set_le_manager_for_testing(std::move(mock_le_manager));
  features_.SetDefaultForFeature(Features::kModernPin, true);

  EXPECT_CALL(hwsec_, IsPinWeaverEnabled()).WillRepeatedly(ReturnValue(true));
  EXPECT_CALL(keyset_management_, UserExists(_)).WillRepeatedly(Return(true));

  // Set up standard list auth factor parameters, we'll be calling this a few
  // times during the test.
  user_data_auth::ListAuthFactorsRequest list_request;
  list_request.mutable_account_id()->set_account_id(*kUser);
  TestFuture<user_data_auth::ListAuthFactorsReply> list_reply_future_1;

  // List all the auth factors, there should be none at the start.
  userdataauth_->ListAuthFactors(
      list_request,
      list_reply_future_1
          .GetCallback<const user_data_auth::ListAuthFactorsReply&>());
  EXPECT_EQ(list_reply_future_1.Get().error(),
            user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  EXPECT_THAT(list_reply_future_1.Get().configured_auth_factors_with_status(),
              IsEmpty());
  EXPECT_THAT(list_reply_future_1.Get().supported_auth_factors(),
              UnorderedElementsAre(
                  user_data_auth::AUTH_FACTOR_TYPE_PASSWORD,
                  user_data_auth::AUTH_FACTOR_TYPE_PIN,
                  user_data_auth::AUTH_FACTOR_TYPE_KIOSK,
                  user_data_auth::AUTH_FACTOR_TYPE_SMART_CARD,
                  user_data_auth::AUTH_FACTOR_TYPE_CRYPTOHOME_RECOVERY));

  // Add uss auth factors, we should be able to list them.
  auto password_factor = std::make_unique<AuthFactor>(
      AuthFactorType::kPassword, "password-label",
      AuthFactorMetadata{.metadata = auth_factor::PasswordMetadata()},
      AuthBlockState{
          .state = TpmBoundToPcrAuthBlockState{
              .scrypt_derived = false,
              .salt = SecureBlob("fake salt"),
              .tpm_key = SecureBlob("fake tpm key"),
              .extended_tpm_key = SecureBlob("fake extended tpm key"),
              .tpm_public_key_hash = SecureBlob("fake tpm public key hash"),
          }});
  ASSERT_THAT(manager.SaveAuthFactor(kObfuscatedUser, *password_factor),
              IsOk());
  auto pin_factor = std::make_unique<AuthFactor>(
      AuthFactorType::kPin, "pin-label",
      AuthFactorMetadata{
          .common =
              auth_factor::CommonMetadata{
                  .lockout_policy = auth_factor::LockoutPolicy::TIME_LIMITED},
          .metadata = auth_factor::PinMetadata()},
      AuthBlockState{.state = PinWeaverAuthBlockState{
                         .le_label = 0xbaadf00d,
                         .salt = SecureBlob("fake salt"),
                         .chaps_iv = SecureBlob("fake chaps IV"),
                         .fek_iv = SecureBlob("fake file encryption IV"),
                         .reset_salt = SecureBlob("more fake salt"),
                     }});
  ASSERT_THAT(manager.SaveAuthFactor(kObfuscatedUser, *pin_factor), IsOk());

  EXPECT_CALL(*mock_le_manager_ptr, GetDelayInSeconds).WillRepeatedly([](auto) {
    return 30;
  });

  // ListAuthFactors() load the factors according to the USS experiment status.
  SetUserSecretStashExperimentForTesting(true);
  TestFuture<user_data_auth::ListAuthFactorsReply> list_reply_future_2;
  userdataauth_->ListAuthFactors(
      list_request,
      list_reply_future_2
          .GetCallback<const user_data_auth::ListAuthFactorsReply&>());
  user_data_auth::ListAuthFactorsReply list_reply_2 =
      list_reply_future_2.Take();
  EXPECT_EQ(list_reply_2.error(), user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  std::sort(
      list_reply_2.mutable_configured_auth_factors_with_status()
          ->pointer_begin(),
      list_reply_2.mutable_configured_auth_factors_with_status()->pointer_end(),
      [](const user_data_auth::AuthFactorWithStatus* lhs,
         const user_data_auth::AuthFactorWithStatus* rhs) {
        return lhs->auth_factor().label() < rhs->auth_factor().label();
      });
  ASSERT_EQ(list_reply_2.configured_auth_factors_with_status_size(), 2);
  EXPECT_EQ(
      list_reply_2.configured_auth_factors_with_status(0).auth_factor().label(),
      "password-label");
  EXPECT_TRUE(list_reply_2.configured_auth_factors_with_status(0)
                  .auth_factor()
                  .has_password_metadata());
  EXPECT_TRUE(list_reply_2.configured_auth_factors_with_status(0)
                  .auth_factor()
                  .has_common_metadata());
  EXPECT_EQ(list_reply_2.configured_auth_factors_with_status(0)
                .auth_factor()
                .common_metadata()
                .lockout_policy(),
            user_data_auth::LOCKOUT_POLICY_NONE);
  EXPECT_EQ(
      list_reply_2.configured_auth_factors_with_status(1).auth_factor().label(),
      "pin-label");
  EXPECT_TRUE(list_reply_2.configured_auth_factors_with_status(1)
                  .auth_factor()
                  .has_pin_metadata());
  EXPECT_TRUE(list_reply_2.configured_auth_factors_with_status(1)
                  .auth_factor()
                  .has_common_metadata());
  EXPECT_EQ(list_reply_2.configured_auth_factors_with_status(1)
                .auth_factor()
                .common_metadata()
                .lockout_policy(),
            user_data_auth::LOCKOUT_POLICY_TIME_LIMITED);
  EXPECT_TRUE(
      list_reply_2.configured_auth_factors_with_status(1).has_status_info());
  EXPECT_EQ(list_reply_2.configured_auth_factors_with_status(1)
                .status_info()
                .time_available_in(),
            30000);
  EXPECT_THAT(
      list_reply_2.supported_auth_factors(),
      UnorderedElementsAre(user_data_auth::AUTH_FACTOR_TYPE_PASSWORD,
                           user_data_auth::AUTH_FACTOR_TYPE_PIN,
                           user_data_auth::AUTH_FACTOR_TYPE_CRYPTOHOME_RECOVERY,
                           user_data_auth::AUTH_FACTOR_TYPE_SMART_CARD));

  ResetUserSecretStashExperimentForTesting();
}

TEST_F(UserDataAuthExTest, ListAuthFactorsWithFactorsFromUssAndVk) {
  const Username kUser("foo@example.com");
  const ObfuscatedUsername kObfuscatedUser = SanitizeUserName(kUser);
  AuthFactorManager manager(&platform_);
  userdataauth_->set_auth_factor_manager_for_testing(&manager);
  SetUserSecretStashExperimentForTesting(false);
  EXPECT_CALL(hwsec_, IsPinWeaverEnabled()).WillRepeatedly(ReturnValue(true));

  EXPECT_CALL(keyset_management_, UserExists(_)).WillRepeatedly(Return(true));

  // Set up standard list auth factor parameters, we'll be calling this a few
  // times during the test.
  user_data_auth::ListAuthFactorsRequest list_request;
  list_request.mutable_account_id()->set_account_id(*kUser);
  TestFuture<user_data_auth::ListAuthFactorsReply> list_reply_future_1;

  // List all the auth factors, there should be none at the start.
  userdataauth_->ListAuthFactors(
      list_request,
      list_reply_future_1
          .GetCallback<const user_data_auth::ListAuthFactorsReply&>());
  EXPECT_EQ(list_reply_future_1.Get().error(),
            user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  EXPECT_THAT(list_reply_future_1.Get().configured_auth_factors_with_status(),
              IsEmpty());
  EXPECT_THAT(
      list_reply_future_1.Get().supported_auth_factors(),
      UnorderedElementsAre(user_data_auth::AUTH_FACTOR_TYPE_PASSWORD,
                           user_data_auth::AUTH_FACTOR_TYPE_PIN,
                           user_data_auth::AUTH_FACTOR_TYPE_KIOSK,
                           user_data_auth::AUTH_FACTOR_TYPE_SMART_CARD));

  // Set up mocks for a VK.
  std::vector<int> vk_indice = {0};
  EXPECT_CALL(keyset_management_, GetVaultKeysets(kObfuscatedUser, _))
      .WillOnce(DoAll(SetArgPointee<1>(vk_indice), Return(true)));
  EXPECT_CALL(keyset_management_, LoadVaultKeysetForUser(kObfuscatedUser, 0))
      .WillOnce([](const ObfuscatedUsername&, int) {
        auto vk = std::make_unique<VaultKeyset>();
        vk->SetFlags(SerializedVaultKeyset::TPM_WRAPPED |
                     SerializedVaultKeyset::PCR_BOUND);
        KeyData key_data;
        key_data.set_type(KeyData::KEY_TYPE_PASSWORD);
        key_data.set_label("password-label");
        vk->SetKeyData(key_data);
        vk->SetTPMKey(SecureBlob("fake tpm key"));
        vk->SetExtendedTPMKey(SecureBlob("fake extended tpm key"));
        return vk;
      });
  // Add an AuthFactor backed by USS.
  auto pin_factor = std::make_unique<AuthFactor>(
      AuthFactorType::kPin, "pin-label",
      AuthFactorMetadata{.metadata = auth_factor::PinMetadata()},
      AuthBlockState{.state = PinWeaverAuthBlockState{
                         .le_label = 0xbaadf00d,
                         .salt = SecureBlob("fake salt"),
                         .chaps_iv = SecureBlob("fake chaps IV"),
                         .fek_iv = SecureBlob("fake file encryption IV"),
                         .reset_salt = SecureBlob("more fake salt"),
                     }});
  ASSERT_THAT(manager.SaveAuthFactor(kObfuscatedUser, *pin_factor), IsOk());

  // ListAuthFactors() load the factors according to the USS experiment status.
  SetUserSecretStashExperimentForTesting(true);
  TestFuture<user_data_auth::ListAuthFactorsReply> list_reply_future_2;
  userdataauth_->ListAuthFactors(
      list_request,
      list_reply_future_2
          .GetCallback<const user_data_auth::ListAuthFactorsReply&>());
  user_data_auth::ListAuthFactorsReply list_reply_2 =
      list_reply_future_2.Take();
  EXPECT_EQ(list_reply_2.error(), user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  std::sort(
      list_reply_2.mutable_configured_auth_factors_with_status()
          ->pointer_begin(),
      list_reply_2.mutable_configured_auth_factors_with_status()->pointer_end(),
      [](const user_data_auth::AuthFactorWithStatus* lhs,
         const user_data_auth::AuthFactorWithStatus* rhs) {
        return lhs->auth_factor().label() < rhs->auth_factor().label();
      });
  ASSERT_EQ(list_reply_2.configured_auth_factors_with_status_size(), 2);
  EXPECT_EQ(
      list_reply_2.configured_auth_factors_with_status(0).auth_factor().label(),
      "password-label");
  EXPECT_TRUE(list_reply_2.configured_auth_factors_with_status(0)
                  .auth_factor()
                  .has_password_metadata());
  EXPECT_TRUE(list_reply_2.configured_auth_factors_with_status(0)
                  .auth_factor()
                  .has_common_metadata());
  EXPECT_EQ(list_reply_2.configured_auth_factors_with_status(0)
                .auth_factor()
                .common_metadata()
                .lockout_policy(),
            user_data_auth::LOCKOUT_POLICY_NONE);
  EXPECT_EQ(
      list_reply_2.configured_auth_factors_with_status(1).auth_factor().label(),
      "pin-label");
  EXPECT_TRUE(list_reply_2.configured_auth_factors_with_status(1)
                  .auth_factor()
                  .has_pin_metadata());
  EXPECT_TRUE(list_reply_2.configured_auth_factors_with_status(1)
                  .auth_factor()
                  .has_common_metadata());
  EXPECT_EQ(list_reply_2.configured_auth_factors_with_status(1)
                .auth_factor()
                .common_metadata()
                .lockout_policy(),
            user_data_auth::LOCKOUT_POLICY_ATTEMPT_LIMITED);
  EXPECT_THAT(
      list_reply_2.supported_auth_factors(),
      UnorderedElementsAre(user_data_auth::AUTH_FACTOR_TYPE_PASSWORD,
                           user_data_auth::AUTH_FACTOR_TYPE_PIN,
                           user_data_auth::AUTH_FACTOR_TYPE_CRYPTOHOME_RECOVERY,
                           user_data_auth::AUTH_FACTOR_TYPE_SMART_CARD));
  ResetUserSecretStashExperimentForTesting();
}

TEST_F(UserDataAuthExTest, PrepareAuthFactorFingerprintSuccess) {
  // Setup.
  PrepareArguments();
  start_auth_session_req_->mutable_account_id()->set_account_id(
      "foo@example.com");
  TestFuture<user_data_auth::StartAuthSessionReply> auth_session_reply_future;
  userdataauth_->StartAuthSession(
      *start_auth_session_req_,
      auth_session_reply_future
          .GetCallback<const user_data_auth::StartAuthSessionReply&>());
  EXPECT_EQ(auth_session_reply_future.Get().error(),
            user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  const std::string auth_session_id =
      auth_session_reply_future.Get().auth_session_id();
  EXPECT_TRUE(
      AuthSession::GetTokenFromSerializedString(auth_session_id).has_value());

  // Prepare the request and set up the mock components.
  user_data_auth::PrepareAuthFactorRequest prepare_auth_factor_req;
  prepare_auth_factor_req.set_auth_session_id(auth_session_id);
  prepare_auth_factor_req.set_auth_factor_type(
      user_data_auth::AUTH_FACTOR_TYPE_FINGERPRINT);
  prepare_auth_factor_req.set_purpose(
      user_data_auth::PURPOSE_AUTHENTICATE_AUTH_FACTOR);
  EXPECT_CALL(*bio_processor_, StartAuthenticateSession(_, _))
      .WillOnce([](auto&&, auto&& callback) { std::move(callback).Run(true); });

  // Test.
  TestFuture<user_data_auth::PrepareAuthFactorReply>
      prepare_auth_factor_reply_future;
  userdataauth_->PrepareAuthFactor(
      prepare_auth_factor_req,
      prepare_auth_factor_reply_future
          .GetCallback<const user_data_auth::PrepareAuthFactorReply&>());

  // Verify.
  EXPECT_EQ(prepare_auth_factor_reply_future.Get().error(),
            user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
}

TEST_F(UserDataAuthExTest, PrepareAuthFactorFingerprintFailure) {
  // Setup.
  PrepareArguments();
  start_auth_session_req_->mutable_account_id()->set_account_id(
      "foo@example.com");
  TestFuture<user_data_auth::StartAuthSessionReply> auth_session_reply_future;
  userdataauth_->StartAuthSession(
      *start_auth_session_req_,
      auth_session_reply_future
          .GetCallback<const user_data_auth::StartAuthSessionReply&>());
  EXPECT_EQ(auth_session_reply_future.Get().error(),
            user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  const std::string auth_session_id =
      auth_session_reply_future.Get().auth_session_id();
  EXPECT_TRUE(
      AuthSession::GetTokenFromSerializedString(auth_session_id).has_value());

  // Prepare the request and set up the mock components.
  user_data_auth::PrepareAuthFactorRequest prepare_auth_factor_req;
  prepare_auth_factor_req.set_auth_session_id(auth_session_id);
  prepare_auth_factor_req.set_auth_factor_type(
      user_data_auth::AUTH_FACTOR_TYPE_FINGERPRINT);
  prepare_auth_factor_req.set_purpose(
      user_data_auth::PURPOSE_AUTHENTICATE_AUTH_FACTOR);
  EXPECT_CALL(*bio_processor_, StartAuthenticateSession(_, _))
      .WillOnce(
          [](auto&&, auto&& callback) { std::move(callback).Run(false); });

  // Test.
  TestFuture<user_data_auth::PrepareAuthFactorReply>
      prepare_auth_factor_reply_future;
  userdataauth_->PrepareAuthFactor(
      prepare_auth_factor_req,
      prepare_auth_factor_reply_future
          .GetCallback<const user_data_auth::PrepareAuthFactorReply&>());

  // Verify.
  EXPECT_EQ(prepare_auth_factor_reply_future.Get().error(),
            user_data_auth::CRYPTOHOME_ERROR_FINGERPRINT_ERROR_INTERNAL);
}

TEST_F(UserDataAuthExTest, PrepareAuthFactorNoAuthSessionIdFailure) {
  // Setup.
  PrepareArguments();
  // Prepare the request and set up the mock components.
  user_data_auth::PrepareAuthFactorRequest prepare_auth_factor_req;
  prepare_auth_factor_req.set_auth_factor_type(
      user_data_auth::AUTH_FACTOR_TYPE_FINGERPRINT);
  prepare_auth_factor_req.set_purpose(
      user_data_auth::PURPOSE_AUTHENTICATE_AUTH_FACTOR);

  // Test.
  TestFuture<user_data_auth::PrepareAuthFactorReply>
      prepare_auth_factor_reply_future;
  userdataauth_->PrepareAuthFactor(
      prepare_auth_factor_req,
      prepare_auth_factor_reply_future
          .GetCallback<const user_data_auth::PrepareAuthFactorReply&>());

  // Verify.
  EXPECT_EQ(prepare_auth_factor_reply_future.Get().error(),
            user_data_auth::CRYPTOHOME_INVALID_AUTH_SESSION_TOKEN);
}

TEST_F(UserDataAuthExTest, PrepareAuthFactorPasswordFailure) {
  // Setup.
  PrepareArguments();
  start_auth_session_req_->mutable_account_id()->set_account_id(
      "foo@example.com");
  TestFuture<user_data_auth::StartAuthSessionReply> auth_session_reply_future;
  userdataauth_->StartAuthSession(
      *start_auth_session_req_,
      auth_session_reply_future
          .GetCallback<const user_data_auth::StartAuthSessionReply&>());
  EXPECT_EQ(auth_session_reply_future.Get().error(),
            user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  const std::string auth_session_id =
      auth_session_reply_future.Get().auth_session_id();
  EXPECT_TRUE(
      AuthSession::GetTokenFromSerializedString(auth_session_id).has_value());

  // Prepare the request and set up the mock components.
  user_data_auth::PrepareAuthFactorRequest prepare_auth_factor_req;
  prepare_auth_factor_req.set_auth_session_id(auth_session_id);
  prepare_auth_factor_req.set_auth_factor_type(
      user_data_auth::AUTH_FACTOR_TYPE_PASSWORD);
  prepare_auth_factor_req.set_purpose(
      user_data_auth::PURPOSE_AUTHENTICATE_AUTH_FACTOR);

  // Test.
  TestFuture<user_data_auth::PrepareAuthFactorReply>
      prepare_auth_factor_reply_future;
  userdataauth_->PrepareAuthFactor(
      prepare_auth_factor_req,
      prepare_auth_factor_reply_future
          .GetCallback<const user_data_auth::PrepareAuthFactorReply&>());

  // Verify.
  EXPECT_EQ(prepare_auth_factor_reply_future.Get().error(),
            user_data_auth::CRYPTOHOME_ERROR_INVALID_ARGUMENT);
}

TEST_F(UserDataAuthExTest, TerminateAuthFactorFingerprintSuccess) {
  // Setup.
  PrepareArguments();
  start_auth_session_req_->mutable_account_id()->set_account_id(
      "foo@example.com");
  TestFuture<user_data_auth::StartAuthSessionReply> auth_session_reply_future;
  userdataauth_->StartAuthSession(
      *start_auth_session_req_,
      auth_session_reply_future
          .GetCallback<const user_data_auth::StartAuthSessionReply&>());
  EXPECT_EQ(auth_session_reply_future.Get().error(),
            user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  const std::string auth_session_id =
      auth_session_reply_future.Get().auth_session_id();
  EXPECT_TRUE(
      AuthSession::GetTokenFromSerializedString(auth_session_id).has_value());

  // Execute a successful PrepareAuthFactor with mocked response.
  user_data_auth::PrepareAuthFactorRequest prepare_auth_factor_req;
  prepare_auth_factor_req.set_auth_session_id(auth_session_id);
  prepare_auth_factor_req.set_auth_factor_type(
      user_data_auth::AUTH_FACTOR_TYPE_FINGERPRINT);
  prepare_auth_factor_req.set_purpose(
      user_data_auth::PURPOSE_AUTHENTICATE_AUTH_FACTOR);
  EXPECT_CALL(*bio_processor_, StartAuthenticateSession(_, _))
      .WillOnce([](auto&&, auto&& callback) { std::move(callback).Run(true); });
  TestFuture<user_data_auth::PrepareAuthFactorReply>
      prepare_auth_factor_reply_future;
  userdataauth_->PrepareAuthFactor(
      prepare_auth_factor_req,
      prepare_auth_factor_reply_future
          .GetCallback<const user_data_auth::PrepareAuthFactorReply&>());
  EXPECT_EQ(prepare_auth_factor_reply_future.Get().error(),
            user_data_auth::CRYPTOHOME_ERROR_NOT_SET);

  // Test.
  user_data_auth::TerminateAuthFactorRequest terminate_auth_factor_req;
  terminate_auth_factor_req.set_auth_session_id(auth_session_id);
  terminate_auth_factor_req.set_auth_factor_type(
      user_data_auth::AUTH_FACTOR_TYPE_FINGERPRINT);
  TestFuture<user_data_auth::TerminateAuthFactorReply>
      terminate_auth_factor_reply_future;
  userdataauth_->TerminateAuthFactor(
      terminate_auth_factor_req,
      terminate_auth_factor_reply_future
          .GetCallback<const user_data_auth::TerminateAuthFactorReply&>());

  // Verify.
  EXPECT_EQ(terminate_auth_factor_reply_future.Get().error(),
            user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
}

TEST_F(UserDataAuthExTest, TerminateAuthFactorInactiveFactorFailure) {
  // Setup.
  PrepareArguments();
  start_auth_session_req_->mutable_account_id()->set_account_id(
      "foo@example.com");
  TestFuture<user_data_auth::StartAuthSessionReply> auth_session_reply_future;
  userdataauth_->StartAuthSession(
      *start_auth_session_req_,
      auth_session_reply_future
          .GetCallback<const user_data_auth::StartAuthSessionReply&>());
  EXPECT_EQ(auth_session_reply_future.Get().error(),
            user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  const std::string auth_session_id =
      auth_session_reply_future.Get().auth_session_id();
  EXPECT_TRUE(
      AuthSession::GetTokenFromSerializedString(auth_session_id).has_value());

  // Test. TerminateAuthFactor fails when there is
  // no pending fingerprint auth factor to be terminated.
  user_data_auth::TerminateAuthFactorRequest terminate_auth_factor_req;
  terminate_auth_factor_req.set_auth_session_id(auth_session_id);
  terminate_auth_factor_req.set_auth_factor_type(
      user_data_auth::AUTH_FACTOR_TYPE_FINGERPRINT);
  TestFuture<user_data_auth::TerminateAuthFactorReply>
      terminate_auth_factor_reply_future;
  userdataauth_->TerminateAuthFactor(
      terminate_auth_factor_req,
      terminate_auth_factor_reply_future
          .GetCallback<const user_data_auth::TerminateAuthFactorReply&>());

  // Verify.
  EXPECT_EQ(terminate_auth_factor_reply_future.Get().error(),
            user_data_auth::CRYPTOHOME_ERROR_INVALID_ARGUMENT);
}

TEST_F(UserDataAuthExTest, TerminateAuthFactorBadTypeFailure) {
  // Setup.
  PrepareArguments();
  start_auth_session_req_->mutable_account_id()->set_account_id(
      "foo@example.com");
  TestFuture<user_data_auth::StartAuthSessionReply> auth_session_reply_future;
  userdataauth_->StartAuthSession(
      *start_auth_session_req_,
      auth_session_reply_future
          .GetCallback<const user_data_auth::StartAuthSessionReply&>());
  EXPECT_EQ(auth_session_reply_future.Get().error(),
            user_data_auth::CRYPTOHOME_ERROR_NOT_SET);
  const std::string auth_session_id =
      auth_session_reply_future.Get().auth_session_id();
  EXPECT_TRUE(
      AuthSession::GetTokenFromSerializedString(auth_session_id).has_value());

  // Test. TerminateAuthFactor fails when the auth factor type
  // does not support PrepareAuthFactor.
  user_data_auth::TerminateAuthFactorRequest terminate_auth_factor_req;
  terminate_auth_factor_req.set_auth_session_id(auth_session_id);
  terminate_auth_factor_req.set_auth_factor_type(
      user_data_auth::AUTH_FACTOR_TYPE_PASSWORD);
  TestFuture<user_data_auth::TerminateAuthFactorReply>
      terminate_auth_factor_reply_future;
  userdataauth_->TerminateAuthFactor(
      terminate_auth_factor_req,
      terminate_auth_factor_reply_future
          .GetCallback<const user_data_auth::TerminateAuthFactorReply&>());

  // Verify.
  EXPECT_EQ(terminate_auth_factor_reply_future.Get().error(),
            user_data_auth::CRYPTOHOME_ERROR_INVALID_ARGUMENT);
}

// ================ Tests requiring fully threaded environment ================

// Test fixture that implements fully threaded environment in UserDataAuth.
// Note that this does not initialize |userdataauth_|.
class UserDataAuthTestThreaded : public UserDataAuthTestBase {
 public:
  UserDataAuthTestThreaded() : origin_thread_("origin_thread") {}
  UserDataAuthTestThreaded(const UserDataAuthTestThreaded&) = delete;
  UserDataAuthTestThreaded& operator=(const UserDataAuthTestThreaded&) = delete;

  ~UserDataAuthTestThreaded() override = default;

  // Post a task to the origin thread, then wait for it to finish.
  void PostToOriginAndBlock(base::OnceClosure task) {
    base::WaitableEvent done(base::WaitableEvent::ResetPolicy::MANUAL,
                             base::WaitableEvent::InitialState::NOT_SIGNALED);

    origin_thread_.task_runner()->PostTask(
        FROM_HERE, base::BindOnce(
                       [](base::OnceClosure task, base::WaitableEvent* done) {
                         std::move(task).Run();
                         done->Signal();
                       },
                       std::move(task), base::Unretained(&done)));

    done.Wait();
  }

  void SetUp() override {
    origin_thread_.Start();

    PostToOriginAndBlock(base::BindOnce(
        &UserDataAuthTestThreaded::SetUpInOrigin, base::Unretained(this)));
  }

  void SetUpInOrigin() {
    // Create the |userdataauth_| object.
    userdataauth_ = std::make_unique<UserDataAuth>();

    // Setup the usual stuff
    UserDataAuthTestBase::SetUp();
  }

  void TearDown() override {
    PostToOriginAndBlock(base::BindOnce(
        &UserDataAuthTestThreaded::TearDownInOrigin, base::Unretained(this)));

    origin_thread_.Stop();
  }

  void TearDownInOrigin() {
    // Destruct the |userdataauth_| object.
    userdataauth_.reset();
  }

  // Initialize |userdataauth_| in |origin_thread_|
  void InitializeUserDataAuth() {
    PostToOriginAndBlock(
        base::BindOnce(base::IgnoreResult(&UserDataAuth::Initialize),
                       base::Unretained(userdataauth_.get()), mount_bus_));
  }

 protected:
  // The thread on which the |userdataauth_| object is created. This is the same
  // as |userdataauth_->origin_thread_|.
  base::Thread origin_thread_;
};

TEST_F(UserDataAuthTestThreaded, DetectEnterpriseOwnership) {
  // If asked, this machine is enterprise owned.
  static const std::string true_str = "true";
  brillo::Blob true_value(true_str.begin(), true_str.end());
  true_value.push_back(0);
  EXPECT_CALL(*attrs_, Get("enterprise.owned", _))
      .WillOnce(DoAll(SetArgPointee<1>(true_value), Return(true)));

  EXPECT_CALL(homedirs_, set_enterprise_owned(true)).WillOnce(Return());

  InitializeUserDataAuth();
}

TEST_F(UserDataAuthTestThreaded, ShutdownTask) {
  InitializeUserDataAuth();
  EXPECT_CALL(*mount_bus_, ShutdownAndBlock()).Times(1);
  PostToOriginAndBlock(base::BindLambdaForTesting([this]() {
    // Destruct the |userdataauth_| object.
    userdataauth_.reset();
  }));
}

// ============== Full API Behaviour Test for Negative Testing ==============

// This section holds tests that simulate API calls so that we can test that the
// right error comes up in error conditions.

// This serves as the base class for all full API behaviour tests. It is for a
// set of integration-style unit tests that is aimed at stressing the negative
// cases from an API usage perspective. This differs from other unit tests in
// which it is written in more of a integration test style and verifies the
// behaviour of cryptohomed APIs rather than the UserDataAuth class.
class UserDataAuthApiTest : public UserDataAuthTest {
 public:
  UserDataAuthApiTest() = default;

  void SetUp() override {
    // We need to simulate manufacturer to allow ECC auth blocks.
    ON_CALL(sim_factory_.GetMockBackend().GetMock().vendor, GetManufacturer)
        .WillByDefault(ReturnValue(0x43524F53));
    // Assume that TPM is ready.
    ON_CALL(sim_factory_.GetMockBackend().GetMock().state, IsReady)
        .WillByDefault(ReturnValue(true));
    // Sealing is supported.
    ON_CALL(sim_factory_.GetMockBackend().GetMock().sealing, IsSupported)
        .WillByDefault(ReturnValue(true));
    userdataauth_ = std::make_unique<UserDataAuth>();
    userdataauth_->set_hwsec_factory(&sim_factory_);

    SetupDefaultUserDataAuth();
    SetupMountFactory();
    // Note: We skip SetupHwsec() because we use the simulated libhwsec layer.
    SetupTasks();
    InitializeUserDataAuth();
  }

  void SetupMountFactory() {
    userdataauth_->set_mount_factory_for_testing(&mount_factory_);

    ON_CALL(mount_factory_, New(_, _, _, _, _))
        .WillByDefault(
            Invoke([this](Platform* platform, HomeDirs* homedirs,
                          bool legacy_mount, bool bind_mount_downloads,
                          bool use_local_mounter) -> Mount* {
              if (new_mounts_.empty()) {
                ADD_FAILURE() << "Not enough objects in new_mounts_";
                return nullptr;
              }
              Mount* result = new_mounts_[0];
              new_mounts_.pop_front();
              return result;
            }));
  }

  // Simply the Sync() version of StartAuthSession(). Caller should check that
  // the returned value is not nullopt, which indicates that the call did not
  // finish.
  std::optional<user_data_auth::StartAuthSessionReply> StartAuthSessionSync(
      const user_data_auth::StartAuthSessionRequest& in_request) {
    TestFuture<user_data_auth::StartAuthSessionReply> reply_future;
    userdataauth_->StartAuthSession(
        in_request,
        reply_future
            .GetCallback<const user_data_auth::StartAuthSessionReply&>());
    RunUntilIdle();
    return reply_future.Get();
  }

  // Obtain a test auth session for kUsername1. Result is nullopt if it's
  // unsuccessful.
  std::optional<std::string> GetTestUnauthedAuthSession(
      user_data_auth::AuthIntent intent =
          user_data_auth::AuthIntent::AUTH_INTENT_DECRYPT,
      uint32_t flags =
          user_data_auth::AuthSessionFlags::AUTH_SESSION_FLAGS_NONE) {
    user_data_auth::StartAuthSessionRequest req;
    req.mutable_account_id()->set_account_id(*kUsername1);
    req.set_intent(intent);
    req.set_flags(flags);
    std::optional<user_data_auth::StartAuthSessionReply> reply =
        StartAuthSessionSync(req);
    if (!reply.has_value()) {
      LOG(ERROR) << "GetTestUnauthedAuthSession() failed because "
                    "StartAuthSession() did not complete.";
      return std::nullopt;
    }

    if (reply.value().error_info().primary_action() !=
        user_data_auth::PrimaryAction::PRIMARY_NO_ERROR) {
      LOG(ERROR) << "GetTestUnauthedAuthSession() failed because "
                    "StartAuthSession() failed.";
      return std::nullopt;
    }
    return reply.value().auth_session_id();
  }

  // Create a test user named kUsername1 with kPassword1. Return true if
  // successful. This doesn't create the vault.
  bool CreateTestUser() {
    std::optional<std::string> session_id = GetTestUnauthedAuthSession();
    if (!session_id.has_value()) {
      LOG(ERROR) << "No session ID in CreateTestUser().";
      return false;
    }

    EXPECT_CALL(homedirs_, CryptohomeExists(_)).WillOnce(ReturnValue(false));
    EXPECT_CALL(homedirs_, Create(_)).WillOnce(Return(true));

    // Create the user.
    user_data_auth::CreatePersistentUserRequest create_request;
    create_request.set_auth_session_id(session_id.value());

    std::optional<user_data_auth::CreatePersistentUserReply> create_reply =
        CreatePersistentUserSync(create_request);
    if (!create_reply.has_value()) {
      LOG(ERROR) << "Call to CreatePersistentUser() did not complete in "
                    "CreateTestUser().";
      return false;
    }
    if (create_reply->error_info().primary_action() !=
        user_data_auth::PrimaryAction::PRIMARY_NO_ERROR) {
      LOG(ERROR)
          << "Call to CreatePersistentUser() failed in CreateTestUser(): "
          << GetProtoDebugString(create_reply.value());
      return false;
    }

    // Add the password auth factor.
    user_data_auth::AddAuthFactorRequest add_factor_request;
    add_factor_request.set_auth_session_id(session_id.value());
    add_factor_request.mutable_auth_factor()->set_type(
        user_data_auth::AuthFactorType::AUTH_FACTOR_TYPE_PASSWORD);
    add_factor_request.mutable_auth_factor()->set_label(kPasswordLabel);
    add_factor_request.mutable_auth_factor()->mutable_password_metadata();
    add_factor_request.mutable_auth_input()
        ->mutable_password_input()
        ->set_secret(kPassword1);

    std::optional<user_data_auth::AddAuthFactorReply> add_factor_reply =
        AddAuthFactorSync(add_factor_request);
    if (!add_factor_reply.has_value()) {
      LOG(ERROR)
          << "Call to AddAuthFactor() did not complete in CreateTestUser().";
      return false;
    }
    if (add_factor_reply->error_info().primary_action() !=
        user_data_auth::PrimaryAction::PRIMARY_NO_ERROR) {
      LOG(ERROR) << "Call to AddAuthFactor() failed in CreateTestUser(): "
                 << GetProtoDebugString(add_factor_reply.value());
      return false;
    }

    // Invalidate the session.
    user_data_auth::InvalidateAuthSessionRequest invalidate_request;
    invalidate_request.set_auth_session_id(session_id.value());
    std::optional<user_data_auth::InvalidateAuthSessionReply> invalidate_reply =
        InvalidateAuthSessionSync(invalidate_request);
    if (!invalidate_reply.has_value()) {
      LOG(ERROR) << "Call to InvalidateAuthSession() did not complete in "
                    "CreateTestUser().";
      return false;
    }
    if (invalidate_reply->error_info().primary_action() !=
        user_data_auth::PrimaryAction::PRIMARY_NO_ERROR) {
      LOG(ERROR)
          << "Call to InvalidateAuthSession() failed in CreateTestUser(): "
          << GetProtoDebugString(invalidate_reply.value());
      return false;
    }

    return true;
  }

  std::optional<std::string> GetTestAuthedAuthSession(
      user_data_auth::AuthIntent intent =
          user_data_auth::AuthIntent::AUTH_INTENT_DECRYPT) {
    std::optional<std::string> session_id = GetTestUnauthedAuthSession(intent);
    if (!session_id.has_value()) {
      LOG(ERROR) << "No session ID in GetTestAuthedAuthSession().";
      return std::nullopt;
    }

    user_data_auth::AuthenticateAuthFactorRequest auth_request;
    auth_request.set_auth_session_id(session_id.value());
    auth_request.add_auth_factor_labels(kPasswordLabel);
    auth_request.mutable_auth_input()->mutable_password_input()->set_secret(
        kPassword1);

    std::optional<user_data_auth::AuthenticateAuthFactorReply> auth_reply =
        AuthenticateAuthFactorSync(auth_request);
    if (!auth_reply.has_value()) {
      LOG(ERROR) << "Call to AuthenticateAuthFactor() did not complete in "
                    "GetTestAuthedAuthSession().";
      return std::nullopt;
    }
    if (auth_reply->error_info().primary_action() !=
        user_data_auth::PrimaryAction::PRIMARY_NO_ERROR) {
      LOG(ERROR) << "Call to AuthenticateAuthFactor() failed in "
                    "GetTestAuthedAuthSession(): "
                 << GetProtoDebugString(auth_reply.value());
      return std::nullopt;
    }

    return session_id.value();
  }

  std::optional<user_data_auth::AuthenticateAuthFactorReply>
  AuthenticateAuthFactorSync(
      const user_data_auth::AuthenticateAuthFactorRequest& in_request) {
    TestFuture<user_data_auth::AuthenticateAuthFactorReply> reply_future;
    userdataauth_->AuthenticateAuthFactor(
        in_request,
        reply_future
            .GetCallback<const user_data_auth::AuthenticateAuthFactorReply&>());
    RunUntilIdle();
    return reply_future.Get();
  }

  std::optional<user_data_auth::CreatePersistentUserReply>
  CreatePersistentUserSync(
      const user_data_auth::CreatePersistentUserRequest& in_request) {
    TestFuture<user_data_auth::CreatePersistentUserReply> reply_future;
    userdataauth_->CreatePersistentUser(
        in_request,
        reply_future
            .GetCallback<const user_data_auth::CreatePersistentUserReply&>());
    RunUntilIdle();
    return reply_future.Get();
  }

  std::optional<user_data_auth::AddAuthFactorReply> AddAuthFactorSync(
      const user_data_auth::AddAuthFactorRequest& in_request) {
    TestFuture<user_data_auth::AddAuthFactorReply> reply_future;
    userdataauth_->AddAuthFactor(
        in_request,
        reply_future.GetCallback<const user_data_auth::AddAuthFactorReply&>());
    RunUntilIdle();
    return reply_future.Get();
  }

  std::optional<user_data_auth::InvalidateAuthSessionReply>
  InvalidateAuthSessionSync(
      const user_data_auth::InvalidateAuthSessionRequest& in_request) {
    TestFuture<user_data_auth::InvalidateAuthSessionReply> reply_future;
    userdataauth_->InvalidateAuthSession(
        in_request,
        reply_future
            .GetCallback<const user_data_auth::InvalidateAuthSessionReply&>());
    RunUntilIdle();
    return reply_future.Get();
  }

  std::optional<user_data_auth::PreparePersistentVaultReply>
  PreparePersistentVaultSync(
      const user_data_auth::PreparePersistentVaultRequest& in_request) {
    TestFuture<user_data_auth::PreparePersistentVaultReply> reply_future;
    userdataauth_->PreparePersistentVault(
        in_request,
        reply_future
            .GetCallback<const user_data_auth::PreparePersistentVaultReply&>());
    RunUntilIdle();
    return reply_future.Get();
  }

  std::optional<user_data_auth::PrepareEphemeralVaultReply>
  PrepareEphemeralVaultSync(
      const user_data_auth::PrepareEphemeralVaultRequest& in_request) {
    TestFuture<user_data_auth::PrepareEphemeralVaultReply> reply_future;
    userdataauth_->PrepareEphemeralVault(
        in_request,
        reply_future
            .GetCallback<const user_data_auth::PrepareEphemeralVaultReply&>());
    RunUntilIdle();
    return reply_future.Get();
  }

  std::optional<user_data_auth::PrepareGuestVaultReply> PrepareGuestVaultSync(
      const user_data_auth::PrepareGuestVaultRequest& in_request) {
    TestFuture<user_data_auth::PrepareGuestVaultReply> reply_future;
    userdataauth_->PrepareGuestVault(
        in_request,
        reply_future
            .GetCallback<const user_data_auth::PrepareGuestVaultReply&>());
    RunUntilIdle();
    return reply_future.Get();
  }

 protected:
  // Mock mount factory for mocking Mount objects.
  MockMountFactory mount_factory_;
  // Any elements added to this queue will be returned when mount_factory_.New()
  // is called.
  std::deque<Mount*> new_mounts_;

  const Username kUsername1{"foo@gmail.com"};
  const Username kUsername2{"bar@gmail.com"};
  static constexpr char kPassword1[] = "MyP@ssW0rd!!";
  static constexpr char kPasswordLabel[] = "Password1";
  static constexpr char kSmartCardLabel[] = "SmartCard1";
  static constexpr char kTestErrorString[] = "ErrorForTestingOnly";

  hwsec::Tpm2SimulatorFactoryForTest sim_factory_;
};

// Matches against user_data_auth::CryptohomeErrorInfo to see if it contains an
// active recommendation for the specified PossibleAction |action|. "Active
// recommendation" here refers to a correct PrimaryAction value such that the
// PossibleAction field is active and not disregarded.
MATCHER_P(HasPossibleAction, action, "") {
  if (arg.primary_action() != user_data_auth::PrimaryAction::PRIMARY_NONE) {
    *result_listener
        << "Invalid PrimaryAction when checking for PossibleAction: "
        << user_data_auth::PrimaryAction_Name(arg.primary_action());
    return false;
  }
  for (int i = 0; i < arg.possible_actions_size(); i++) {
    if (arg.possible_actions(i) == action)
      return true;
  }

  return false;
}

// Same as multiple invocation of HasPossibleAction. This matcher checks that
// the CryptohomeErrorInfo contains a correct PrimaryAction and the list of
// recommended PossibleAction(s) contains the specified actions. |actions|
// should be set<user_data_auth::PossibleAction>.
MATCHER_P(HasPossibleActions, actions, "") {
  // We need to copy the actions to strip off the constness.
  std::set<user_data_auth::PossibleAction> to_match = actions;
  if (arg.primary_action() != user_data_auth::PrimaryAction::PRIMARY_NONE) {
    *result_listener
        << "Invalid PrimaryAction when checking for PossibleAction: "
        << user_data_auth::PrimaryAction_Name(arg.primary_action());
    return false;
  }
  for (int i = 0; i < arg.possible_actions_size(); i++) {
    const auto current_action = arg.possible_actions(i);
    if (to_match.count(current_action) != 0) {
      to_match.erase(current_action);
    }
  }
  for (const auto& action : to_match) {
    *result_listener << "Action " << user_data_auth::PossibleAction_Name(action)
                     << " not found";
  }
  return to_match.size() == 0;
}

TEST_F(UserDataAuthApiTest, RemoveStillMounted) {
  // If a home directory is mounted it'll return false for Remove().
  EXPECT_CALL(homedirs_, Remove(_)).WillOnce(Return(false));

  std::optional<std::string> session_id = GetTestUnauthedAuthSession();
  ASSERT_TRUE(session_id.has_value());

  user_data_auth::RemoveRequest req;
  req.set_auth_session_id(session_id.value());
  user_data_auth::RemoveReply reply;

  reply = userdataauth_->Remove(req);

  // Failure to Remove() due to still mounted vault should result in Reboot and
  // Powerwash recommendation.
  EXPECT_THAT(reply.error_info(),
              HasPossibleActions(std::set(
                  {user_data_auth::PossibleAction::POSSIBLY_REBOOT,
                   user_data_auth::PossibleAction::POSSIBLY_POWERWASH})));
}

TEST_F(UserDataAuthApiTest, RemoveNoID) {
  user_data_auth::RemoveRequest req;
  user_data_auth::RemoveReply reply;

  reply = userdataauth_->Remove(req);

  // Failure to Remove() due to the lack of username in the request is
  // unexpected, and should result in POSSIBLY_DEV_CHECK_UNEXPECTED_STATE.
  EXPECT_THAT(
      reply.error_info(),
      HasPossibleAction(
          user_data_auth::PossibleAction::POSSIBLY_DEV_CHECK_UNEXPECTED_STATE));
}

TEST_F(UserDataAuthApiTest, AuthAuthFactorNoSession) {
  user_data_auth::AuthenticateAuthFactorRequest req;
  req.set_auth_session_id("NOT_A_VALID_AUTH_SESSION!");
  user_data_auth::AuthenticateAuthFactorReply reply;

  std::optional<user_data_auth::AuthenticateAuthFactorReply> result =
      AuthenticateAuthFactorSync(req);
  ASSERT_TRUE(result.has_value());
  reply = *result;

  // Failure to AuthenticateAuthFactor() due to missing session should result in
  // recommendation to reboot, because we'll need to restart the session after
  // reboot so the problem might go away.
  EXPECT_THAT(
      reply.error_info(),
      HasPossibleAction(user_data_auth::PossibleAction::POSSIBLY_REBOOT));
}

TEST_F(UserDataAuthApiTest, ChalCredBadSRKROCA) {
  ASSERT_TRUE(CreateTestUser());
  std::optional<std::string> session_id = GetTestAuthedAuthSession();
  ASSERT_TRUE(session_id.has_value());

  ON_CALL(sim_factory_.GetMockBackend().GetMock().vendor, IsSrkRocaVulnerable)
      .WillByDefault(ReturnValue(true));

  ON_CALL(key_challenge_service_factory_, New(_))
      .WillByDefault(
          Return(ByMove(std::make_unique<MockKeyChallengeService>())));

  user_data_auth::AddAuthFactorRequest add_factor_request;
  add_factor_request.set_auth_session_id(session_id.value());
  add_factor_request.mutable_auth_factor()->set_type(
      user_data_auth::AuthFactorType::AUTH_FACTOR_TYPE_SMART_CARD);
  add_factor_request.mutable_auth_factor()->set_label(kSmartCardLabel);
  add_factor_request.mutable_auth_factor()
      ->mutable_smart_card_metadata()
      ->set_public_key_spki_der("test_pubkey_spki_der");
  add_factor_request.mutable_auth_input()
      ->mutable_smart_card_input()
      ->add_signature_algorithms(user_data_auth::SmartCardSignatureAlgorithm::
                                     CHALLENGE_RSASSA_PKCS1_V1_5_SHA256);
  add_factor_request.mutable_auth_input()
      ->mutable_smart_card_input()
      ->set_key_delegate_dbus_service_name("test_challenge_dbus");

  std::optional<user_data_auth::AddAuthFactorReply> add_factor_reply =
      AddAuthFactorSync(add_factor_request);
  ASSERT_TRUE(add_factor_reply.has_value());
  EXPECT_EQ(add_factor_reply->error_info().primary_action(),
            user_data_auth::PrimaryAction::PRIMARY_TPM_UDPATE_REQUIRED);
  EXPECT_FALSE(add_factor_reply->has_added_auth_factor());
}

TEST_F(UserDataAuthApiTest, MountFailed) {
  // Prepare an account.
  ASSERT_TRUE(CreateTestUser());
  std::optional<std::string> session_id = GetTestAuthedAuthSession();
  ASSERT_TRUE(session_id.has_value());

  // Ensure that the mount fails.
  scoped_refptr<MockMount> mount = new MockMount();
  EXPECT_CALL(*mount, MountCryptohome(_, _, _))
      .WillOnce(ReturnError<StorageError>(FROM_HERE, kTestErrorString,
                                          MOUNT_ERROR_FATAL, false));
  new_mounts_.push_back(mount.get());

  EXPECT_CALL(homedirs_, Exists(_)).WillOnce(Return(true));
  EXPECT_CALL(disk_cleanup_, FreeDiskSpaceDuringLogin(_))
      .WillRepeatedly(Return(true));

  // Make the call to check that the result is correct.
  user_data_auth::PreparePersistentVaultRequest prepare_req;
  prepare_req.set_auth_session_id(session_id.value());
  std::optional<user_data_auth::PreparePersistentVaultReply> prepare_reply =
      PreparePersistentVaultSync(prepare_req);

  ASSERT_TRUE(prepare_reply.has_value());
  EXPECT_THAT(prepare_reply->error_info(),
              HasPossibleActions(std::set(
                  {user_data_auth::PossibleAction::POSSIBLY_RETRY,
                   user_data_auth::PossibleAction::POSSIBLY_REBOOT,
                   user_data_auth::PossibleAction::POSSIBLY_DELETE_VAULT,
                   user_data_auth::PossibleAction::POSSIBLY_POWERWASH})));
}

TEST_F(UserDataAuthApiTest, GuestMountFailed) {
  // Ensure that the guest mount fails.
  scoped_refptr<MockMount> mount = new MockMount();
  EXPECT_CALL(*mount, MountEphemeralCryptohome(_))
      .WillOnce(ReturnError<StorageError>(FROM_HERE, kTestErrorString,
                                          MOUNT_ERROR_FATAL, false));
  new_mounts_.push_back(mount.get());

  // Make the call to check that it failed correctly.
  user_data_auth::PrepareGuestVaultRequest prepare_req;
  std::optional<user_data_auth::PrepareGuestVaultReply> prepare_reply =
      PrepareGuestVaultSync(prepare_req);
  ASSERT_TRUE(prepare_reply.has_value());
  EXPECT_THAT(prepare_reply->error_info(),
              HasPossibleActions(std::set(
                  {user_data_auth::PossibleAction::POSSIBLY_RETRY,
                   user_data_auth::PossibleAction::POSSIBLY_REBOOT,
                   user_data_auth::PossibleAction::POSSIBLY_POWERWASH})));
}

TEST_F(UserDataAuthApiTest, EphemeralMountFailed) {
  // Prepare an auth session for ephemeral mount.
  std::optional<std::string> session_id = GetTestUnauthedAuthSession(
      user_data_auth::AuthIntent::AUTH_INTENT_DECRYPT,
      user_data_auth::AuthSessionFlags::AUTH_SESSION_FLAGS_EPHEMERAL_USER);
  ASSERT_TRUE(session_id.has_value());

  // Ensure that the mount fails.
  scoped_refptr<MockMount> mount = new MockMount();
  EXPECT_CALL(*mount, MountEphemeralCryptohome(_))
      .WillOnce(ReturnError<StorageError>(FROM_HERE, kTestErrorString,
                                          MOUNT_ERROR_FATAL, false));
  new_mounts_.push_back(mount.get());
  EXPECT_CALL(homedirs_, GetPlainOwner(_))
      .WillRepeatedly(DoAll(SetArgPointee<0>(kUsername2), Return(true)));

  // Make the call to check that the result is correct.
  user_data_auth::PrepareEphemeralVaultRequest prepare_req;
  prepare_req.set_auth_session_id(session_id.value());
  std::optional<user_data_auth::PrepareEphemeralVaultReply> prepare_reply =
      PrepareEphemeralVaultSync(prepare_req);

  ASSERT_TRUE(prepare_reply.has_value());
  EXPECT_THAT(prepare_reply->error_info(),
              HasPossibleActions(std::set(
                  {user_data_auth::PossibleAction::POSSIBLY_RETRY,
                   user_data_auth::PossibleAction::POSSIBLY_REBOOT,
                   user_data_auth::PossibleAction::POSSIBLY_POWERWASH})));
}

// This is designed to trigger the unrecoverable vault flow.
TEST_F(UserDataAuthApiTest, VaultWithoutAuth) {
  // Mock that the user exists.
  base::FilePath upath = UserPath(SanitizeUserName(kUsername1));
  EXPECT_CALL(platform_, DirectoryExists(upath)).WillOnce(Return(true));

  // Call StartAuthSession and it should fail.
  user_data_auth::StartAuthSessionRequest req;
  req.mutable_account_id()->set_account_id(*kUsername1);
  req.set_intent(user_data_auth::AuthIntent::AUTH_INTENT_DECRYPT);
  req.set_flags(user_data_auth::AuthSessionFlags::AUTH_SESSION_FLAGS_NONE);
  std::optional<user_data_auth::StartAuthSessionReply> reply =
      StartAuthSessionSync(req);
  ASSERT_TRUE(reply.has_value());

  EXPECT_THAT(
      reply->error_info(),
      HasPossibleAction(user_data_auth::PossibleAction::POSSIBLY_DELETE_VAULT));
}

// This is designed to trigger FailureReason::COULD_NOT_MOUNT_CRYPTOHOME on
// Chromium side for AuthenticateAuthFactor().
TEST_F(UserDataAuthApiTest, AuthAuthFactorWithoutLabel) {
  // Prepare an account.
  ASSERT_TRUE(CreateTestUser());

  // Call AuthenticateAuthFactor with an empty label.
  std::optional<std::string> session_id = GetTestUnauthedAuthSession();
  ASSERT_TRUE(session_id.has_value());

  user_data_auth::AuthenticateAuthFactorRequest auth_request;
  auth_request.set_auth_session_id(session_id.value());
  // Intentionally set empty label.
  auth_request.set_auth_factor_label("");
  auth_request.mutable_auth_input()->mutable_password_input()->set_secret(
      kPassword1);

  std::optional<user_data_auth::AuthenticateAuthFactorReply> auth_reply =
      AuthenticateAuthFactorSync(auth_request);

  // Should result is POSSIBLY_DEV_CHECK_UNEXPECTED_STATE.
  ASSERT_TRUE(auth_reply.has_value());
  EXPECT_THAT(
      auth_reply->error_info(),
      HasPossibleAction(
          user_data_auth::PossibleAction::POSSIBLY_DEV_CHECK_UNEXPECTED_STATE));
}

// This is designed to trigger FailureReason::COULD_NOT_MOUNT_CRYPTOHOME on
// Chromium side for CreatePersistentUserAlreadyExist().
TEST_F(UserDataAuthApiTest, CreatePeristentUserAlreadyExist) {
  // Setup auth session.
  std::optional<std::string> session_id = GetTestUnauthedAuthSession();
  ASSERT_TRUE(session_id.has_value());

  // Call CreatePersistentUser() while the user already exists.
  EXPECT_CALL(homedirs_, CryptohomeExists(_)).WillOnce(ReturnValue(true));
  user_data_auth::CreatePersistentUserRequest create_request;
  create_request.set_auth_session_id(session_id.value());

  std::optional<user_data_auth::CreatePersistentUserReply> create_reply =
      CreatePersistentUserSync(create_request);
  ASSERT_TRUE(create_reply.has_value());
  EXPECT_THAT(
      create_reply->error_info(),
      HasPossibleActions(std::set(
          {user_data_auth::PossibleAction::POSSIBLY_DEV_CHECK_UNEXPECTED_STATE,
           user_data_auth::PossibleAction::POSSIBLY_DELETE_VAULT})));
}

// This is designed to trigger FailureReason::COULD_NOT_MOUNT_CRYPTOHOME on
// Chromium side for PreparePersistentVault().
TEST_F(UserDataAuthApiTest, PreparePersistentVaultWithoutUser) {
  // Prepare an account.
  ASSERT_TRUE(CreateTestUser());
  std::optional<std::string> session_id = GetTestAuthedAuthSession();
  ASSERT_TRUE(session_id.has_value());

  // Vault doesn't exist.
  EXPECT_CALL(homedirs_, Exists(_)).WillOnce(Return(false));

  // Make the call to check that the result is correct.
  user_data_auth::PreparePersistentVaultRequest prepare_req;
  prepare_req.set_auth_session_id(session_id.value());
  std::optional<user_data_auth::PreparePersistentVaultReply> prepare_reply =
      PreparePersistentVaultSync(prepare_req);

  ASSERT_TRUE(prepare_reply.has_value());
  EXPECT_THAT(
      prepare_reply->error_info(),
      HasPossibleActions(std::set(
          {user_data_auth::PossibleAction::POSSIBLY_DEV_CHECK_UNEXPECTED_STATE,
           user_data_auth::PossibleAction::POSSIBLY_REBOOT,
           user_data_auth::PossibleAction::POSSIBLY_DELETE_VAULT,
           user_data_auth::PossibleAction::POSSIBLY_POWERWASH})));
}

// This is designed to trigger FailureReason::COULD_NOT_MOUNT_CRYPTOHOME on
// Chromium side for PrepareEphemeralVault().
TEST_F(UserDataAuthApiTest, EphemeralMountWithRegularSession) {
  // Prepare an auth session for ephemeral mount, note that we intentionally
  // does not specify it as ephemeral.
  std::optional<std::string> session_id = GetTestUnauthedAuthSession(
      user_data_auth::AuthIntent::AUTH_INTENT_DECRYPT,
      user_data_auth::AuthSessionFlags::AUTH_SESSION_FLAGS_NONE);
  ASSERT_TRUE(session_id.has_value());

  // Make the call to check that it fails due to the session not being
  // ephemeral.
  user_data_auth::PrepareEphemeralVaultRequest prepare_req;
  prepare_req.set_auth_session_id(session_id.value());
  std::optional<user_data_auth::PrepareEphemeralVaultReply> prepare_reply =
      PrepareEphemeralVaultSync(prepare_req);

  ASSERT_TRUE(prepare_reply.has_value());
  EXPECT_THAT(
      prepare_reply->error_info(),
      HasPossibleActions(std::set(
          {user_data_auth::PossibleAction::POSSIBLY_DEV_CHECK_UNEXPECTED_STATE,
           user_data_auth::PossibleAction::POSSIBLY_REBOOT,
           user_data_auth::PossibleAction::POSSIBLY_POWERWASH})));
}

// This is designed to trigger FailureReason::COULD_NOT_MOUNT_CRYPTOHOME on
// Chromium side for PrepareGuestVault().
TEST_F(UserDataAuthApiTest, MountGuestWithOtherMounts) {
  // Create test user and mount the vault.
  ASSERT_TRUE(CreateTestUser());
  std::optional<std::string> session_id = GetTestAuthedAuthSession();
  ASSERT_TRUE(session_id.has_value());

  // Setup the mount.
  scoped_refptr<MockMount> mount = new MockMount();
  EXPECT_CALL(*mount, MountCryptohome(_, _, _))
      .WillOnce(ReturnOk<StorageError>());
  new_mounts_.push_back(mount.get());

  EXPECT_CALL(homedirs_, Exists(_)).WillOnce(Return(true));
  EXPECT_CALL(disk_cleanup_, FreeDiskSpaceDuringLogin(_))
      .WillRepeatedly(Return(true));

  user_data_auth::PreparePersistentVaultRequest prepare_req;
  prepare_req.set_auth_session_id(session_id.value());
  std::optional<user_data_auth::PreparePersistentVaultReply> prepare_reply =
      PreparePersistentVaultSync(prepare_req);
  ASSERT_TRUE(prepare_reply.has_value());
  ASSERT_EQ(prepare_reply->error_info().primary_action(),
            user_data_auth::PrimaryAction::PRIMARY_NO_ERROR);

  // Try to mount the guest vault and it should fail.
  user_data_auth::PrepareGuestVaultRequest guest_req;
  std::optional<user_data_auth::PrepareGuestVaultReply> guest_reply =
      PrepareGuestVaultSync(guest_req);
  ASSERT_TRUE(guest_reply.has_value());
  EXPECT_THAT(guest_reply->error_info(),
              HasPossibleActions(
                  std::set({user_data_auth::PossibleAction::POSSIBLY_REBOOT})));
}

}  // namespace cryptohome

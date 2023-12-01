// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/session_manager_impl.h"

#include <fcntl.h>
#include <keyutils.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/command_line.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/files/scoped_temp_dir.h>
#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/memory/ptr_util.h>
#include <base/memory/ref_counted.h>
#include <base/memory/weak_ptr.h>
#include <base/notreached.h>
#include <base/posix/unix_domain_socket.h>
#include <base/run_loop.h>
#include <base/strings/string_util.h>
#include <base/task/single_thread_task_executor.h>
#include <base/test/bind.h>
#include <base/test/simple_test_tick_clock.h>
#include <base/test/test_future.h>
#include <brillo/cryptohome.h>
#include <brillo/dbus/dbus_param_writer.h>
#include <brillo/errors/error.h>
#include <brillo/message_loops/fake_message_loop.h>
#include <chromeos/dbus/service_constants.h>
#include <crypto/scoped_nss_types.h>
#include <dbus/bus.h>
#include <dbus/message.h>
#include <dbus/mock_exported_object.h>
#include <dbus/mock_object_proxy.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <libpasswordprovider/password.h>
#include <libpasswordprovider/password_provider.h>

#include "arc/arc.pb.h"
#include "bindings/chrome_device_policy.pb.h"
#include "bindings/device_management_backend.pb.h"
#include "dbus/login_manager/dbus-constants.h"
#include "libpasswordprovider/fake_password_provider.h"
#include "login_manager/blob_util.h"
#include "login_manager/dbus_test_util.h"
#include "login_manager/dbus_util.h"
#include "login_manager/device_local_account_manager.h"
#include "login_manager/fake_container_manager.h"
#include "login_manager/fake_crossystem.h"
#include "login_manager/fake_secret_util.h"
#include "login_manager/file_checker.h"
#include "login_manager/matchers.h"
#include "login_manager/mock_arc_sideload_status.h"
#include "login_manager/mock_device_identifier_generator.h"
#include "login_manager/mock_device_policy_service.h"
#include "login_manager/mock_file_checker.h"
#include "login_manager/mock_init_daemon_controller.h"
#include "login_manager/mock_install_attributes_reader.h"
#include "login_manager/mock_key_generator.h"
#include "login_manager/mock_metrics.h"
#include "login_manager/mock_nss_util.h"
#include "login_manager/mock_policy_key.h"
#include "login_manager/mock_policy_service.h"
#include "login_manager/mock_process_manager_service.h"
#include "login_manager/mock_system_utils.h"
#include "login_manager/mock_user_policy_service_factory.h"
#include "login_manager/mock_vpd_process.h"
#include "login_manager/proto_bindings/login_screen_storage.pb.h"
#include "login_manager/proto_bindings/policy_descriptor.pb.h"
#include "login_manager/secret_util.h"
#include "login_manager/system_utils_impl.h"

using ::base::test::TestFuture;
using ::testing::_;
using ::testing::AnyNumber;
using ::testing::AtLeast;
using ::testing::AtMost;
using ::testing::ByMove;
using ::testing::DoAll;
using ::testing::ElementsAre;
using ::testing::ElementsAreArray;
using ::testing::Field;
using ::testing::HasSubstr;
using ::testing::Invoke;
using ::testing::InvokeWithoutArgs;
using ::testing::IsEmpty;
using ::testing::Matcher;
using ::testing::Mock;
using ::testing::NotNull;
using ::testing::Return;
using ::testing::ReturnNull;
using ::testing::ReturnRef;
using ::testing::SaveArg;
using ::testing::SetArgPointee;
using ::testing::StartsWith;
using ::testing::StrEq;
using ::testing::WithArg;

using brillo::cryptohome::home::GetGuestUsername;
using brillo::cryptohome::home::SanitizeUserName;
using brillo::cryptohome::home::SetSystemSalt;
using brillo::cryptohome::home::Username;

ACTION_TEMPLATE(MovePointee,
                HAS_1_TEMPLATE_PARAMS(int, k),
                AND_1_VALUE_PARAMS(pointer)) {
  *pointer = std::move(*(::std::get<k>(args)));
}

using std::map;
using std::string;
using std::vector;

namespace em = enterprise_management;

namespace login_manager {

namespace {

const char* const kUserlessArgv[] = {
    "program",
    "--switch1",
    "--switch2=switch2_value",
    "--switch3=escaped_\"_quote",
    "--switch4=white space",
    "arg1",
    "arg 2",
};

const char* const kGuestArgv[] = {
    "program",
    "--bwsi",
    "--switch1=switch1_value",
    "--switch2=escaped_\"_quote",
    "--switch3=white space",
    "arg1",
    "arg 2",
};

// Test Bus instance to inject MockExportedObject.
class FakeBus : public dbus::Bus {
 public:
  FakeBus()
      : dbus::Bus(GetBusOptions()),
        exported_object_(new dbus::MockExportedObject(
            nullptr, dbus::ObjectPath("/fake/path"))) {}

  dbus::MockExportedObject* exported_object() { return exported_object_.get(); }

  // dbus::Bus overrides.
  dbus::ExportedObject* GetExportedObject(
      const dbus::ObjectPath& object_path) override {
    return exported_object_.get();
  }

  bool RequestOwnershipAndBlock(const std::string& service_name,
                                ServiceOwnershipOptions options) override {
    return true;  // Fake to success.
  }

 protected:
  // dbus::Bus is refcounted object.
  ~FakeBus() override = default;

 private:
  scoped_refptr<dbus::MockExportedObject> exported_object_;

  static dbus::Bus::Options GetBusOptions() {
    dbus::Bus::Options options;
    options.bus_type = dbus::Bus::SYSTEM;
    return options;
  }
};

// Storing T value. Iff T is const char*, instead std::string value.
template <typename T>
struct PayloadStorage {
  // gtest/gmock 1.8.1 and later add an extra const that needs to be stripped.
  typename std::remove_const<T>::type value;
};

// For gtest/gmock < 1.8.1
template <>
struct PayloadStorage<const char*> {
  std::string value;
};

// For gtest/gmock >= 1.8.1
template <>
struct PayloadStorage<const char* const> {
  std::string value;
};

#if USE_CHEETS
// For gtest/gmock < 1.8.1
template <>
struct PayloadStorage<ArcContainerStopReason> {
  uint32_t value;
};

// For gtest/gmock >= 1.8.1
template <>
struct PayloadStorage<const ArcContainerStopReason> {
  uint32_t value;
};

// Overloading for easier payload test in MATCHERs.
bool operator==(ArcContainerStopReason payload, uint32_t value) {
  return static_cast<uint32_t>(payload) == value;
}
#endif

// Matcher for SessionManagerInterface's signal.
MATCHER_P(SignalEq, method_name, "") {
  return arg->GetMember() == method_name;
}

MATCHER_P2(SignalEq, method_name, payload1, "") {
  PayloadStorage<decltype(payload1)> actual1;
  dbus::MessageReader reader(arg);
  return (arg->GetMember() == method_name &&
          brillo::dbus_utils::PopValueFromReader(&reader, &actual1.value) &&
          payload1 == actual1.value);
}

MATCHER_P3(SignalEq, method_name, payload1, payload2, "") {
  PayloadStorage<decltype(payload1)> actual1;
  PayloadStorage<decltype(payload2)> actual2;
  dbus::MessageReader reader(arg);
  return (arg->GetMember() == method_name &&
          brillo::dbus_utils::PopValueFromReader(&reader, &actual1.value) &&
          payload1 == actual1.value &&
          brillo::dbus_utils::PopValueFromReader(&reader, &actual2.value) &&
          payload2 == actual2.value);
}

// Checks whether a PolicyNamespace is not a POLICY_DOMAIN_CHROME namespace and
// has a component id.
MATCHER(IsComponentNamespace, "") {
  return arg.first != POLICY_DOMAIN_CHROME && !arg.second.empty();
}

// Checks whether the PK11SlotDescriptor object includes a given PK11SlotInfo
// object.
MATCHER_P(IncludesSlot, slot, "") {
  return arg->slot.get() == slot;
}

constexpr pid_t kAndroidPid = 10;

constexpr char kSaneEmail[] = "user@somewhere.com";
constexpr char kDeviceLocalAccountsDir[] = "device_local_accounts";
constexpr char kLoginScreenStoragePath[] = "login_screen_storage";

#if USE_CHEETS
constexpr char kDefaultLocale[] = "en_US";

arc::UpgradeArcContainerRequest CreateUpgradeArcContainerRequest() {
  arc::UpgradeArcContainerRequest request;
  request.set_account_id(kSaneEmail);
  request.set_locale(kDefaultLocale);
  return request;
}
#endif

constexpr char kEmptyAccountId[] = "";

std::vector<uint8_t> MakePolicyDescriptor(PolicyAccountType account_type,
                                          const std::string& account_id) {
  PolicyDescriptor descriptor;
  descriptor.set_account_type(account_type);
  descriptor.set_account_id(account_id);
  descriptor.set_domain(POLICY_DOMAIN_CHROME);
  return StringToBlob(descriptor.SerializeAsString());
}

std::vector<uint8_t> MakeLoginScreenStorageMetadata(
    bool clear_on_session_exit) {
  LoginScreenStorageMetadata metadata;
  metadata.set_clear_on_session_exit(clear_on_session_exit);
  return StringToBlob(metadata.SerializeAsString());
}

#if USE_CHEETS
std::string ExpectedSkipPackagesCacheSetupFlagValue(bool enabled) {
  return base::StringPrintf("SKIP_PACKAGES_CACHE_SETUP=%d", enabled);
}

std::string ExpectedCopyPackagesCacheFlagValue(bool enabled) {
  return base::StringPrintf("COPY_PACKAGES_CACHE=%d", enabled);
}

std::string ExpectedSkipGmsCoreCacheSetupFlagValue(bool enabled) {
  return base::StringPrintf("SKIP_GMS_CORE_CACHE_SETUP=%d", enabled);
}

std::string ExpectedSkipTtsCacheSetupFlagValue(bool enabled) {
  return base::StringPrintf("SKIP_TTS_CACHE_SETUP=%d", enabled);
}

#endif  // USE_CHEETS

}  // namespace

class SessionManagerImplTest : public ::testing::Test,
                               public SessionManagerImpl::Delegate {
 public:
  SessionManagerImplTest()
      : bus_(new FakeBus()),
        device_identifier_generator_(&utils_, &metrics_),
        android_container_(kAndroidPid),
        powerd_proxy_(new dbus::MockObjectProxy(
            nullptr, "", dbus::ObjectPath("/fake/powerd"))),
        system_clock_proxy_(new dbus::MockObjectProxy(
            nullptr, "", dbus::ObjectPath("/fake/clock"))),
        debugd_proxy_(new dbus::MockObjectProxy(
            nullptr, "", dbus::ObjectPath("/fake/debugd"))),
        fwmp_proxy_(new dbus::MockObjectProxy(
            nullptr, "", dbus::ObjectPath("/fake/fwmp"))) {}
  SessionManagerImplTest(const SessionManagerImplTest&) = delete;
  SessionManagerImplTest& operator=(const SessionManagerImplTest&) = delete;

  ~SessionManagerImplTest() override = default;

  void SetUp() override {
    ON_CALL(utils_, GetDevModeState())
        .WillByDefault(Return(DevModeState::DEV_MODE_OFF));
    ON_CALL(utils_, GetVmState()).WillByDefault(Return(VmState::OUTSIDE_VM));

    // Forward file operation calls to |real_utils_| so that the tests can
    // actually create/modify/delete files in |tmpdir_|.
    ON_CALL(utils_, EnsureAndReturnSafeFileSize(_, _))
        .WillByDefault(Invoke(&real_utils_,
                              &SystemUtilsImpl::EnsureAndReturnSafeFileSize));
    ON_CALL(utils_, Exists(_))
        .WillByDefault(Invoke(&real_utils_, &SystemUtilsImpl::Exists));
    ON_CALL(utils_, DirectoryExists(_))
        .WillByDefault(Invoke(&real_utils_, &SystemUtilsImpl::DirectoryExists));
    ON_CALL(utils_, CreateDir(_))
        .WillByDefault(Invoke(&real_utils_, &SystemUtilsImpl::CreateDir));
    ON_CALL(utils_, GetUniqueFilenameInWriteOnlyTempDir(_))
        .WillByDefault(
            Invoke(&real_utils_,
                   &SystemUtilsImpl::GetUniqueFilenameInWriteOnlyTempDir));
    ON_CALL(utils_, RemoveFile(_))
        .WillByDefault(Invoke(&real_utils_, &SystemUtilsImpl::RemoveFile));
    ON_CALL(utils_, AtomicFileWrite(_, _))
        .WillByDefault(Invoke(&real_utils_, &SystemUtilsImpl::AtomicFileWrite));

    // 10 GB Free Disk Space for ARC launch.
    ON_CALL(utils_, AmountOfFreeDiskSpace(_)).WillByDefault(Return(10LL << 30));

    ASSERT_TRUE(tmpdir_.CreateUniqueTempDir());
    real_utils_.set_base_dir_for_testing(tmpdir_.GetPath());
    SetSystemSalt(&fake_salt_);

    // AtomicFileWrite calls in TEST_F assume that these directories exist.
    ASSERT_TRUE(utils_.CreateDir(base::FilePath("/run/session_manager")));
    ASSERT_TRUE(utils_.CreateDir(base::FilePath("/mnt/stateful_partition")));

    ASSERT_TRUE(log_dir_.CreateUniqueTempDir());
    log_symlink_ = log_dir_.GetPath().Append("ui.LATEST");

    init_controller_ = new MockInitDaemonController();
    arc_sideload_status_ = new MockArcSideloadStatus();
    impl_ = std::make_unique<SessionManagerImpl>(
        this /* delegate */, base::WrapUnique(init_controller_), bus_.get(),
        &key_gen_, &device_identifier_generator_, &manager_, &metrics_, &nss_,
        std::nullopt, &utils_, &crossystem_, &vpd_process_, &owner_key_,
        &android_container_, &install_attributes_reader_, powerd_proxy_.get(),
        system_clock_proxy_.get(), debugd_proxy_.get(), fwmp_proxy_.get(),
        arc_sideload_status_);
    impl_->SetSystemClockLastSyncInfoRetryDelayForTesting(base::TimeDelta());
    impl_->SetUiLogSymlinkPathForTesting(log_symlink_);

    device_policy_store_ = new MockPolicyStore();
    ON_CALL(*device_policy_store_, Get())
        .WillByDefault(ReturnRef(device_policy_));

    device_policy_service_ = new MockDevicePolicyService(&owner_key_);
    device_policy_service_->SetStoreForTesting(
        MakeChromePolicyNamespace(),
        std::unique_ptr<MockPolicyStore>(device_policy_store_));

    user_policy_service_factory_ =
        new testing::NiceMock<MockUserPolicyServiceFactory>();
    ON_CALL(*user_policy_service_factory_, Create(_))
        .WillByDefault(
            Invoke(this, &SessionManagerImplTest::CreateUserPolicyService));

    device_local_accounts_dir_ =
        tmpdir_.GetPath().Append(kDeviceLocalAccountsDir);
    auto device_local_account_manager =
        std::make_unique<DeviceLocalAccountManager>(device_local_accounts_dir_,
                                                    &owner_key_);

    impl_->SetPolicyServicesForTesting(
        base::WrapUnique(device_policy_service_),
        base::WrapUnique(user_policy_service_factory_),
        std::move(device_local_account_manager));

    // Start at an arbitrary non-zero time.
    tick_clock_ = new base::SimpleTestTickClock();
    tick_clock_->SetNowTicks(base::TimeTicks() + base::Hours(1));
    impl_->SetTickClockForTesting(base::WrapUnique(tick_clock_));

    login_screen_storage_path_ =
        tmpdir_.GetPath().Append(kLoginScreenStoragePath);
    auto shared_memory_util =
        std::make_unique<secret_util::FakeSharedMemoryUtil>();
    shared_memory_util_ = shared_memory_util.get();
    impl_->SetLoginScreenStorageForTesting(std::make_unique<LoginScreenStorage>(
        login_screen_storage_path_, std::move(shared_memory_util)));

    EXPECT_CALL(*debugd_proxy_, CallMethodAndBlock(_, _))
        .WillRepeatedly(
            Invoke(this, &SessionManagerImplTest::CreateMockProxyResponse));

    EXPECT_CALL(*powerd_proxy_,
                DoConnectToSignal(power_manager::kPowerManagerInterface,
                                  power_manager::kSuspendImminentSignal, _, _))
        .WillOnce(SaveArg<2>(&suspend_imminent_callback_));
    EXPECT_CALL(*powerd_proxy_,
                DoConnectToSignal(power_manager::kPowerManagerInterface,
                                  power_manager::kSuspendDoneSignal, _, _))
        .WillOnce(SaveArg<2>(&suspend_done_callback_));

    EXPECT_CALL(*system_clock_proxy_, DoWaitForServiceToBeAvailable(_))
        .WillOnce(MovePointee<0>(&available_callback_));

    EXPECT_CALL(*arc_sideload_status_, Initialize());
    impl_->Initialize();

    ASSERT_TRUE(Mock::VerifyAndClearExpectations(powerd_proxy_.get()));
    ASSERT_FALSE(suspend_imminent_callback_.is_null());
    ASSERT_FALSE(suspend_done_callback_.is_null());

    ASSERT_TRUE(Mock::VerifyAndClearExpectations(system_clock_proxy_.get()));
    ASSERT_FALSE(available_callback_.is_null());

    EXPECT_CALL(*exported_object(), ExportMethodAndBlock(_, _, _))
        .WillRepeatedly(Return(true));
    impl_->StartDBusService();
    ASSERT_TRUE(Mock::VerifyAndClearExpectations(exported_object()));

    password_provider_ = new password_provider::FakePasswordProvider;
    impl_->SetPasswordProviderForTesting(
        std::unique_ptr<password_provider::FakePasswordProvider>(
            password_provider_));
  }

  void TearDown() override {
    device_policy_service_ = nullptr;
    init_controller_ = nullptr;
    EXPECT_CALL(*exported_object(), Unregister()).Times(1);
    impl_.reset();
    Mock::VerifyAndClearExpectations(exported_object());

    SetSystemSalt(nullptr);
    EXPECT_EQ(actual_locks_, expected_locks_);
    EXPECT_EQ(actual_restarts_, expected_restarts_);
  }

  // SessionManagerImpl::Delegate:
  void LockScreen() override { actual_locks_++; }
  void RestartDevice(const std::string& description) override {
    actual_restarts_++;
  }

 protected:
#if USE_CHEETS
  class StartArcInstanceExpectationsBuilder {
   public:
    StartArcInstanceExpectationsBuilder() = default;
    StartArcInstanceExpectationsBuilder(
        const StartArcInstanceExpectationsBuilder&) = delete;
    StartArcInstanceExpectationsBuilder& operator=(
        const StartArcInstanceExpectationsBuilder&) = delete;

    StartArcInstanceExpectationsBuilder& SetDevMode(bool v) {
      dev_mode_ = v;
      return *this;
    }

    StartArcInstanceExpectationsBuilder& SetNativeBridgeExperiment(bool v) {
      native_bridge_experiment_ = v;
      return *this;
    }

    StartArcInstanceExpectationsBuilder& SetArcFilePickerExperiment(bool v) {
      arc_file_picker_experiment_ = v;
      return *this;
    }

    StartArcInstanceExpectationsBuilder& SetArcCustomTabExperiment(bool v) {
      arc_custom_tab_experiment_ = v;
      return *this;
    }

    StartArcInstanceExpectationsBuilder& SetDisableMediaStoreMaintenance(
        bool v) {
      disable_media_store_maintenance_ = v;
      return *this;
    }

    StartArcInstanceExpectationsBuilder& SetDisableDownloadProvider(bool v) {
      disable_download_provider_ = v;
      return *this;
    }

    StartArcInstanceExpectationsBuilder& SetDisableUreadahead(bool v) {
      disable_ureadahead_ = v;
      return *this;
    }

    StartArcInstanceExpectationsBuilder& SetEnableNotificationRefresh(bool v) {
      enable_notification_refresh_ = v;
      return *this;
    }

    StartArcInstanceExpectationsBuilder& SetEnableConsumerAutoUpdateToggle(
        int v) {
      enable_consumer_auto_update_toggle_ = v;
      return *this;
    }

    StartArcInstanceExpectationsBuilder& SetEnablePrivacyHubForChrome(int v) {
      enable_privacy_hub_for_chrome_ = v;
      return *this;
    }

    StartArcInstanceExpectationsBuilder& SetArcGeneratePai(bool v) {
      arc_generate_pai_ = v;
      return *this;
    }

    StartArcInstanceExpectationsBuilder& SetPlayStoreAutoUpdate(
        arc::StartArcMiniInstanceRequest_PlayStoreAutoUpdate v) {
      play_store_auto_update_ = v;
      return *this;
    }

    StartArcInstanceExpectationsBuilder& SetArcLcdDensity(int v) {
      arc_lcd_density_ = v;
      return *this;
    }

    StartArcInstanceExpectationsBuilder& SetDalvikMemoryProfile(
        arc::StartArcMiniInstanceRequest_DalvikMemoryProfile v) {
      dalvik_memory_profile_ = v;
      return *this;
    }

    StartArcInstanceExpectationsBuilder& SetEnableTTSCaching(bool v) {
      enable_tts_caching_ = v;
      return *this;
    }

    StartArcInstanceExpectationsBuilder& SetHostUreadaheadGeneration(bool v) {
      host_ureadahead_generation_ = v;
      return *this;
    }

    std::vector<std::string> Build() const {
      std::vector<std::string> result({
          "CHROMEOS_DEV_MODE=" + std::to_string(dev_mode_),
          "CHROMEOS_INSIDE_VM=0",
          "NATIVE_BRIDGE_EXPERIMENT=" +
              std::to_string(native_bridge_experiment_),
          "ARC_FILE_PICKER_EXPERIMENT=" +
              std::to_string(arc_file_picker_experiment_),
          "ARC_CUSTOM_TABS_EXPERIMENT=" +
              std::to_string(arc_custom_tab_experiment_),
          "DISABLE_MEDIA_STORE_MAINTENANCE=" +
              std::to_string(disable_media_store_maintenance_),
          "DISABLE_DOWNLOAD_PROVIDER=" +
              std::to_string(disable_download_provider_),
          "DISABLE_UREADAHEAD=" + std::to_string(disable_ureadahead_),
          "ENABLE_CONSUMER_AUTO_UPDATE_TOGGLE=" +
              std::to_string(enable_consumer_auto_update_toggle_),
          "ENABLE_NOTIFICATIONS_REFRESH=" +
              std::to_string(enable_notification_refresh_),
          "ENABLE_PRIVACY_HUB_FOR_CHROME=" +
              std::to_string(enable_privacy_hub_for_chrome_),
          "ENABLE_TTS_CACHING=" + std::to_string(enable_tts_caching_),
          "HOST_UREADAHEAD_GENERATION=" +
              std::to_string(host_ureadahead_generation_),
      });

      if (arc_generate_pai_)
        result.emplace_back("ARC_GENERATE_PAI=1");

      if (arc_lcd_density_ >= 0) {
        result.emplace_back(
            base::StringPrintf("ARC_LCD_DENSITY=%d", arc_lcd_density_));
      }

      switch (play_store_auto_update_) {
        case arc::StartArcMiniInstanceRequest::AUTO_UPDATE_DEFAULT:
          break;
        case arc::StartArcMiniInstanceRequest::AUTO_UPDATE_ON:
          result.emplace_back("PLAY_STORE_AUTO_UPDATE=1");
          break;
        case arc::StartArcMiniInstanceRequest::AUTO_UPDATE_OFF:
          result.emplace_back("PLAY_STORE_AUTO_UPDATE=0");
          break;
        default:
          NOTREACHED();
      }

      switch (dalvik_memory_profile_) {
        case arc::StartArcMiniInstanceRequest::MEMORY_PROFILE_DEFAULT:
          break;
        case arc::StartArcMiniInstanceRequest::MEMORY_PROFILE_4G:
          result.emplace_back("DALVIK_MEMORY_PROFILE=4G");
          break;
        case arc::StartArcMiniInstanceRequest::MEMORY_PROFILE_8G:
          result.emplace_back("DALVIK_MEMORY_PROFILE=8G");
          break;
        case arc::StartArcMiniInstanceRequest::MEMORY_PROFILE_16G:
          result.emplace_back("DALVIK_MEMORY_PROFILE=16G");
          break;
        default:
          NOTREACHED();
      }

      return result;
    }

   private:
    bool dev_mode_ = false;
    bool native_bridge_experiment_ = false;
    bool arc_file_picker_experiment_ = false;
    bool arc_custom_tab_experiment_ = false;

    bool disable_media_store_maintenance_ = false;
    bool disable_download_provider_ = false;
    bool disable_ureadahead_ = false;
    bool enable_consumer_auto_update_toggle_ = false;
    bool enable_notification_refresh_ = false;
    bool enable_privacy_hub_for_chrome_ = false;
    bool enable_tts_caching_ = false;
    bool host_ureadahead_generation_ = false;
    bool arc_generate_pai_ = false;
    arc::StartArcMiniInstanceRequest_PlayStoreAutoUpdate
        play_store_auto_update_ = arc::
            StartArcMiniInstanceRequest_PlayStoreAutoUpdate_AUTO_UPDATE_DEFAULT;
    int arc_lcd_density_ = -1;
    arc::StartArcMiniInstanceRequest_DalvikMemoryProfile
        dalvik_memory_profile_ =
            arc::StartArcMiniInstanceRequest::MEMORY_PROFILE_DEFAULT;
  };

  class UpgradeContainerExpectationsBuilder {
   public:
    UpgradeContainerExpectationsBuilder() = default;
    UpgradeContainerExpectationsBuilder(
        const UpgradeContainerExpectationsBuilder&) = delete;
    UpgradeContainerExpectationsBuilder& operator=(
        const UpgradeContainerExpectationsBuilder&) = delete;

    UpgradeContainerExpectationsBuilder& SetDevMode(bool v) {
      dev_mode_ = v;
      return *this;
    }

    UpgradeContainerExpectationsBuilder& SetDisableBootCompletedCallback(
        bool v) {
      disable_boot_completed_callback_ = v;
      return *this;
    }

    UpgradeContainerExpectationsBuilder& SetIsDemoSession(bool v) {
      is_demo_session_ = v;
      return *this;
    }

    UpgradeContainerExpectationsBuilder& SetDemoSessionAppsPath(
        const std::string& v) {
      demo_session_apps_path_ = v;
      return *this;
    }

    UpgradeContainerExpectationsBuilder& SetSkipPackagesCache(bool v) {
      skip_packages_cache_ = v;
      return *this;
    }

    UpgradeContainerExpectationsBuilder& SetCopyPackagesCache(bool v) {
      copy_packages_cache_ = v;
      return *this;
    }

    UpgradeContainerExpectationsBuilder& SetSkipGmsCoreCache(bool v) {
      skip_gms_core_cache_ = v;
      return *this;
    }

    UpgradeContainerExpectationsBuilder& SetLocale(const std::string& v) {
      locale_ = v;
      return *this;
    }

    UpgradeContainerExpectationsBuilder& SetPreferredLanguages(
        const std::string& v) {
      preferred_languages_ = v;
      return *this;
    }

    UpgradeContainerExpectationsBuilder& SetEnableAdbSideload(int v) {
      enable_adb_sideload_ = v;
      return *this;
    }

    UpgradeContainerExpectationsBuilder& SetEnableArcNearbyShare(int v) {
      enable_arc_nearby_share_ = v;
      return *this;
    }

    UpgradeContainerExpectationsBuilder& SetDisableUreadahead(bool v) {
      disable_ureadahead_ = v;
      return *this;
    }

    UpgradeContainerExpectationsBuilder& SetManagementTransition(bool v) {
      management_transition_ = v;
      return *this;
    }

    UpgradeContainerExpectationsBuilder& SetSkipTtsCache(bool v) {
      skip_tts_cache_ = v;
      return *this;
    }

    std::vector<std::string> Build() const {
      return {
          "CHROMEOS_DEV_MODE=" + std::to_string(dev_mode_),
          "CHROMEOS_INSIDE_VM=0", std::string("CHROMEOS_USER=") + kSaneEmail,
          "DISABLE_BOOT_COMPLETED_BROADCAST=" +
              std::to_string(disable_boot_completed_callback_),
          // The upgrade signal has a PID.
          "CONTAINER_PID=" + std::to_string(kAndroidPid),
          "DEMO_SESSION_APPS_PATH=" + demo_session_apps_path_,
          "IS_DEMO_SESSION=" + std::to_string(is_demo_session_),
          "MANAGEMENT_TRANSITION=" + std::to_string(management_transition_),
          "ENABLE_ADB_SIDELOAD=" + std::to_string(enable_adb_sideload_),
          "ENABLE_ARC_NEARBY_SHARE=" + std::to_string(enable_arc_nearby_share_),
          "DISABLE_UREADAHEAD=" + std::to_string(disable_ureadahead_),
          ExpectedSkipPackagesCacheSetupFlagValue(skip_packages_cache_),
          ExpectedCopyPackagesCacheFlagValue(copy_packages_cache_),
          ExpectedSkipGmsCoreCacheSetupFlagValue(skip_gms_core_cache_),
          ExpectedSkipTtsCacheSetupFlagValue(skip_tts_cache_),
          "LOCALE=" + locale_, "PREFERRED_LANGUAGES=" + preferred_languages_};
    }

   private:
    bool dev_mode_ = false;
    bool disable_boot_completed_callback_ = false;
    bool is_demo_session_ = false;
    std::string demo_session_apps_path_;
    bool skip_packages_cache_ = false;
    bool copy_packages_cache_ = false;
    bool skip_gms_core_cache_ = false;
    std::string locale_ = kDefaultLocale;
    std::string preferred_languages_;
    int management_transition_ = 0;
    bool enable_adb_sideload_ = false;
    bool enable_arc_nearby_share_ = false;
    bool disable_ureadahead_ = false;
    bool skip_tts_cache_ = false;
  };
#endif

  dbus::MockExportedObject* exported_object() {
    return bus_->exported_object();
  }

  void SetDeviceMode(const std::string& mode) {
    install_attributes_reader_.SetAttributes({{"enterprise.mode", mode}});
  }

  void ExpectStartSession(const string& account_id_string) {
    ExpectSessionBoilerplate(account_id_string, false /* guest */,
                             false /* for_owner */);
  }

  void ExpectGuestSession() {
    ExpectSessionBoilerplate(*GetGuestUsername(), true /* guest */,
                             false /* for_owner */);
  }

  void ExpectStartOwnerSession(const string& account_id_string) {
    ExpectSessionBoilerplate(account_id_string, false /* guest */,
                             true /* for_owner */);
  }

  void ExpectStartSessionUnowned(const string& account_id_string) {
    ExpectStartSessionUnownedBoilerplate(account_id_string,
                                         false,  // mitigating
                                         true);  // key_gen
  }

  void ExpectStartSessionOwningInProcess(const string& account_id_string) {
    ExpectStartSessionUnownedBoilerplate(account_id_string,
                                         false,   // mitigating
                                         false);  // key_gen
  }

  void ExpectStartSessionOwnerLost(const string& account_id_string) {
    ExpectStartSessionUnownedBoilerplate(account_id_string,
                                         true,    // mitigating
                                         false);  // key_gen
  }

  void ExpectLockScreen() { expected_locks_ = 1; }

  // Since expected_restarts_ is 0 by default, ExpectDeviceRestart(0) initially
  // is equivalent to no-op. In the tests ExpectDeviceRestart(0) is used
  // to make the setup more explicit.
  void ExpectDeviceRestart(uint32_t count) { expected_restarts_ = count; }

  void ExpectStorePolicy(MockDevicePolicyService* service,
                         const std::vector<uint8_t>& policy_blob,
                         int flags) {
    EXPECT_CALL(*service,
                Store(MakeChromePolicyNamespace(), policy_blob, flags, _))
        .WillOnce(Return(true));
  }

  void ExpectNoStorePolicy(MockDevicePolicyService* service) {
    EXPECT_CALL(*service, Store(_, _, _, _)).Times(0);
  }

  void ExpectAndRunStartSession(const string& email) {
    ExpectStartSession(email);
    brillo::ErrorPtr error;
    EXPECT_TRUE(impl_->StartSession(&error, email, kNothing));
    EXPECT_FALSE(error.get());
    VerifyAndClearExpectations();
  }

  void ExpectAndRunGuestSession() {
    ExpectGuestSession();
    brillo::ErrorPtr error;
    EXPECT_TRUE(impl_->StartSession(&error, *GetGuestUsername(), kNothing));
    EXPECT_FALSE(error.get());
    VerifyAndClearExpectations();
  }

  std::unique_ptr<PolicyService> CreateUserPolicyService(
      const string& username) {
    std::unique_ptr<MockPolicyService> policy_service =
        std::make_unique<MockPolicyService>();
    user_policy_services_[username] = policy_service.get();
    return policy_service;
  }

  void SetDevicePolicy(const em::ChromeDeviceSettingsProto& settings) {
    em::PolicyData policy_data;
    CHECK(settings.SerializeToString(policy_data.mutable_policy_value()));
    CHECK(policy_data.SerializeToString(device_policy_.mutable_policy_data()));
  }

#if USE_CHEETS
  void SetUpArcMiniContainer() {
    EXPECT_CALL(*init_controller_,
                TriggerImpulse(SessionManagerImpl::kStartArcInstanceImpulse,
                               StartArcInstanceExpectationsBuilder().Build(),
                               InitDaemonController::TriggerMode::ASYNC))
        .WillOnce(Return(ByMove(dbus::Response::CreateEmpty())));

    brillo::ErrorPtr error;
    EXPECT_TRUE(impl_->StartArcMiniContainer(
        &error, SerializeAsBlob(arc::StartArcMiniInstanceRequest())));
    VerifyAndClearExpectations();
  }
#endif

  // Stores a device policy with a device local account, which should add this
  // account to SessionManagerImpl's device local account manager.
  void SetupDeviceLocalAccount(const std::string& account_id) {
    // Setup device policy with a device local account.
    em::ChromeDeviceSettingsProto settings;
    em::DeviceLocalAccountInfoProto* account =
        settings.mutable_device_local_accounts()->add_account();
    account->set_type(
        em::DeviceLocalAccountInfoProto::ACCOUNT_TYPE_PUBLIC_SESSION);
    account->set_account_id(account_id);

    // Make sure that SessionManagerImpl calls DeviceLocalAccountManager with
    // the given |settings| to initialize the account.
    SetDevicePolicy(settings);
    EXPECT_CALL(*device_policy_store_, Get()).Times(1);
    EXPECT_CALL(*exported_object(),
                SendSignal(SignalEq(
                    login_manager::kPropertyChangeCompleteSignal, "success")))
        .Times(1);
    device_policy_service_->OnPolicySuccessfullyPersisted();
    VerifyAndClearExpectations();
  }

  // Creates a policy blob that can be serialized with a real PolicyService.
  std::vector<uint8_t> CreatePolicyFetchResponseBlob() {
    em::PolicyFetchResponse policy;
    em::PolicyData policy_data;
    policy_data.set_policy_value("fake policy");
    CHECK(policy_data.SerializeToString(policy.mutable_policy_data()));
    return StringToBlob(policy.SerializeAsString());
  }

  base::FilePath GetDeviceLocalAccountPolicyPath(
      const std::string& account_id) {
    return device_local_accounts_dir_
        .Append(*SanitizeUserName(Username(account_id)))
        .Append(DeviceLocalAccountManager::kPolicyDir)
        .Append(PolicyService::kChromePolicyFileName);
  }

  void VerifyAndClearExpectations() {
    Mock::VerifyAndClearExpectations(device_policy_store_);
    Mock::VerifyAndClearExpectations(device_policy_service_);
    for (auto& entry : user_policy_services_)
      Mock::VerifyAndClearExpectations(entry.second);
    Mock::VerifyAndClearExpectations(init_controller_);
    Mock::VerifyAndClearExpectations(&manager_);
    Mock::VerifyAndClearExpectations(&metrics_);
    Mock::VerifyAndClearExpectations(&nss_);
    Mock::VerifyAndClearExpectations(&utils_);
    Mock::VerifyAndClearExpectations(exported_object());
  }

  void GotLastSyncInfo(bool network_synchronized) {
    ASSERT_FALSE(available_callback_.is_null());

    dbus::ObjectProxy::ResponseCallback time_sync_callback;
    EXPECT_CALL(*system_clock_proxy_,
                DoCallMethod(_, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT, _))
        .WillOnce(MovePointee<2>(&time_sync_callback));
    std::move(available_callback_).Run(true);
    ASSERT_TRUE(Mock::VerifyAndClearExpectations(system_clock_proxy_.get()));

    std::unique_ptr<dbus::Response> response = dbus::Response::CreateEmpty();
    dbus::MessageWriter writer(response.get());
    writer.AppendBool(network_synchronized);
    std::move(time_sync_callback).Run(response.get());
  }

  base::FilePath GetTestLoginScreenStoragePath(const std::string& key) {
    return base::FilePath(login_screen_storage_path_)
        .Append(secret_util::StringToSafeFilename(key));
  }

  // These are bare pointers, not unique_ptrs, because we need to give them
  // to a SessionManagerImpl instance, but also be able to set expectations
  // on them after we hand them off.
  // Owned by SessionManagerImpl.
  MockInitDaemonController* init_controller_ = nullptr;
  MockPolicyStore* device_policy_store_ = nullptr;
  MockDevicePolicyService* device_policy_service_ = nullptr;
  MockUserPolicyServiceFactory* user_policy_service_factory_ = nullptr;
  MockArcSideloadStatus* arc_sideload_status_ = nullptr;
  base::SimpleTestTickClock* tick_clock_ = nullptr;
  map<string, MockPolicyService*> user_policy_services_;
  em::PolicyFetchResponse device_policy_;

  scoped_refptr<FakeBus> bus_;
  MockKeyGenerator key_gen_;
  MockDeviceIdentifierGenerator device_identifier_generator_;
  MockProcessManagerService manager_;
  MockMetrics metrics_;
  MockNssUtil nss_;
  SystemUtilsImpl real_utils_;
  testing::NiceMock<MockSystemUtils> utils_;
  FakeCrossystem crossystem_;
  MockVpdProcess vpd_process_;
  MockPolicyKey owner_key_;
  FakeContainerManager android_container_;
  MockInstallAttributesReader install_attributes_reader_;

  scoped_refptr<dbus::MockObjectProxy> powerd_proxy_;
  dbus::ObjectProxy::SignalCallback suspend_imminent_callback_;
  dbus::ObjectProxy::SignalCallback suspend_done_callback_;

  scoped_refptr<dbus::MockObjectProxy> system_clock_proxy_;
  dbus::ObjectProxy::WaitForServiceToBeAvailableCallback available_callback_;

  scoped_refptr<dbus::MockObjectProxy> debugd_proxy_;
  scoped_refptr<dbus::MockObjectProxy> fwmp_proxy_;

  password_provider::FakePasswordProvider* password_provider_ = nullptr;

  base::ScopedTempDir log_dir_;  // simulates /var/log/ui
  base::FilePath log_symlink_;   // simulates ui.LATEST; not created by default

  std::unique_ptr<SessionManagerImpl> impl_;
  base::ScopedTempDir tmpdir_;
  base::FilePath device_local_accounts_dir_;
  secret_util::SharedMemoryUtil* shared_memory_util_;
  base::FilePath login_screen_storage_path_;

  static const pid_t kFakePid;
  static const char kNothing[];
  static const char kContainerInstanceId[];
  static const int kAllKeyFlags;

 private:
  // Returns a response for the given method call. Used to implement
  // CallMethodAndBlock() for |mock_proxy_|.
  std::unique_ptr<dbus::Response> CreateMockProxyResponse(
      dbus::MethodCall* method_call, int timeout_ms) {
    return dbus::Response::CreateEmpty();
  }

  void ExpectSessionBoilerplate(const string& account_id_string,
                                bool guest,
                                bool for_owner) {
    EXPECT_CALL(manager_,
                SetBrowserSessionForUser(
                    StrEq(account_id_string),
                    StrEq(*SanitizeUserName(Username(account_id_string)))))
        .Times(1);
    // Expect initialization of the device policy service, return success.
    EXPECT_CALL(*device_policy_service_, UserIsOwner)
        .WillOnce(Return(for_owner));
    if (for_owner) {
      EXPECT_CALL(*device_policy_service_,
                  HandleOwnerLogin(StrEq(account_id_string), _, _))
          .WillOnce(Return(true));
      // Confirm that the key is present.
      EXPECT_CALL(*device_policy_service_, KeyMissing())
          .Times(2)
          .WillRepeatedly(Return(false));
    }

    EXPECT_CALL(*init_controller_,
                TriggerImpulse(SessionManagerImpl::kStartUserSessionImpulse,
                               ElementsAre(StartsWith("CHROMEOS_USER=")),
                               InitDaemonController::TriggerMode::ASYNC))
        .WillOnce(Return(ByMove(nullptr)));
    EXPECT_CALL(*exported_object(),
                SendSignal(SignalEq(login_manager::kSessionStateChangedSignal,
                                    SessionManagerImpl::kStarted)))
        .Times(1);
  }

  void ExpectStartSessionUnownedBoilerplate(const string& account_id_string,
                                            bool mitigating,
                                            bool key_gen) {
    CHECK(!(mitigating && key_gen));

    EXPECT_CALL(manager_,
                SetBrowserSessionForUser(
                    StrEq(account_id_string),
                    StrEq(*SanitizeUserName(Username(account_id_string)))))
        .Times(1);

    // Expect initialization of the device policy service, return success.
    EXPECT_CALL(*device_policy_service_, UserIsOwner).WillOnce(Return(false));

    // Indicate that there is no owner key in order to trigger a new one to be
    // generated.
    EXPECT_CALL(*device_policy_service_, KeyMissing())
        .Times(2)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(*device_policy_service_, Mitigating())
        .WillRepeatedly(Return(mitigating));
    if (key_gen)
      EXPECT_CALL(key_gen_, Start(StrEq(account_id_string), _)).Times(1);
    else
      EXPECT_CALL(key_gen_, Start(_, _)).Times(0);

    EXPECT_CALL(*init_controller_,
                TriggerImpulse(SessionManagerImpl::kStartUserSessionImpulse,
                               ElementsAre(StartsWith("CHROMEOS_USER=")),
                               InitDaemonController::TriggerMode::ASYNC))
        .WillOnce(Return(ByMove(nullptr)));
    EXPECT_CALL(*exported_object(),
                SendSignal(SignalEq(login_manager::kSessionStateChangedSignal,
                                    SessionManagerImpl::kStarted)))
        .Times(1);
  }

  string fake_salt_ = "fake salt";

  base::SingleThreadTaskExecutor task_executor;

  // Used by fake closures that simulate calling chrome and powerd to lock
  // the screen and restart the device.
  uint32_t actual_locks_ = 0;
  uint32_t expected_locks_ = 0;
  uint32_t actual_restarts_ = 0;
  uint32_t expected_restarts_ = 0;
};

class SessionManagerPackagesCacheTest
    : public SessionManagerImplTest,
      public testing::WithParamInterface<
          std::tuple<arc::UpgradeArcContainerRequest_PackageCacheMode,
                     bool,
                     bool>> {
 public:
  SessionManagerPackagesCacheTest() = default;
  SessionManagerPackagesCacheTest(const SessionManagerPackagesCacheTest&) =
      delete;
  SessionManagerPackagesCacheTest& operator=(
      const SessionManagerPackagesCacheTest&) = delete;

  ~SessionManagerPackagesCacheTest() override = default;
};

class SessionManagerPlayStoreAutoUpdateTest
    : public SessionManagerImplTest,
      public testing::WithParamInterface<
          arc::StartArcMiniInstanceRequest_PlayStoreAutoUpdate> {
 public:
  SessionManagerPlayStoreAutoUpdateTest() = default;
  SessionManagerPlayStoreAutoUpdateTest(
      const SessionManagerPlayStoreAutoUpdateTest&) = delete;
  SessionManagerPlayStoreAutoUpdateTest& operator=(
      const SessionManagerPlayStoreAutoUpdateTest&) = delete;

  ~SessionManagerPlayStoreAutoUpdateTest() override = default;
};

class SessionManagerDalvikMemoryProfileTest
    : public SessionManagerImplTest,
      public testing::WithParamInterface<
          arc::StartArcMiniInstanceRequest_DalvikMemoryProfile> {
 public:
  SessionManagerDalvikMemoryProfileTest() = default;
  SessionManagerDalvikMemoryProfileTest(
      const SessionManagerDalvikMemoryProfileTest&) = delete;
  SessionManagerDalvikMemoryProfileTest& operator=(
      const SessionManagerDalvikMemoryProfileTest&) = delete;

  ~SessionManagerDalvikMemoryProfileTest() override = default;
};

const pid_t SessionManagerImplTest::kFakePid = 4;
const char SessionManagerImplTest::kNothing[] = "";
const int SessionManagerImplTest::kAllKeyFlags =
    PolicyService::KEY_ROTATE | PolicyService::KEY_INSTALL_NEW |
    PolicyService::KEY_CLOBBER;

TEST_F(SessionManagerImplTest, EmitLoginPromptVisible) {
  const char event_name[] = "login-prompt-visible";
  EXPECT_CALL(metrics_, RecordStats(StrEq(event_name))).Times(1);
  EXPECT_CALL(*exported_object(),
              SendSignal(SignalEq(login_manager::kLoginPromptVisibleSignal)))
      .Times(1);
  EXPECT_CALL(*init_controller_,
              TriggerImpulse("login-prompt-visible", ElementsAre(),
                             InitDaemonController::TriggerMode::ASYNC))
      .Times(1);
  impl_->EmitLoginPromptVisible();
}

TEST_F(SessionManagerImplTest, EmitAshInitialized) {
  EXPECT_CALL(*init_controller_,
              TriggerImpulse("ash-initialized", ElementsAre(),
                             InitDaemonController::TriggerMode::ASYNC))
      .Times(1);
  impl_->EmitAshInitialized();
}

TEST_F(SessionManagerImplTest, EnableChromeTesting) {
  std::vector<std::string> args = {"--repeat-arg", "--one-time-arg"};
  const std::vector<std::string> kEnvVars = {"FOO=", "BAR=/tmp"};

  base::FilePath temp_dir;
  ASSERT_TRUE(base::CreateNewTempDirectory("" /* ignored */, &temp_dir));

  const size_t random_suffix_len = strlen("XXXXXX");
  ASSERT_LT(random_suffix_len, temp_dir.value().size()) << temp_dir.value();

  // Check that SetBrowserTestArgs() is called with a randomly chosen
  // --testing-channel path name.
  const string expected_testing_path_prefix =
      temp_dir.value().substr(0, temp_dir.value().size() - random_suffix_len);
  EXPECT_CALL(manager_,
              SetBrowserTestArgs(ElementsAre(
                  args[0], args[1], HasSubstr(expected_testing_path_prefix))))
      .Times(1);
  EXPECT_CALL(manager_, SetBrowserAdditionalEnvironmentalVariables(
                            ElementsAre(kEnvVars[0], kEnvVars[1])))
      .Times(1);
  EXPECT_CALL(manager_, RestartBrowser()).Times(1);

  {
    brillo::ErrorPtr error;
    std::string testing_path;
    ASSERT_TRUE(impl_->EnableChromeTesting(&error, false, args, kEnvVars,
                                           &testing_path));
    EXPECT_FALSE(error.get());
    EXPECT_NE(std::string::npos,
              testing_path.find(expected_testing_path_prefix))
        << testing_path;
  }

  {
    // Calling again, without forcing relaunch, should not do anything.
    brillo::ErrorPtr error;
    std::string testing_path;
    ASSERT_TRUE(impl_->EnableChromeTesting(&error, false, args, kEnvVars,
                                           &testing_path));
    EXPECT_FALSE(error.get());
    EXPECT_NE(std::string::npos,
              testing_path.find(expected_testing_path_prefix))
        << testing_path;
  }

  // Force relaunch.  Should go through the whole path again.
  args[0] = "--some-switch";
  args[1] = "--repeat-arg";
  EXPECT_CALL(manager_,
              SetBrowserTestArgs(ElementsAre(
                  args[0], args[1], HasSubstr(expected_testing_path_prefix))))
      .Times(1);
  EXPECT_CALL(manager_, SetBrowserAdditionalEnvironmentalVariables(
                            ElementsAre(kEnvVars[0], kEnvVars[1])))
      .Times(1);
  EXPECT_CALL(manager_, RestartBrowser()).Times(1);

  {
    brillo::ErrorPtr error;
    std::string testing_path;
    ASSERT_TRUE(impl_->EnableChromeTesting(&error, true, args, kEnvVars,
                                           &testing_path));
    EXPECT_FALSE(error.get());
    EXPECT_NE(std::string::npos,
              testing_path.find(expected_testing_path_prefix))
        << testing_path;
  }
}

TEST_F(SessionManagerImplTest, StartSession) {
  ExpectStartSession(kSaneEmail);
  brillo::ErrorPtr error;
  EXPECT_TRUE(impl_->StartSession(&error, kSaneEmail, kNothing));
}

TEST_F(SessionManagerImplTest, StartSession_New) {
  ExpectStartSessionUnowned(kSaneEmail);
  brillo::ErrorPtr error;
  EXPECT_TRUE(impl_->StartSession(&error, kSaneEmail, kNothing));
}

TEST_F(SessionManagerImplTest, StartSession_InvalidUser) {
  constexpr char kBadEmail[] = "user";
  brillo::ErrorPtr error;
  EXPECT_FALSE(impl_->StartSession(&error, kBadEmail, kNothing));
  ASSERT_TRUE(error.get());
  EXPECT_EQ(dbus_error::kInvalidAccount, error->GetCode());
}

TEST_F(SessionManagerImplTest, StartSession_Twice) {
  ExpectStartSession(kSaneEmail);
  brillo::ErrorPtr error;
  EXPECT_TRUE(impl_->StartSession(&error, kSaneEmail, kNothing));
  EXPECT_FALSE(error.get());

  EXPECT_FALSE(impl_->StartSession(&error, kSaneEmail, kNothing));
  ASSERT_TRUE(error.get());
  EXPECT_EQ(dbus_error::kSessionExists, error->GetCode());
}

TEST_F(SessionManagerImplTest, StartSession_TwoUsers) {
  ExpectStartSession(kSaneEmail);
  brillo::ErrorPtr error;
  EXPECT_TRUE(impl_->StartSession(&error, kSaneEmail, kNothing));
  EXPECT_FALSE(error.get());
  VerifyAndClearExpectations();

  constexpr char kEmail2[] = "user2@somewhere";
  ExpectStartSession(kEmail2);
  EXPECT_TRUE(impl_->StartSession(&error, kEmail2, kNothing));
  EXPECT_FALSE(error.get());
}

TEST_F(SessionManagerImplTest, StartSession_TwoUsers_MultiUserSession) {
  // Test that starting an extra session on top of the primary user i.e.
  // multi-user session, results in calling of |SetMultiUserSessionStarted()|.
  brillo::ErrorPtr error;
  EXPECT_TRUE(impl_->StartSession(&error, kSaneEmail, kNothing));
  EXPECT_FALSE(error.get());

  EXPECT_CALL(manager_, SetMultiUserSessionStarted());
  constexpr char kEmail2[] = "user2@somewhere";
  EXPECT_TRUE(impl_->StartSession(&error, kEmail2, kNothing));
  EXPECT_FALSE(error.get());
  VerifyAndClearExpectations();
}

TEST_F(SessionManagerImplTest, StartSession_OwnerAndOther) {
  ExpectStartSessionUnowned(kSaneEmail);
  brillo::ErrorPtr error;
  EXPECT_TRUE(impl_->StartSession(&error, kSaneEmail, kNothing));
  EXPECT_FALSE(error.get());
  VerifyAndClearExpectations();

  constexpr char kEmail2[] = "user2@somewhere";
  ExpectStartSession(kEmail2);
  EXPECT_TRUE(impl_->StartSession(&error, kEmail2, kNothing));
  EXPECT_FALSE(error.get());
}

TEST_F(SessionManagerImplTest, StartSession_OwnerRace) {
  ExpectStartSessionUnowned(kSaneEmail);
  brillo::ErrorPtr error;
  EXPECT_TRUE(impl_->StartSession(&error, kSaneEmail, kNothing));
  EXPECT_FALSE(error.get());
  VerifyAndClearExpectations();

  constexpr char kEmail2[] = "user2@somewhere";
  ExpectStartSessionOwningInProcess(kEmail2);
  EXPECT_TRUE(impl_->StartSession(&error, kEmail2, kNothing));
  EXPECT_FALSE(error.get());
}

TEST_F(SessionManagerImplTest, StartSession_BadNssDB) {
  nss_.MakeBadDB();
  // Force SessionManagerImpl to attempt opening the NSS database.
  EXPECT_CALL(*device_policy_service_, KeyMissing).WillOnce(Return(true));
  brillo::ErrorPtr error;
  EXPECT_FALSE(impl_->StartSession(&error, kSaneEmail, kNothing));
  ASSERT_TRUE(error.get());
  EXPECT_EQ(dbus_error::kNoUserNssDb, error->GetCode());
}

TEST_F(SessionManagerImplTest, StartSession_DevicePolicyFailure) {
  EXPECT_CALL(*device_policy_service_, UserIsOwner).WillOnce(Return(true));
  // Upon the owner login check, return an error.
  EXPECT_CALL(*device_policy_service_,
              HandleOwnerLogin(StrEq(kSaneEmail), _, _))
      .WillOnce(WithArg<2>(Invoke([](brillo::ErrorPtr* error) {
        *error = CreateError(dbus_error::kPubkeySetIllegal, "test");
        return false;
      })));

  brillo::ErrorPtr error;
  EXPECT_FALSE(impl_->StartSession(&error, kSaneEmail, kNothing));
  ASSERT_TRUE(error.get());
}

TEST_F(SessionManagerImplTest, StartSession_Owner) {
  ExpectStartOwnerSession(kSaneEmail);
  brillo::ErrorPtr error;
  EXPECT_TRUE(impl_->StartSession(&error, kSaneEmail, kNothing));
  EXPECT_FALSE(error.get());
}

TEST_F(SessionManagerImplTest, StartSession_KeyMitigation) {
  ExpectStartSessionOwnerLost(kSaneEmail);
  brillo::ErrorPtr error;
  EXPECT_TRUE(impl_->StartSession(&error, kSaneEmail, kNothing));
  EXPECT_FALSE(error.get());
}

TEST_F(SessionManagerImplTest, SaveLoginPassword) {
  const string kPassword("thepassword");
  base::ScopedFD password_fd = secret_util::WriteSizeAndDataToPipe(
      std::vector<uint8_t>(kPassword.begin(), kPassword.end()));
  brillo::ErrorPtr error;
  EXPECT_TRUE(impl_->SaveLoginPassword(&error, password_fd));
  EXPECT_FALSE(error.get());

  EXPECT_TRUE(password_provider_->password_saved());
}

TEST_F(SessionManagerImplTest, DiscardPasswordOnStopSession) {
  impl_->StopSessionWithReason(
      static_cast<uint32_t>(SessionStopReason::RESTORE_ACTIVE_SESSIONS));
  EXPECT_TRUE(password_provider_->password_discarded());
}

TEST_F(SessionManagerImplTest, StopSession) {
  EXPECT_CALL(manager_, ScheduleShutdown()).Times(1);
  impl_->StopSessionWithReason(
      static_cast<uint32_t>(SessionStopReason::RESTORE_ACTIVE_SESSIONS));
}

TEST_F(SessionManagerImplTest, LoadShillProfile) {
  EXPECT_CALL(*init_controller_,
              TriggerImpulse(SessionManagerImpl::kLoadShillProfileImpulse,
                             ElementsAre(StartsWith("CHROMEOS_USER=")),
                             InitDaemonController::TriggerMode::ASYNC))
      .WillOnce(Return(ByMove(nullptr)));
  {
    brillo::ErrorPtr error;
    EXPECT_TRUE(impl_->LoadShillProfile(&error, kSaneEmail));
    EXPECT_FALSE(error.get());
  }
}

TEST_F(SessionManagerImplTest, LoginScreenStorage_StoreEphemeral) {
  const string kTestKey("testkey");
  const string kTestValue("testvalue");
  const vector<uint8_t> kTestValueVector =
      std::vector<uint8_t>(kTestValue.begin(), kTestValue.end());
  auto value_fd =
      shared_memory_util_->WriteDataToSharedMemory(kTestValueVector);

  ExpectAndRunStartSession(kSaneEmail);

  brillo::ErrorPtr error;
  impl_->LoginScreenStorageStore(
      &error, kTestKey,
      MakeLoginScreenStorageMetadata(/*clear_on_session_exit=*/true),
      kTestValue.size(), value_fd);
  EXPECT_FALSE(error.get());
  EXPECT_FALSE(base::PathExists(GetTestLoginScreenStoragePath(kTestKey)));

  base::ScopedFD out_value_fd;
  uint64_t out_value_size;
  impl_->LoginScreenStorageRetrieve(&error, kTestKey, &out_value_size,
                                    &out_value_fd);
  EXPECT_FALSE(error.get());
  std::vector<uint8_t> out_value;
  EXPECT_TRUE(shared_memory_util_->ReadDataFromSharedMemory(
      out_value_fd, out_value_size, &out_value));
  EXPECT_EQ(out_value,
            std::vector<uint8_t>(kTestValue.begin(), kTestValue.end()));
}

TEST_F(SessionManagerImplTest, LoginScreenStorage_StorePersistent) {
  const string kTestKey("testkey");
  const string kTestValue("testvalue");
  const vector<uint8_t> kTestValueVector =
      std::vector<uint8_t>(kTestValue.begin(), kTestValue.end());
  auto value_fd =
      shared_memory_util_->WriteDataToSharedMemory(kTestValueVector);

  brillo::ErrorPtr error;
  impl_->LoginScreenStorageStore(
      &error, kTestKey,
      MakeLoginScreenStorageMetadata(/*clear_on_session_exit=*/false),
      kTestValue.size(), value_fd);
  EXPECT_FALSE(error.get());
  EXPECT_TRUE(base::PathExists(GetTestLoginScreenStoragePath(kTestKey)));

  base::ScopedFD out_value_fd;
  uint64_t out_value_size;
  impl_->LoginScreenStorageRetrieve(&error, kTestKey, &out_value_size,
                                    &out_value_fd);
  EXPECT_FALSE(error.get());
  std::vector<uint8_t> out_value;
  EXPECT_TRUE(shared_memory_util_->ReadDataFromSharedMemory(
      out_value_fd, out_value_size, &out_value));
  EXPECT_EQ(out_value,
            std::vector<uint8_t>(kTestValue.begin(), kTestValue.end()));
}

TEST_F(SessionManagerImplTest,
       LoginScreenStorage_StorePersistentFailsInSession) {
  const string kTestKey("testkey");
  const string kTestValue("testvalue");
  const vector<uint8_t> kTestValueVector =
      std::vector<uint8_t>(kTestValue.begin(), kTestValue.end());
  auto value_fd =
      shared_memory_util_->WriteDataToSharedMemory(kTestValueVector);

  ExpectAndRunStartSession(kSaneEmail);

  brillo::ErrorPtr error;
  impl_->LoginScreenStorageStore(
      &error, kTestKey,
      MakeLoginScreenStorageMetadata(/*clear_on_session_exit=*/false),
      kTestValue.size(), value_fd);
  EXPECT_TRUE(error.get());
  EXPECT_FALSE(base::PathExists(GetTestLoginScreenStoragePath(kTestKey)));
  base::ScopedFD out_value_fd;
  uint64_t out_value_size;
  impl_->LoginScreenStorageRetrieve(&error, kTestKey, &out_value_size,
                                    &out_value_fd);
  EXPECT_TRUE(error.get());
}

TEST_F(SessionManagerImplTest, StorePolicyEx_NoSession) {
  const std::vector<uint8_t> policy_blob = StringToBlob("fake policy");
  ExpectStorePolicy(device_policy_service_, policy_blob, kAllKeyFlags);
  ResponseCapturer capturer;
  impl_->StorePolicyEx(
      capturer.CreateMethodResponse<>(),
      MakePolicyDescriptor(ACCOUNT_TYPE_DEVICE, kEmptyAccountId), policy_blob);
}

TEST_F(SessionManagerImplTest, StorePolicyEx_SessionStarted) {
  ExpectAndRunStartSession(kSaneEmail);
  const std::vector<uint8_t> policy_blob = StringToBlob("fake policy");
  ExpectStorePolicy(device_policy_service_, policy_blob,
                    PolicyService::KEY_ROTATE | PolicyService::KEY_INSTALL_NEW);

  ResponseCapturer capturer;
  impl_->StorePolicyEx(
      capturer.CreateMethodResponse<>(),
      MakePolicyDescriptor(ACCOUNT_TYPE_DEVICE, kEmptyAccountId), policy_blob);
}

TEST_F(SessionManagerImplTest, RetrievePolicyEx) {
  const std::vector<uint8_t> policy_blob = StringToBlob("fake policy");
  EXPECT_CALL(*device_policy_service_, Retrieve(MakeChromePolicyNamespace(), _))
      .WillOnce(DoAll(SetArgPointee<1>(policy_blob), Return(true)));
  std::vector<uint8_t> out_blob;
  brillo::ErrorPtr error;
  EXPECT_TRUE(impl_->RetrievePolicyEx(
      &error, MakePolicyDescriptor(ACCOUNT_TYPE_DEVICE, kEmptyAccountId),
      &out_blob));
  EXPECT_FALSE(error.get());
  EXPECT_EQ(policy_blob, out_blob);
}

TEST_F(SessionManagerImplTest, ListStoredComponentPolicies) {
  // Create a descriptor to query component ids.
  // Note: The component_id() field must be empty for this!
  PolicyDescriptor descriptor;
  descriptor.set_account_type(ACCOUNT_TYPE_DEVICE);
  descriptor.set_account_id(kEmptyAccountId);
  descriptor.set_domain(POLICY_DOMAIN_SIGNIN_EXTENSIONS);
  std::vector<uint8_t> descriptor_blob =
      StringToBlob(descriptor.SerializeAsString());

  // Tell the mock store to return some component ids for ListComponentIds.
  std::vector<std::string> expected_component_ids({"id1", "id2"});
  EXPECT_CALL(*device_policy_service_, ListComponentIds(descriptor.domain()))
      .WillOnce(Return(expected_component_ids));

  // Query component ids and validate the result.
  brillo::ErrorPtr error;
  std::vector<std::string> component_ids;
  EXPECT_TRUE(impl_->ListStoredComponentPolicies(&error, descriptor_blob,
                                                 &component_ids));
  EXPECT_FALSE(error.get());
  EXPECT_EQ(expected_component_ids, component_ids);
}

TEST_F(SessionManagerImplTest, GetServerBackedStateKeys_TimeSync) {
  EXPECT_CALL(device_identifier_generator_, RequestStateKeys(_));

  ResponseCapturer capturer;
  impl_->GetServerBackedStateKeys(
      capturer.CreateMethodResponse<std::vector<std::vector<uint8_t>>>());
  ASSERT_NO_FATAL_FAILURE(GotLastSyncInfo(true));
}

TEST_F(SessionManagerImplTest, GetServerBackedStateKeys_NoTimeSync) {
  EXPECT_CALL(device_identifier_generator_, RequestStateKeys(_)).Times(0);
  ResponseCapturer capturer;
  impl_->GetServerBackedStateKeys(
      capturer.CreateMethodResponse<std::vector<std::vector<uint8_t>>>());
}

TEST_F(SessionManagerImplTest, GetServerBackedStateKeys_TimeSyncDoneBefore) {
  ASSERT_NO_FATAL_FAILURE(GotLastSyncInfo(true));

  EXPECT_CALL(device_identifier_generator_, RequestStateKeys(_));
  ResponseCapturer capturer;
  impl_->GetServerBackedStateKeys(
      capturer.CreateMethodResponse<std::vector<std::vector<uint8_t>>>());
}

TEST_F(SessionManagerImplTest, GetServerBackedStateKeys_FailedTimeSync) {
  ASSERT_NO_FATAL_FAILURE(GotLastSyncInfo(false));

  EXPECT_CALL(device_identifier_generator_, RequestStateKeys(_)).Times(0);
  ResponseCapturer capturer;
  impl_->GetServerBackedStateKeys(
      capturer.CreateMethodResponse<std::vector<std::vector<uint8_t>>>());

  EXPECT_CALL(*system_clock_proxy_,
              DoCallMethod(_, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT, _))
      .Times(1);
  base::RunLoop().RunUntilIdle();
}

TEST_F(SessionManagerImplTest, GetServerBackedStateKeys_TimeSyncAfterFail) {
  ASSERT_NO_FATAL_FAILURE(GotLastSyncInfo(false));

  ResponseCapturer capturer;
  impl_->GetServerBackedStateKeys(
      capturer.CreateMethodResponse<std::vector<std::vector<uint8_t>>>());

  dbus::ObjectProxy::ResponseCallback time_sync_callback;
  EXPECT_CALL(*system_clock_proxy_,
              DoCallMethod(_, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT, _))
      .WillOnce(MovePointee<2>(&time_sync_callback));
  base::RunLoop().RunUntilIdle();
  ASSERT_TRUE(Mock::VerifyAndClearExpectations(system_clock_proxy_.get()));
  ASSERT_FALSE(time_sync_callback.is_null());

  EXPECT_CALL(device_identifier_generator_, RequestStateKeys(_)).Times(1);
  std::unique_ptr<dbus::Response> response = dbus::Response::CreateEmpty();
  dbus::MessageWriter writer(response.get());
  writer.AppendBool(true);
  std::move(time_sync_callback).Run(response.get());
}

TEST_F(SessionManagerImplTest, GetPsmDeviceActiveSecretSuccess) {
  EXPECT_CALL(device_identifier_generator_, RequestPsmDeviceActiveSecret(_));
  ResponseCapturer capturer;
  impl_->GetPsmDeviceActiveSecret(capturer.CreateMethodResponse<std::string>());
}

TEST_F(SessionManagerImplTest, StoreUserPolicyEx_NoSession) {
  const std::vector<uint8_t> policy_blob = StringToBlob("fake policy");

  ResponseCapturer capturer;
  impl_->StorePolicyEx(capturer.CreateMethodResponse<>(),
                       MakePolicyDescriptor(ACCOUNT_TYPE_USER, kSaneEmail),
                       policy_blob);
  ASSERT_TRUE(capturer.response());
  EXPECT_EQ(dbus_error::kGetServiceFail, capturer.response()->GetErrorName());
}

TEST_F(SessionManagerImplTest, StoreUserPolicyEx_SessionStarted) {
  ExpectAndRunStartSession(kSaneEmail);
  const std::vector<uint8_t> policy_blob = StringToBlob("fake policy");
  EXPECT_CALL(
      *user_policy_services_[kSaneEmail],
      Store(MakeChromePolicyNamespace(), policy_blob,
            PolicyService::KEY_ROTATE | PolicyService::KEY_INSTALL_NEW, _))
      .WillOnce(Return(true));

  ResponseCapturer capturer;
  impl_->StorePolicyEx(capturer.CreateMethodResponse<>(),
                       MakePolicyDescriptor(ACCOUNT_TYPE_USER, kSaneEmail),
                       policy_blob);
}

TEST_F(SessionManagerImplTest, StoreUserPolicyEx_SecondSession) {
  ExpectAndRunStartSession(kSaneEmail);
  ASSERT_TRUE(user_policy_services_[kSaneEmail]);

  // Store policy for the signed-in user.
  const std::vector<uint8_t> policy_blob = StringToBlob("fake policy");
  EXPECT_CALL(
      *user_policy_services_[kSaneEmail],
      Store(MakeChromePolicyNamespace(), policy_blob,
            PolicyService::KEY_ROTATE | PolicyService::KEY_INSTALL_NEW, _))
      .WillOnce(Return(true));

  {
    ResponseCapturer capturer;
    impl_->StorePolicyEx(capturer.CreateMethodResponse<>(),
                         MakePolicyDescriptor(ACCOUNT_TYPE_USER, kSaneEmail),
                         policy_blob);
    Mock::VerifyAndClearExpectations(user_policy_services_[kSaneEmail]);
  }

  // Storing policy for another username fails before their session starts.
  constexpr char kEmail2[] = "user2@somewhere.com";
  {
    ResponseCapturer capturer;
    impl_->StorePolicyEx(capturer.CreateMethodResponse<>(),
                         MakePolicyDescriptor(ACCOUNT_TYPE_USER, kEmail2),
                         policy_blob);
    ASSERT_TRUE(capturer.response());
    EXPECT_EQ(dbus_error::kGetServiceFail, capturer.response()->GetErrorName());
  }

  // Now start another session for the 2nd user.
  ExpectAndRunStartSession(kEmail2);
  ASSERT_TRUE(user_policy_services_[kEmail2]);

  // Storing policy for that user now succeeds.
  EXPECT_CALL(
      *user_policy_services_[kEmail2],
      Store(MakeChromePolicyNamespace(), policy_blob,
            PolicyService::KEY_ROTATE | PolicyService::KEY_INSTALL_NEW, _))
      .WillOnce(Return(true));
  {
    ResponseCapturer capturer;
    impl_->StorePolicyEx(capturer.CreateMethodResponse<>(),
                         MakePolicyDescriptor(ACCOUNT_TYPE_USER, kEmail2),
                         policy_blob);
  }
  Mock::VerifyAndClearExpectations(user_policy_services_[kEmail2]);
}

TEST_F(SessionManagerImplTest, RetrieveUserPolicyEx_NoSession) {
  std::vector<uint8_t> out_blob;
  brillo::ErrorPtr error;
  EXPECT_FALSE(impl_->RetrievePolicyEx(
      &error, MakePolicyDescriptor(ACCOUNT_TYPE_USER, kSaneEmail), &out_blob));
  ASSERT_TRUE(error.get());
  EXPECT_EQ(dbus_error::kSigEncodeFail, error->GetCode());
}

TEST_F(SessionManagerImplTest, RetrieveUserPolicyEx_SessionStarted) {
  ExpectAndRunStartSession(kSaneEmail);
  const std::vector<uint8_t> policy_blob = StringToBlob("fake policy");
  EXPECT_CALL(*user_policy_services_[kSaneEmail],
              Retrieve(MakeChromePolicyNamespace(), _))
      .WillOnce(DoAll(SetArgPointee<1>(policy_blob), Return(true)));

  std::vector<uint8_t> out_blob;
  brillo::ErrorPtr error;
  EXPECT_TRUE(impl_->RetrievePolicyEx(
      &error, MakePolicyDescriptor(ACCOUNT_TYPE_USER, kSaneEmail), &out_blob));
  EXPECT_FALSE(error.get());
  EXPECT_EQ(policy_blob, out_blob);
}

TEST_F(SessionManagerImplTest, RetrieveUserPolicyEx_SecondSession) {
  ExpectAndRunStartSession(kSaneEmail);
  ASSERT_TRUE(user_policy_services_[kSaneEmail]);

  // Retrieve policy for the signed-in user.
  const std::vector<uint8_t> policy_blob = StringToBlob("fake policy");
  EXPECT_CALL(*user_policy_services_[kSaneEmail],
              Retrieve(MakeChromePolicyNamespace(), _))
      .WillOnce(DoAll(SetArgPointee<1>(policy_blob), Return(true)));
  {
    std::vector<uint8_t> out_blob;
    brillo::ErrorPtr error;
    EXPECT_TRUE(impl_->RetrievePolicyEx(
        &error, MakePolicyDescriptor(ACCOUNT_TYPE_USER, kSaneEmail),
        &out_blob));
    EXPECT_FALSE(error.get());
    Mock::VerifyAndClearExpectations(user_policy_services_[kSaneEmail]);
    EXPECT_EQ(policy_blob, out_blob);
  }

  // Retrieving policy for another username fails before their session starts.
  constexpr char kEmail2[] = "user2@somewhere.com";
  {
    std::vector<uint8_t> out_blob;
    brillo::ErrorPtr error;
    EXPECT_FALSE(impl_->RetrievePolicyEx(
        &error, MakePolicyDescriptor(ACCOUNT_TYPE_USER, kEmail2), &out_blob));
    ASSERT_TRUE(error.get());
    EXPECT_EQ(dbus_error::kSigEncodeFail, error->GetCode());
  }

  // Now start another session for the 2nd user.
  ExpectAndRunStartSession(kEmail2);
  ASSERT_TRUE(user_policy_services_[kEmail2]);

  // Retrieving policy for that user now succeeds.
  EXPECT_CALL(*user_policy_services_[kEmail2],
              Retrieve(MakeChromePolicyNamespace(), _))
      .WillOnce(DoAll(SetArgPointee<1>(policy_blob), Return(true)));
  {
    std::vector<uint8_t> out_blob;
    brillo::ErrorPtr error;
    EXPECT_TRUE(impl_->RetrievePolicyEx(
        &error, MakePolicyDescriptor(ACCOUNT_TYPE_USER, kEmail2), &out_blob));
    EXPECT_FALSE(error.get());
    Mock::VerifyAndClearExpectations(user_policy_services_[kEmail2]);
    EXPECT_EQ(policy_blob, out_blob);
  }
}

TEST_F(SessionManagerImplTest, StoreDeviceLocalAccountPolicyNoAccount) {
  const std::vector<uint8_t> policy_blob = CreatePolicyFetchResponseBlob();
  base::FilePath policy_path = GetDeviceLocalAccountPolicyPath(kSaneEmail);

  ResponseCapturer capturer;
  impl_->StorePolicyEx(
      capturer.CreateMethodResponse<>(),
      MakePolicyDescriptor(ACCOUNT_TYPE_DEVICE_LOCAL_ACCOUNT, kSaneEmail),
      policy_blob);
  ASSERT_TRUE(capturer.response());
  EXPECT_EQ(dbus_error::kGetServiceFail, capturer.response()->GetErrorName());
  VerifyAndClearExpectations();

  EXPECT_FALSE(base::PathExists(policy_path));
}

TEST_F(SessionManagerImplTest, StoreDeviceLocalAccountPolicySuccess) {
  const std::vector<uint8_t> policy_blob = CreatePolicyFetchResponseBlob();
  base::FilePath policy_path = GetDeviceLocalAccountPolicyPath(kSaneEmail);
  SetupDeviceLocalAccount(kSaneEmail);
  EXPECT_FALSE(base::PathExists(policy_path));
  EXPECT_CALL(owner_key_, Verify(_, _, _)).WillOnce(Return(true));

  brillo::FakeMessageLoop io_loop(nullptr);
  io_loop.SetAsCurrent();

  ResponseCapturer capturer;
  impl_->StorePolicyEx(
      capturer.CreateMethodResponse<>(),
      MakePolicyDescriptor(ACCOUNT_TYPE_DEVICE_LOCAL_ACCOUNT, kSaneEmail),
      policy_blob);
  VerifyAndClearExpectations();

  io_loop.Run();
  EXPECT_TRUE(base::PathExists(policy_path));
}

TEST_F(SessionManagerImplTest, RetrieveDeviceLocalAccountPolicyNoAccount) {
  std::vector<uint8_t> out_blob;
  brillo::ErrorPtr error;
  EXPECT_FALSE(impl_->RetrievePolicyEx(
      &error,
      MakePolicyDescriptor(ACCOUNT_TYPE_DEVICE_LOCAL_ACCOUNT, kSaneEmail),
      &out_blob));
  ASSERT_TRUE(error.get());
  EXPECT_EQ(dbus_error::kSigEncodeFail, error->GetCode());
}

TEST_F(SessionManagerImplTest, RetrieveDeviceLocalAccountPolicySuccess) {
  const std::vector<uint8_t> policy_blob = CreatePolicyFetchResponseBlob();
  base::FilePath policy_path = GetDeviceLocalAccountPolicyPath(kSaneEmail);
  SetupDeviceLocalAccount(kSaneEmail);
  ASSERT_TRUE(base::CreateDirectory(policy_path.DirName()));
  ASSERT_TRUE(WriteBlobToFile(policy_path, policy_blob));

  std::vector<uint8_t> out_blob;
  brillo::ErrorPtr error;
  EXPECT_TRUE(impl_->RetrievePolicyEx(
      &error,
      MakePolicyDescriptor(ACCOUNT_TYPE_DEVICE_LOCAL_ACCOUNT, kSaneEmail),
      &out_blob));
  EXPECT_FALSE(error.get());
  EXPECT_EQ(policy_blob, out_blob);
}

TEST_F(SessionManagerImplTest, RetrieveActiveSessions) {
  ExpectStartSession(kSaneEmail);
  {
    brillo::ErrorPtr error;
    EXPECT_TRUE(impl_->StartSession(&error, kSaneEmail, kNothing));
    EXPECT_FALSE(error.get());
  }
  {
    std::map<std::string, std::string> active_users =
        impl_->RetrieveActiveSessions();
    EXPECT_EQ(active_users.size(), 1);
    EXPECT_EQ(active_users[kSaneEmail],
              *SanitizeUserName(Username(kSaneEmail)));
  }
  VerifyAndClearExpectations();

  constexpr char kEmail2[] = "user2@somewhere";
  ExpectStartSession(kEmail2);
  {
    brillo::ErrorPtr error;
    EXPECT_TRUE(impl_->StartSession(&error, kEmail2, kNothing));
    EXPECT_FALSE(error.get());
  }
  {
    std::map<std::string, std::string> active_users =
        impl_->RetrieveActiveSessions();
    EXPECT_EQ(active_users.size(), 2);
    EXPECT_EQ(active_users[kSaneEmail],
              *SanitizeUserName(Username(kSaneEmail)));
    EXPECT_EQ(active_users[kEmail2], *SanitizeUserName(Username(kEmail2)));
  }
}

TEST_F(SessionManagerImplTest, RetrievePrimarySession) {
  ExpectGuestSession();
  {
    brillo::ErrorPtr error;
    EXPECT_TRUE(impl_->StartSession(&error, *GetGuestUsername(), kNothing));
    EXPECT_FALSE(error.get());
  }
  {
    std::string username;
    std::string sanitized_username;
    impl_->RetrievePrimarySession(&username, &sanitized_username);
    EXPECT_EQ(username, "");
    EXPECT_EQ(sanitized_username, "");
  }
  VerifyAndClearExpectations();

  ExpectStartSession(kSaneEmail);
  {
    brillo::ErrorPtr error;
    EXPECT_TRUE(impl_->StartSession(&error, kSaneEmail, kNothing));
    EXPECT_FALSE(error.get());
  }
  {
    std::string username;
    std::string sanitized_username;
    impl_->RetrievePrimarySession(&username, &sanitized_username);
    EXPECT_EQ(username, kSaneEmail);
    EXPECT_EQ(sanitized_username, *SanitizeUserName(Username(kSaneEmail)));
  }
  VerifyAndClearExpectations();

  constexpr char kEmail2[] = "user2@somewhere";
  ExpectStartSession(kEmail2);
  {
    brillo::ErrorPtr error;
    EXPECT_TRUE(impl_->StartSession(&error, kEmail2, kNothing));
    EXPECT_FALSE(error.get());
  }
  {
    std::string username;
    std::string sanitized_username;
    impl_->RetrievePrimarySession(&username, &sanitized_username);
    EXPECT_EQ(username, kSaneEmail);
    EXPECT_EQ(sanitized_username, *SanitizeUserName(Username(kSaneEmail)));
  }
}

TEST_F(SessionManagerImplTest, IsGuestSessionActive) {
  EXPECT_FALSE(impl_->IsGuestSessionActive());
  ExpectAndRunGuestSession();
  EXPECT_TRUE(impl_->IsGuestSessionActive());
  ExpectAndRunStartSession(kSaneEmail);
  EXPECT_FALSE(impl_->IsGuestSessionActive());
}

TEST_F(SessionManagerImplTest, RestartJobBadSocket) {
  brillo::ErrorPtr error;
  auto mode = static_cast<uint32_t>(SessionManagerImpl::RestartJobMode::kGuest);
  EXPECT_FALSE(impl_->RestartJob(&error, base::ScopedFD(), {}, mode));
  ASSERT_TRUE(error.get());
  EXPECT_EQ(dbus_error::kGetPeerCredsFailed, error->GetCode());
}

TEST_F(SessionManagerImplTest, RestartJobBadPid) {
  base::ScopedFD fd0_closer, fd1;
  EXPECT_TRUE(CreateSocketPair(&fd0_closer, &fd1));

  EXPECT_CALL(manager_, IsBrowser(getpid())).WillRepeatedly(Return(false));
  brillo::ErrorPtr error;
  auto mode = static_cast<uint32_t>(SessionManagerImpl::RestartJobMode::kGuest);
  EXPECT_FALSE(impl_->RestartJob(&error, fd1, {}, mode));
  ASSERT_TRUE(error.get());
  EXPECT_EQ(dbus_error::kUnknownPid, error->GetCode());
}

TEST_F(SessionManagerImplTest, RestartJobGuestFailure) {
  const std::vector<std::string> argv(std::begin(kUserlessArgv),
                                      std::end(kUserlessArgv));

  base::ScopedFD fd0_closer, fd1;
  EXPECT_TRUE(CreateSocketPair(&fd0_closer, &fd1));

  EXPECT_CALL(manager_, IsBrowser(getpid())).WillRepeatedly(Return(true));
  brillo::ErrorPtr error;
  auto mode = static_cast<uint32_t>(SessionManagerImpl::RestartJobMode::kGuest);
  EXPECT_FALSE(impl_->RestartJob(&error, fd1, argv, mode));
  EXPECT_EQ(dbus_error::kInvalidParameter, error->GetCode());
}

TEST_F(SessionManagerImplTest, RestartJobModeMismatch) {
  const std::vector<std::string> argv(std::begin(kGuestArgv),
                                      std::end(kGuestArgv));

  base::ScopedFD fd0_closer, fd1;
  EXPECT_TRUE(CreateSocketPair(&fd0_closer, &fd1));

  EXPECT_CALL(manager_, IsBrowser(getpid())).WillRepeatedly(Return(true));
  brillo::ErrorPtr error;
  auto mode =
      static_cast<uint32_t>(SessionManagerImpl::RestartJobMode::kUserless);
  EXPECT_FALSE(impl_->RestartJob(&error, fd1, argv, mode));
  EXPECT_EQ(dbus_error::kInvalidParameter, error->GetCode());
}

TEST_F(SessionManagerImplTest, RestartJobSuccess) {
  const std::vector<std::string> argv(std::begin(kGuestArgv),
                                      std::end(kGuestArgv));

  base::ScopedFD fd0_closer, fd1;
  EXPECT_TRUE(CreateSocketPair(&fd0_closer, &fd1));

  EXPECT_CALL(manager_, IsBrowser(getpid())).WillRepeatedly(Return(true));
  EXPECT_CALL(manager_, SetBrowserArgs(ElementsAreArray(argv))).Times(1);
  EXPECT_CALL(manager_, RestartBrowser()).Times(1);
  ExpectGuestSession();

  brillo::ErrorPtr error;
  auto mode = static_cast<uint32_t>(SessionManagerImpl::RestartJobMode::kGuest);
  EXPECT_TRUE(impl_->RestartJob(&error, fd1, argv, mode));
  EXPECT_FALSE(error.get());
}

TEST_F(SessionManagerImplTest, RestartJobUserlessSuccess) {
  const std::vector<std::string> argv(std::begin(kUserlessArgv),
                                      std::end(kUserlessArgv));

  base::ScopedFD fd0_closer, fd1;
  EXPECT_TRUE(CreateSocketPair(&fd0_closer, &fd1));

  EXPECT_CALL(manager_, IsBrowser(getpid())).WillRepeatedly(Return(true));
  EXPECT_CALL(manager_, SetBrowserArgs(ElementsAreArray(argv))).Times(1);
  EXPECT_CALL(manager_, RestartBrowser()).Times(1);

  brillo::ErrorPtr error;
  auto mode =
      static_cast<uint32_t>(SessionManagerImpl::RestartJobMode::kUserless);
  EXPECT_TRUE(impl_->RestartJob(&error, fd1, argv, mode));
  EXPECT_FALSE(error.get());
}

TEST_F(SessionManagerImplTest, RestartJobForNonGuestUserFailure) {
  const std::vector<std::string> argv(std::begin(kUserlessArgv),
                                      std::end(kUserlessArgv));

  // Start session.
  ExpectStartSession(kSaneEmail);
  brillo::ErrorPtr error;
  EXPECT_TRUE(impl_->StartSession(&error, kSaneEmail, kNothing));

  base::ScopedFD fd0_closer, fd1;
  EXPECT_TRUE(CreateSocketPair(&fd0_closer, &fd1));

  EXPECT_CALL(manager_, IsBrowser(getpid())).WillRepeatedly(Return(true));

  auto mode =
      static_cast<uint32_t>(SessionManagerImpl::RestartJobMode::kUserless);
  EXPECT_FALSE(impl_->RestartJob(&error, fd1, argv, mode));
  EXPECT_TRUE(error.get());
  EXPECT_EQ(dbus_error::kInvalidParameter, error->GetCode());
}

TEST_F(SessionManagerImplTest, SupervisedUserCreation) {
  impl_->HandleSupervisedUserCreationStarting();
  EXPECT_TRUE(impl_->ShouldEndSession(nullptr));
  impl_->HandleSupervisedUserCreationFinished();
  EXPECT_FALSE(impl_->ShouldEndSession(nullptr));
}

TEST_F(SessionManagerImplTest, LockScreen) {
  ExpectAndRunStartSession(kSaneEmail);
  ExpectLockScreen();
  brillo::ErrorPtr error;
  EXPECT_TRUE(impl_->LockScreen(&error));
  EXPECT_FALSE(error.get());
  EXPECT_TRUE(impl_->ShouldEndSession(nullptr));
}

TEST_F(SessionManagerImplTest, LockScreen_DuringSupervisedUserCreation) {
  ExpectAndRunStartSession(kSaneEmail);
  ExpectLockScreen();
  EXPECT_CALL(*exported_object(), SendSignal(_)).Times(AnyNumber());

  impl_->HandleSupervisedUserCreationStarting();
  EXPECT_TRUE(impl_->ShouldEndSession(nullptr));
  brillo::ErrorPtr error;
  EXPECT_TRUE(impl_->LockScreen(&error));
  EXPECT_FALSE(error.get());
  EXPECT_TRUE(impl_->ShouldEndSession(nullptr));
  impl_->HandleLockScreenShown();
  EXPECT_TRUE(impl_->ShouldEndSession(nullptr));
  impl_->HandleLockScreenDismissed();
  EXPECT_TRUE(impl_->ShouldEndSession(nullptr));
  impl_->HandleSupervisedUserCreationFinished();
  EXPECT_FALSE(impl_->ShouldEndSession(nullptr));
}

TEST_F(SessionManagerImplTest, LockScreen_InterleavedSupervisedUserCreation) {
  ExpectAndRunStartSession(kSaneEmail);
  ExpectLockScreen();
  EXPECT_CALL(*exported_object(), SendSignal(_)).Times(AnyNumber());

  impl_->HandleSupervisedUserCreationStarting();
  EXPECT_TRUE(impl_->ShouldEndSession(nullptr));
  brillo::ErrorPtr error;
  EXPECT_TRUE(impl_->LockScreen(&error));
  EXPECT_FALSE(error.get());
  EXPECT_TRUE(impl_->ShouldEndSession(nullptr));
  impl_->HandleLockScreenShown();
  EXPECT_TRUE(impl_->ShouldEndSession(nullptr));
  impl_->HandleSupervisedUserCreationFinished();
  EXPECT_TRUE(impl_->ShouldEndSession(nullptr));
  impl_->HandleLockScreenDismissed();
  EXPECT_FALSE(impl_->ShouldEndSession(nullptr));
}

TEST_F(SessionManagerImplTest, LockScreen_MultiSession) {
  ExpectAndRunStartSession("user@somewhere");
  ExpectAndRunStartSession("user2@somewhere");
  ExpectLockScreen();
  brillo::ErrorPtr error;
  EXPECT_TRUE(impl_->LockScreen(&error));
  EXPECT_FALSE(error.get());
  EXPECT_TRUE(impl_->ShouldEndSession(nullptr));
}

TEST_F(SessionManagerImplTest, LockScreen_NoSession) {
  brillo::ErrorPtr error;
  EXPECT_FALSE(impl_->LockScreen(&error));
  ASSERT_TRUE(error.get());
  EXPECT_EQ(dbus_error::kSessionDoesNotExist, error->GetCode());
}

TEST_F(SessionManagerImplTest, LockScreen_Guest) {
  ExpectAndRunGuestSession();
  brillo::ErrorPtr error;
  EXPECT_FALSE(impl_->LockScreen(&error));
  ASSERT_TRUE(error.get());
  EXPECT_EQ(dbus_error::kSessionExists, error->GetCode());
}

TEST_F(SessionManagerImplTest, LockScreen_UserAndGuest) {
  ExpectAndRunStartSession(kSaneEmail);
  ExpectAndRunGuestSession();
  ExpectLockScreen();
  brillo::ErrorPtr error;
  EXPECT_TRUE(impl_->LockScreen(&error));
  ASSERT_FALSE(error.get());
  EXPECT_TRUE(impl_->ShouldEndSession(nullptr));
}

TEST_F(SessionManagerImplTest, LockUnlockScreen) {
  ExpectAndRunStartSession(kSaneEmail);
  ExpectLockScreen();
  brillo::ErrorPtr error;
  EXPECT_CALL(
      *init_controller_,
      TriggerImpulse(SessionManagerImpl::kScreenLockedImpulse, ElementsAre(),
                     InitDaemonController::TriggerMode::ASYNC))
      .WillOnce(Return(ByMove(dbus::Response::CreateEmpty())));
  EXPECT_TRUE(impl_->LockScreen(&error));
  EXPECT_FALSE(error.get());
  EXPECT_TRUE(impl_->ShouldEndSession(nullptr));

  EXPECT_CALL(*exported_object(),
              SendSignal(SignalEq(login_manager::kScreenIsLockedSignal)))
      .Times(1);
  impl_->HandleLockScreenShown();
  EXPECT_TRUE(impl_->ShouldEndSession(nullptr));

  EXPECT_TRUE(impl_->IsScreenLocked());

  EXPECT_CALL(*exported_object(),
              SendSignal(SignalEq(login_manager::kScreenIsUnlockedSignal)))
      .Times(1);
  EXPECT_CALL(
      *init_controller_,
      TriggerImpulse(SessionManagerImpl::kScreenUnlockedImpulse, ElementsAre(),
                     InitDaemonController::TriggerMode::ASYNC))
      .WillOnce(Return(ByMove(dbus::Response::CreateEmpty())));
  impl_->HandleLockScreenDismissed();
  EXPECT_FALSE(impl_->ShouldEndSession(nullptr));

  EXPECT_FALSE(impl_->IsScreenLocked());
}

TEST_F(SessionManagerImplTest, EndSessionBeforeSuspend) {
  const base::TimeTicks crash_time = tick_clock_->NowTicks();
  auto set_expectations = [&](bool should_stop) {
    EXPECT_CALL(manager_, GetLastBrowserRestartTime())
        .WillRepeatedly(Return(crash_time));
    EXPECT_CALL(manager_, ScheduleShutdown()).Times(should_stop ? 1 : 0);
  };

  // The session should be ended in response to a SuspendImminent signal.
  set_expectations(true);
  dbus::Signal imminent_signal(power_manager::kPowerManagerInterface,
                               power_manager::kSuspendImminentSignal);
  suspend_imminent_callback_.Run(&imminent_signal);
  Mock::VerifyAndClearExpectations(&manager_);

  // It should also be ended if a small amount of time passes between the
  // restart and the signal.
  tick_clock_->Advance(SessionManagerImpl::kCrashBeforeSuspendInterval);
  set_expectations(true);
  suspend_imminent_callback_.Run(&imminent_signal);
  Mock::VerifyAndClearExpectations(&manager_);

  // We shouldn't end the session after the specified interval has elapsed.
  tick_clock_->Advance(base::Seconds(1));
  set_expectations(false);
  suspend_imminent_callback_.Run(&imminent_signal);
}

TEST_F(SessionManagerImplTest, EndSessionDuringAndAfterSuspend) {
  EXPECT_CALL(manager_, GetLastBrowserRestartTime())
      .WillRepeatedly(Return(base::TimeTicks()));

  // Initially, we should restart Chrome if it crashes.
  EXPECT_FALSE(impl_->ShouldEndSession(nullptr));

  // Right after suspend starts, we should end the session instead.
  dbus::Signal imminent_signal(power_manager::kPowerManagerInterface,
                               power_manager::kSuspendImminentSignal);
  suspend_imminent_callback_.Run(&imminent_signal);
  EXPECT_TRUE(impl_->ShouldEndSession(nullptr));

  // We should also end it if some time passes...
  tick_clock_->Advance(base::Seconds(20));
  EXPECT_TRUE(impl_->ShouldEndSession(nullptr));

  // ... and right after resume finishes...
  dbus::Signal done_signal(power_manager::kPowerManagerInterface,
                           power_manager::kSuspendDoneSignal);
  suspend_done_callback_.Run(&done_signal);
  EXPECT_TRUE(impl_->ShouldEndSession(nullptr));

  // ... and for a period of time after that.
  tick_clock_->Advance(SessionManagerImpl::kCrashAfterSuspendInterval);
  EXPECT_TRUE(impl_->ShouldEndSession(nullptr));

  // If we wait long enough, we should go back to restarting Chrome.
  tick_clock_->Advance(base::Seconds(1));
  EXPECT_FALSE(impl_->ShouldEndSession(nullptr));
}

TEST_F(SessionManagerImplTest, StartDeviceWipe) {
  // Just make sure the device is being restart as a basic check of
  // InitiateDeviceWipe() invocation.
  ExpectDeviceRestart(1);

  brillo::ErrorPtr error;
  EXPECT_TRUE(impl_->StartDeviceWipe(&error));
  EXPECT_FALSE(error.get());
}

TEST_F(SessionManagerImplTest, StartDeviceWipe_AlreadyLoggedIn) {
  base::FilePath logged_in_path(SessionManagerImpl::kLoggedInFlag);
  ASSERT_FALSE(utils_.Exists(logged_in_path));
  ASSERT_TRUE(utils_.AtomicFileWrite(logged_in_path, "1"));
  brillo::ErrorPtr error;
  EXPECT_FALSE(impl_->StartDeviceWipe(&error));
  ASSERT_TRUE(error.get());
  EXPECT_EQ(dbus_error::kSessionExists, error->GetCode());
}

class StartRemoteDeviceWipeTest : public SessionManagerImplTest,
                                  public testing::WithParamInterface<
                                      em::PolicyFetchRequest::SignatureType> {
 public:
  std::unique_ptr<dbus::MethodCall> ConstructMethodCall() {
    constexpr uint32_t kSerial = 123;
    auto method_call = std::make_unique<dbus::MethodCall>(
        login_manager::kSessionManagerInterface,
        login_manager::kSessionManagerStartRemoteDeviceWipe);
    method_call->SetSerial(kSerial);

    return method_call;
  }
};

TEST_F(StartRemoteDeviceWipeTest, StartRemoteDeviceWipe_NoParameterShouldFail) {
  ExpectDeviceRestart(0);
  std::unique_ptr<dbus::MethodCall> method_call = ConstructMethodCall();
  TestFuture<std::unique_ptr<dbus::Response>> sender;

  impl_->StartRemoteDeviceWipe(method_call.get(), sender.GetCallback());

  EXPECT_EQ(dbus_error::kInvalidParameter, sender.Get()->GetErrorName());
}

TEST_F(StartRemoteDeviceWipeTest, StartRemoteDeviceWipe_EmptyArrayShouldFail) {
  ExpectDeviceRestart(0);
  std::vector<uint8_t> in_signed_command;
  std::unique_ptr<dbus::MethodCall> method_call = ConstructMethodCall();
  dbus::MessageWriter writer(method_call.get());
  writer.AppendArrayOfBytes(in_signed_command.data(), in_signed_command.size());
  TestFuture<std::unique_ptr<dbus::Response>> sender;

  impl_->StartRemoteDeviceWipe(method_call.get(), sender.GetCallback());

  EXPECT_EQ(dbus_error::kInvalidParameter, sender.Get()->GetErrorName());
}

TEST_F(StartRemoteDeviceWipeTest, StartRemoteDeviceWipe_NotArrayShouldFail) {
  ExpectDeviceRestart(0);
  std::unique_ptr<dbus::MethodCall> method_call = ConstructMethodCall();
  dbus::MessageWriter writer(method_call.get());
  writer.AppendByte(1);
  TestFuture<std::unique_ptr<dbus::Response>> sender;

  impl_->StartRemoteDeviceWipe(method_call.get(), sender.GetCallback());

  EXPECT_EQ(dbus_error::kInvalidParameter, sender.Get()->GetErrorName());
}

TEST_F(StartRemoteDeviceWipeTest,
       StartRemoteDeviceWipe_CorrectlySignedShouldPowerwash) {
  ExpectDeviceRestart(1);
  std::vector<uint8_t> in_signed_command;
  in_signed_command.push_back(1);
  std::unique_ptr<dbus::MethodCall> method_call = ConstructMethodCall();
  dbus::MessageWriter writer(method_call.get());
  writer.AppendArrayOfBytes(in_signed_command.data(), in_signed_command.size());
  TestFuture<std::unique_ptr<dbus::Response>> sender;
  EXPECT_CALL(
      *device_policy_service_,
      ValidateRemoteDeviceWipeCommand(_, em::PolicyFetchRequest::SHA256_RSA))
      .WillOnce(Return(true));

  impl_->StartRemoteDeviceWipe(method_call.get(), sender.GetCallback());

  EXPECT_TRUE(sender.Get()->GetErrorName().empty());
}

TEST_F(StartRemoteDeviceWipeTest,
       StartRemoteDeviceWipe_IncorrectlySignedShouldFail) {
  ExpectDeviceRestart(0);
  std::vector<uint8_t> in_signed_command;
  in_signed_command.push_back(1);
  std::unique_ptr<dbus::MethodCall> method_call = ConstructMethodCall();
  dbus::MessageWriter writer(method_call.get());
  writer.AppendArrayOfBytes(in_signed_command.data(), in_signed_command.size());
  TestFuture<std::unique_ptr<dbus::Response>> sender;
  EXPECT_CALL(
      *device_policy_service_,
      ValidateRemoteDeviceWipeCommand(_, em::PolicyFetchRequest::SHA256_RSA))
      .WillOnce(Return(false));

  impl_->StartRemoteDeviceWipe(method_call.get(), sender.GetCallback());

  EXPECT_EQ(dbus_error::kInvalidArgs, sender.Get()->GetErrorName());
}

TEST_F(SessionManagerImplTest, InitiateDeviceWipe_TooLongReason) {
  ASSERT_TRUE(
      utils_.RemoveFile(base::FilePath(SessionManagerImpl::kLoggedInFlag)));
  ExpectDeviceRestart(1);
  impl_->InitiateDeviceWipe(
      "overly long test message with\nspecial/chars$\t\xa4\xd6 1234567890");
  std::string contents;
  base::FilePath reset_path = real_utils_.PutInsideBaseDirForTesting(
      base::FilePath(SessionManagerImpl::kResetFile));
  ASSERT_TRUE(base::ReadFileToString(reset_path, &contents));
  ASSERT_EQ(
      "fast safe keepimg reason="
      "overly_long_test_message_with_special_chars_____12",
      contents);
}

TEST_F(SessionManagerImplTest, ClearForcedReEnrollmentVpd) {
  ResponseCapturer capturer;
  EXPECT_CALL(*device_policy_service_, ClearBlockDevmode(_)).Times(1);
  impl_->ClearForcedReEnrollmentVpd(capturer.CreateMethodResponse<>());
}

TEST_F(SessionManagerImplTest, ImportValidateAndStoreGeneratedKey) {
  base::FilePath key_file_path;
  string key("key_contents");
  ASSERT_TRUE(
      base::CreateTemporaryFileInDir(tmpdir_.GetPath(), &key_file_path));
  ASSERT_EQ(base::WriteFile(key_file_path, key.c_str(), key.size()),
            key.size());

  // Start a session, to set up NSSDB for the user.
  ExpectStartOwnerSession(kSaneEmail);
  brillo::ErrorPtr error;
  ASSERT_TRUE(impl_->StartSession(&error, kSaneEmail, kNothing));
  EXPECT_FALSE(error.get());

  EXPECT_CALL(*device_policy_service_,
              ValidateAndStoreOwnerKey(StrEq(kSaneEmail), StringToBlob(key),
                                       IncludesSlot(nss_.GetSlot())))
      .WillOnce(Return(true));

  impl_->OnKeyGenerated(kSaneEmail, key_file_path);
  EXPECT_FALSE(base::PathExists(key_file_path));
}

TEST_F(SessionManagerImplTest, DisconnectLogFile) {
  // Write a log file and create a relative symlink pointing at it.
  constexpr char kData[] = "fake log data";
  const base::FilePath kLogFile = log_dir_.GetPath().Append("ui.real");
  ASSERT_EQ(strlen(kData), base::WriteFile(kLogFile, kData, strlen(kData)));
  ASSERT_TRUE(base::CreateSymbolicLink(kLogFile.BaseName(), log_symlink_));

  struct stat st;
  ASSERT_EQ(0, stat(kLogFile.value().c_str(), &st));
  const ino_t orig_inode = st.st_ino;

  ExpectAndRunStartSession(kSaneEmail);

  // The file should still contain the same data...
  std::string data;
  ASSERT_TRUE(base::ReadFileToString(kLogFile, &data));
  EXPECT_EQ(kData, data);

  // ... but its inode should've changed.
  ASSERT_EQ(0, stat(kLogFile.value().c_str(), &st));
  const ino_t updated_inode = st.st_ino;
  EXPECT_NE(orig_inode, updated_inode);

  // Start a second session. The log file shouldn't be modified this time.
  constexpr char kEmail2[] = "user2@somewhere.com";
  ExpectAndRunStartSession(kEmail2);
  ASSERT_EQ(0, stat(kLogFile.value().c_str(), &st));
  EXPECT_EQ(updated_inode, st.st_ino);
}

TEST_F(SessionManagerImplTest, DontDisconnectLogFileInOtherDir) {
  // Write a log file to a subdirectory and create an absolute symlink.
  constexpr char kData[] = "fake log data";
  const base::FilePath kSubdir = log_dir_.GetPath().Append("subdir");
  ASSERT_TRUE(base::CreateDirectory(kSubdir));
  const base::FilePath kLogFile = kSubdir.Append("ui.real");
  ASSERT_EQ(strlen(kData), base::WriteFile(kLogFile, kData, strlen(kData)));
  ASSERT_TRUE(base::CreateSymbolicLink(kLogFile, log_symlink_));

  struct stat st;
  ASSERT_EQ(0, stat(kLogFile.value().c_str(), &st));
  const ino_t orig_inode = st.st_ino;

  ExpectAndRunStartSession(kSaneEmail);

  // The inode should stay the same since the symlink points to a file in a
  // different directory.
  ASSERT_EQ(0, stat(kLogFile.value().c_str(), &st));
  EXPECT_EQ(orig_inode, st.st_ino);
}

#if USE_CHEETS
TEST_F(SessionManagerImplTest, StopArcInstance) {
  EXPECT_CALL(*init_controller_, TriggerImpulse(_, _, _))
      .WillRepeatedly(
          InvokeWithoutArgs([]() { return dbus::Response::CreateEmpty(); }));
  EXPECT_CALL(*exported_object(),
              SendSignal(SignalEq(login_manager::kArcInstanceStopped,
                                  ArcContainerStopReason::USER_REQUEST)))
      .Times(1);

  brillo::ErrorPtr error;
  EXPECT_TRUE(impl_->StartArcMiniContainer(
      &error, SerializeAsBlob(arc::StartArcMiniInstanceRequest())));
  EXPECT_FALSE(error.get());

  EXPECT_TRUE(impl_->StopArcInstance(&error, std::string() /*account_id*/,
                                     false /*should_backup_log*/));
  EXPECT_FALSE(error.get());
}

TEST_F(SessionManagerImplTest, StopArcInstance_BackupsArcBugReport) {
  ExpectAndRunStartSession(kSaneEmail);

  EXPECT_CALL(*init_controller_, TriggerImpulse(_, _, _))
      .WillRepeatedly(
          InvokeWithoutArgs([] { return dbus::Response::CreateEmpty(); }));
  EXPECT_CALL(*exported_object(),
              SendSignal(SignalEq(login_manager::kArcInstanceStopped,
                                  ArcContainerStopReason::USER_REQUEST)))
      .Times(1);

  EXPECT_CALL(*debugd_proxy_, CallMethodAndBlock(_, _))
      .WillOnce(WithArg<0>(Invoke([](dbus::MethodCall* method_call) {
        EXPECT_EQ(method_call->GetInterface(), debugd::kDebugdInterface);
        EXPECT_EQ(method_call->GetMember(), debugd::kBackupArcBugReport);
        return dbus::Response::CreateEmpty();
      })));

  brillo::ErrorPtr error;
  EXPECT_TRUE(impl_->StartArcMiniContainer(
      &error, SerializeAsBlob(arc::StartArcMiniInstanceRequest())));
  EXPECT_FALSE(error.get());

  EXPECT_TRUE(
      impl_->StopArcInstance(&error, kSaneEmail, true /*should_backup_log*/));
  EXPECT_FALSE(error.get());
}

TEST_F(SessionManagerImplTest, StartArcMiniContainer) {
  {
    int64_t start_time = 0;
    brillo::ErrorPtr error;
    EXPECT_FALSE(impl_->GetArcStartTimeTicks(&error, &start_time));
    ASSERT_TRUE(error.get());
    EXPECT_EQ(dbus_error::kNotStarted, error->GetCode());
  }

  EXPECT_CALL(*init_controller_,
              TriggerImpulse(SessionManagerImpl::kStartArcInstanceImpulse,
                             StartArcInstanceExpectationsBuilder().Build(),
                             InitDaemonController::TriggerMode::ASYNC))
      .WillOnce(Return(ByMove(dbus::Response::CreateEmpty())));

  brillo::ErrorPtr error;
  EXPECT_TRUE(impl_->StartArcMiniContainer(
      &error, SerializeAsBlob(arc::StartArcMiniInstanceRequest())));
  EXPECT_FALSE(error.get());
  EXPECT_TRUE(android_container_.running());

  // StartArcInstance() does not update start time for login screen.
  {
    brillo::ErrorPtr error;
    int64_t start_time = 0;
    EXPECT_FALSE(impl_->GetArcStartTimeTicks(&error, &start_time));
    ASSERT_TRUE(error.get());
    EXPECT_EQ(dbus_error::kNotStarted, error->GetCode());
  }

  EXPECT_CALL(
      *init_controller_,
      TriggerImpulse(SessionManagerImpl::kStopArcInstanceImpulse, ElementsAre(),
                     InitDaemonController::TriggerMode::SYNC))
      .WillOnce(Return(ByMove(dbus::Response::CreateEmpty())));
  EXPECT_CALL(*exported_object(),
              SendSignal(SignalEq(login_manager::kArcInstanceStopped,
                                  ArcContainerStopReason::USER_REQUEST)))
      .Times(1);
  {
    brillo::ErrorPtr error;
    EXPECT_TRUE(impl_->StopArcInstance(&error, std::string() /*account_id*/,
                                       false /*should_backup_log*/));
    EXPECT_FALSE(error.get());
  }

  EXPECT_FALSE(android_container_.running());
}

TEST_F(SessionManagerImplTest, UpgradeArcContainer) {
  ExpectAndRunStartSession(kSaneEmail);

  // First, start ARC for login screen.
  EXPECT_CALL(*init_controller_,
              TriggerImpulse(SessionManagerImpl::kStartArcInstanceImpulse,
                             StartArcInstanceExpectationsBuilder().Build(),
                             InitDaemonController::TriggerMode::ASYNC))
      .WillOnce(Return(ByMove(dbus::Response::CreateEmpty())));

  brillo::ErrorPtr error;
  EXPECT_TRUE(impl_->StartArcMiniContainer(
      &error, SerializeAsBlob(arc::StartArcMiniInstanceRequest())));

  // Then, upgrade it to a fully functional one.
  {
    brillo::ErrorPtr error;
    int64_t start_time = 0;
    EXPECT_FALSE(impl_->GetArcStartTimeTicks(&error, &start_time));
    ASSERT_TRUE(error.get());
    EXPECT_EQ(dbus_error::kNotStarted, error->GetCode());
  }

  EXPECT_CALL(*init_controller_,
              TriggerImpulseWithTimeoutAndError(
                  SessionManagerImpl::kContinueArcBootImpulse,
                  UpgradeContainerExpectationsBuilder().Build(),
                  InitDaemonController::TriggerMode::SYNC,
                  SessionManagerImpl::kArcBootContinueTimeout, _))
      .WillOnce(Return(ByMove(dbus::Response::CreateEmpty())));
  EXPECT_CALL(
      *init_controller_,
      TriggerImpulse(SessionManagerImpl::kStopArcInstanceImpulse, ElementsAre(),
                     InitDaemonController::TriggerMode::SYNC))
      .WillOnce(Return(ByMove(dbus::Response::CreateEmpty())));

  auto upgrade_request = CreateUpgradeArcContainerRequest();
  EXPECT_TRUE(
      impl_->UpgradeArcContainer(&error, SerializeAsBlob(upgrade_request)));
  EXPECT_FALSE(error.get());
  EXPECT_TRUE(android_container_.running());
  {
    brillo::ErrorPtr error;
    int64_t start_time = 0;
    EXPECT_TRUE(impl_->GetArcStartTimeTicks(&error, &start_time));
    EXPECT_NE(0, start_time);
    ASSERT_FALSE(error.get());
  }
  // The ID for the container for login screen is passed to the dbus call.
  EXPECT_CALL(*exported_object(),
              SendSignal(SignalEq(login_manager::kArcInstanceStopped,
                                  ArcContainerStopReason::USER_REQUEST)))
      .Times(1);

  {
    brillo::ErrorPtr error;
    EXPECT_TRUE(impl_->StopArcInstance(&error, std::string() /*account_id*/,
                                       false /*should_backup_log*/));
    EXPECT_FALSE(error.get());
  }
  EXPECT_FALSE(android_container_.running());
}

TEST_F(SessionManagerImplTest,
       UpgradeArcContainer_BackupsArcBugReportOnFailure) {
  ExpectAndRunStartSession(kSaneEmail);

  // First, start ARC for login screen.
  EXPECT_CALL(*init_controller_,
              TriggerImpulse(SessionManagerImpl::kStartArcInstanceImpulse,
                             StartArcInstanceExpectationsBuilder().Build(),
                             InitDaemonController::TriggerMode::ASYNC))
      .WillOnce(Return(ByMove(dbus::Response::CreateEmpty())));

  brillo::ErrorPtr error;
  EXPECT_TRUE(impl_->StartArcMiniContainer(
      &error, SerializeAsBlob(arc::StartArcMiniInstanceRequest())));

  EXPECT_CALL(*init_controller_,
              TriggerImpulseWithTimeoutAndError(
                  SessionManagerImpl::kContinueArcBootImpulse,
                  UpgradeContainerExpectationsBuilder().Build(),
                  InitDaemonController::TriggerMode::SYNC,
                  SessionManagerImpl::kArcBootContinueTimeout, _))
      .WillOnce(ReturnNull());
  EXPECT_CALL(
      *init_controller_,
      TriggerImpulse(SessionManagerImpl::kStopArcInstanceImpulse, ElementsAre(),
                     InitDaemonController::TriggerMode::SYNC))
      .WillOnce(Return(ByMove(dbus::Response::CreateEmpty())));

  EXPECT_CALL(*exported_object(),
              SendSignal(SignalEq(login_manager::kArcInstanceStopped,
                                  ArcContainerStopReason::UPGRADE_FAILURE)))
      .Times(1);

  EXPECT_CALL(*arc_sideload_status_, IsAdbSideloadAllowed())
      .WillRepeatedly(Return(false));

  EXPECT_CALL(*debugd_proxy_, CallMethodAndBlock(_, _))
      .WillOnce(WithArg<0>(Invoke([](dbus::MethodCall* method_call) {
        EXPECT_EQ(method_call->GetInterface(), debugd::kDebugdInterface);
        EXPECT_EQ(method_call->GetMember(), debugd::kBackupArcBugReport);
        return dbus::Response::CreateEmpty();
      })));

  auto upgrade_request = CreateUpgradeArcContainerRequest();
  EXPECT_FALSE(
      impl_->UpgradeArcContainer(&error, SerializeAsBlob(upgrade_request)));
  EXPECT_TRUE(error.get());
  EXPECT_FALSE(android_container_.running());
}

TEST_F(SessionManagerImplTest, UpgradeArcContainerWithManagementTransition) {
  ExpectAndRunStartSession(kSaneEmail);
  SetUpArcMiniContainer();

  // Expect continue-arc-boot and start-arc-network impulses.
  EXPECT_CALL(*init_controller_,
              TriggerImpulseWithTimeoutAndError(
                  SessionManagerImpl::kContinueArcBootImpulse,
                  UpgradeContainerExpectationsBuilder()
                      .SetManagementTransition(1)
                      .Build(),
                  InitDaemonController::TriggerMode::SYNC,
                  SessionManagerImpl::kArcBootContinueTimeout, _))
      .WillOnce(Return(ByMove(dbus::Response::CreateEmpty())));

  auto upgrade_request = CreateUpgradeArcContainerRequest();
  upgrade_request.set_management_transition(
      arc::UpgradeArcContainerRequest_ManagementTransition_CHILD_TO_REGULAR);

  brillo::ErrorPtr error;
  EXPECT_TRUE(
      impl_->UpgradeArcContainer(&error, SerializeAsBlob(upgrade_request)));
  EXPECT_FALSE(error.get());
  EXPECT_TRUE(android_container_.running());
}

TEST_F(SessionManagerImplTest, DisableMediaStoreMaintenance) {
  ExpectAndRunStartSession(kSaneEmail);

  arc::StartArcMiniInstanceRequest request;
  request.set_disable_media_store_maintenance(true);

  // First, start ARC for login screen.
  EXPECT_CALL(*init_controller_,
              TriggerImpulse(SessionManagerImpl::kStartArcInstanceImpulse,
                             StartArcInstanceExpectationsBuilder()
                                 .SetDisableMediaStoreMaintenance(true)
                                 .Build(),
                             InitDaemonController::TriggerMode::ASYNC))
      .WillOnce(Return(ByMove(dbus::Response::CreateEmpty())));

  brillo::ErrorPtr error;
  EXPECT_TRUE(impl_->StartArcMiniContainer(&error, SerializeAsBlob(request)));
}

TEST_F(SessionManagerImplTest,
       UpgradeArcContainer_ConsumerAutoUpdateToggleEnabled) {
  ExpectAndRunStartSession(kSaneEmail);

  // Expect continue-arc-boot and start-arc-network impulses.
  EXPECT_CALL(*init_controller_,
              TriggerImpulse(SessionManagerImpl::kStartArcInstanceImpulse,
                             StartArcInstanceExpectationsBuilder()
                                 .SetEnableConsumerAutoUpdateToggle(true)
                                 .Build(),
                             InitDaemonController::TriggerMode::ASYNC))
      .WillOnce(Return(ByMove(dbus::Response::CreateEmpty())));

  brillo::ErrorPtr error;
  arc::StartArcMiniInstanceRequest request;
  request.set_enable_consumer_auto_update_toggle(true);

  EXPECT_TRUE(impl_->StartArcMiniContainer(&error, SerializeAsBlob(request)));
  EXPECT_FALSE(error.get());
}

TEST_F(SessionManagerImplTest,
       UpgradeArcContainer_ConsumerAutoUpdateToggleDisabled) {
  ExpectAndRunStartSession(kSaneEmail);

  // Expect continue-arc-boot and start-arc-network impulses.
  EXPECT_CALL(*init_controller_,
              TriggerImpulse(SessionManagerImpl::kStartArcInstanceImpulse,
                             StartArcInstanceExpectationsBuilder()
                                 .SetEnableConsumerAutoUpdateToggle(false)
                                 .Build(),
                             InitDaemonController::TriggerMode::ASYNC))
      .WillOnce(Return(ByMove(dbus::Response::CreateEmpty())));

  brillo::ErrorPtr error;
  arc::StartArcMiniInstanceRequest request;
  request.set_enable_consumer_auto_update_toggle(false);

  EXPECT_TRUE(impl_->StartArcMiniContainer(&error, SerializeAsBlob(request)));
  EXPECT_FALSE(error.get());
}

TEST_F(SessionManagerImplTest, UpgradeArcContainer_PrivacyHubForChromeEnabled) {
  ExpectAndRunStartSession(kSaneEmail);

  // Expect continue-arc-boot and start-arc-network impulses.
  EXPECT_CALL(*init_controller_,
              TriggerImpulse(SessionManagerImpl::kStartArcInstanceImpulse,
                             StartArcInstanceExpectationsBuilder()
                                 .SetEnablePrivacyHubForChrome(true)
                                 .Build(),
                             InitDaemonController::TriggerMode::ASYNC))
      .WillOnce(Return(ByMove(dbus::Response::CreateEmpty())));

  brillo::ErrorPtr error;
  arc::StartArcMiniInstanceRequest request;
  request.set_enable_privacy_hub_for_chrome(true);

  EXPECT_TRUE(impl_->StartArcMiniContainer(&error, SerializeAsBlob(request)));
  EXPECT_FALSE(error.get());
}

TEST_F(SessionManagerImplTest,
       UpgradeArcContainer_PrivacyHubForChromeEDisabled) {
  ExpectAndRunStartSession(kSaneEmail);

  // Expect continue-arc-boot and start-arc-network impulses.
  EXPECT_CALL(*init_controller_,
              TriggerImpulse(SessionManagerImpl::kStartArcInstanceImpulse,
                             StartArcInstanceExpectationsBuilder()
                                 .SetEnablePrivacyHubForChrome(false)
                                 .Build(),
                             InitDaemonController::TriggerMode::ASYNC))
      .WillOnce(Return(ByMove(dbus::Response::CreateEmpty())));

  brillo::ErrorPtr error;
  arc::StartArcMiniInstanceRequest request;
  request.set_enable_privacy_hub_for_chrome(false);

  EXPECT_TRUE(impl_->StartArcMiniContainer(&error, SerializeAsBlob(request)));
  EXPECT_FALSE(error.get());
}

TEST_F(SessionManagerImplTest, DisableDownloadProvider) {
  ExpectAndRunStartSession(kSaneEmail);

  arc::StartArcMiniInstanceRequest request;
  request.set_disable_download_provider(true);

  // First, start ARC for login screen.
  EXPECT_CALL(*init_controller_,
              TriggerImpulse(SessionManagerImpl::kStartArcInstanceImpulse,
                             StartArcInstanceExpectationsBuilder()
                                 .SetDisableDownloadProvider(true)
                                 .Build(),
                             InitDaemonController::TriggerMode::ASYNC))
      .WillOnce(Return(ByMove(dbus::Response::CreateEmpty())));

  brillo::ErrorPtr error;
  EXPECT_TRUE(impl_->StartArcMiniContainer(&error, SerializeAsBlob(request)));
}

TEST_F(SessionManagerImplTest, DisableUreadahead) {
  ExpectAndRunStartSession(kSaneEmail);

  arc::StartArcMiniInstanceRequest request;
  request.set_disable_ureadahead(true);

  // First, start ARC for login screen.
  EXPECT_CALL(*init_controller_,
              TriggerImpulse(SessionManagerImpl::kStartArcInstanceImpulse,
                             StartArcInstanceExpectationsBuilder()
                                 .SetDisableUreadahead(true)
                                 .Build(),
                             InitDaemonController::TriggerMode::ASYNC))
      .WillOnce(Return(ByMove(dbus::Response::CreateEmpty())));

  brillo::ErrorPtr error;
  EXPECT_TRUE(impl_->StartArcMiniContainer(&error, SerializeAsBlob(request)));
}

TEST_F(SessionManagerImplTest, EnableNotificationRefresh) {
  ExpectAndRunStartSession(kSaneEmail);

  arc::StartArcMiniInstanceRequest request;
  request.set_enable_notifications_refresh(true);

  // First, start ARC for login screen.
  EXPECT_CALL(*init_controller_,
              TriggerImpulse(SessionManagerImpl::kStartArcInstanceImpulse,
                             StartArcInstanceExpectationsBuilder()
                                 .SetEnableNotificationRefresh(true)
                                 .Build(),
                             InitDaemonController::TriggerMode::ASYNC))
      .WillOnce(Return(ByMove(dbus::Response::CreateEmpty())));

  brillo::ErrorPtr error;
  EXPECT_TRUE(impl_->StartArcMiniContainer(&error, SerializeAsBlob(request)));
}

TEST_F(SessionManagerImplTest, EnableTTSCaching) {
  ExpectAndRunStartSession(kSaneEmail);

  arc::StartArcMiniInstanceRequest request;
  request.set_enable_tts_caching(true);

  // First, start ARC for login screen.
  EXPECT_CALL(*init_controller_,
              TriggerImpulse(SessionManagerImpl::kStartArcInstanceImpulse,
                             StartArcInstanceExpectationsBuilder()
                                 .SetEnableTTSCaching(true)
                                 .Build(),
                             InitDaemonController::TriggerMode::ASYNC))
      .WillOnce(Return(ByMove(dbus::Response::CreateEmpty())));

  brillo::ErrorPtr error;
  EXPECT_TRUE(impl_->StartArcMiniContainer(&error, SerializeAsBlob(request)));
}

TEST_F(SessionManagerImplTest, HostUreadaheadGeneration) {
  ExpectAndRunStartSession(kSaneEmail);

  arc::StartArcMiniInstanceRequest request;
  request.set_host_ureadahead_generation(true);

  // First, start ARC for login screen.
  EXPECT_CALL(*init_controller_,
              TriggerImpulse(SessionManagerImpl::kStartArcInstanceImpulse,
                             StartArcInstanceExpectationsBuilder()
                                 .SetHostUreadaheadGeneration(true)
                                 .Build(),
                             InitDaemonController::TriggerMode::ASYNC))
      .WillOnce(Return(ByMove(dbus::Response::CreateEmpty())));

  brillo::ErrorPtr error;
  EXPECT_TRUE(impl_->StartArcMiniContainer(&error, SerializeAsBlob(request)));
}

TEST_P(SessionManagerPackagesCacheTest, PackagesCache) {
  ExpectAndRunStartSession(kSaneEmail);

  // First, start ARC for login screen.
  EXPECT_CALL(*init_controller_,
              TriggerImpulse(SessionManagerImpl::kStartArcInstanceImpulse,
                             StartArcInstanceExpectationsBuilder().Build(),
                             InitDaemonController::TriggerMode::ASYNC))
      .WillOnce(Return(ByMove(dbus::Response::CreateEmpty())));

  brillo::ErrorPtr error;
  EXPECT_TRUE(impl_->StartArcMiniContainer(
      &error, SerializeAsBlob(arc::StartArcMiniInstanceRequest())));

  bool skip_packages_cache_setup = false;
  bool copy_cache_setup = false;
  switch (std::get<0>(GetParam())) {
    case arc::
        UpgradeArcContainerRequest_PackageCacheMode_SKIP_SETUP_COPY_ON_INIT:
      skip_packages_cache_setup = true;
      [[fallthrough]];
    case arc::UpgradeArcContainerRequest_PackageCacheMode_COPY_ON_INIT:
      copy_cache_setup = true;
      break;
    case arc::UpgradeArcContainerRequest_PackageCacheMode_DEFAULT:
      break;
    default:
      NOTREACHED();
  }

  // Then, upgrade it to a fully functional one.
  EXPECT_CALL(*init_controller_,
              TriggerImpulseWithTimeoutAndError(
                  SessionManagerImpl::kContinueArcBootImpulse,
                  UpgradeContainerExpectationsBuilder()
                      .SetSkipPackagesCache(skip_packages_cache_setup)
                      .SetCopyPackagesCache(copy_cache_setup)
                      .SetSkipGmsCoreCache(std::get<1>(GetParam()))
                      .SetSkipTtsCache(std::get<2>(GetParam()))
                      .Build(),
                  InitDaemonController::TriggerMode::SYNC,
                  SessionManagerImpl::kArcBootContinueTimeout, _))
      .WillOnce(Return(ByMove(dbus::Response::CreateEmpty())));
  EXPECT_CALL(
      *init_controller_,
      TriggerImpulse(SessionManagerImpl::kStopArcInstanceImpulse, ElementsAre(),
                     InitDaemonController::TriggerMode::SYNC))
      .WillOnce(Return(ByMove(dbus::Response::CreateEmpty())));

  auto upgrade_request = CreateUpgradeArcContainerRequest();
  upgrade_request.set_packages_cache_mode(std::get<0>(GetParam()));
  upgrade_request.set_skip_gms_core_cache(std::get<1>(GetParam()));
  upgrade_request.set_skip_tts_cache(std::get<2>(GetParam()));
  EXPECT_TRUE(
      impl_->UpgradeArcContainer(&error, SerializeAsBlob(upgrade_request)));
  EXPECT_TRUE(android_container_.running());

  EXPECT_TRUE(impl_->StopArcInstance(&error, std::string() /*account_id*/,
                                     false /*should_backup_log*/));
  EXPECT_FALSE(android_container_.running());
}

INSTANTIATE_TEST_SUITE_P(
    ,
    SessionManagerPackagesCacheTest,
    ::testing::Combine(
        ::testing::Values(
            arc::UpgradeArcContainerRequest::DEFAULT,
            arc::UpgradeArcContainerRequest::COPY_ON_INIT,
            arc::UpgradeArcContainerRequest::SKIP_SETUP_COPY_ON_INIT),
        ::testing::Bool(),
        ::testing::Bool()));

TEST_P(SessionManagerPlayStoreAutoUpdateTest, PlayStoreAutoUpdate) {
  ExpectAndRunStartSession(kSaneEmail);

  arc::StartArcMiniInstanceRequest request;
  request.set_play_store_auto_update(GetParam());

  // First, start ARC for login screen.
  EXPECT_CALL(*init_controller_,
              TriggerImpulse(SessionManagerImpl::kStartArcInstanceImpulse,
                             StartArcInstanceExpectationsBuilder()
                                 .SetPlayStoreAutoUpdate(GetParam())
                                 .Build(),

                             InitDaemonController::TriggerMode::ASYNC))
      .WillOnce(Return(ByMove(dbus::Response::CreateEmpty())));

  brillo::ErrorPtr error;
  EXPECT_TRUE(impl_->StartArcMiniContainer(&error, SerializeAsBlob(request)));
}

INSTANTIATE_TEST_SUITE_P(
    ,
    SessionManagerPlayStoreAutoUpdateTest,
    ::testing::ValuesIn(
        {arc::StartArcMiniInstanceRequest::AUTO_UPDATE_DEFAULT,
         arc::StartArcMiniInstanceRequest_PlayStoreAutoUpdate_AUTO_UPDATE_ON,
         arc::
             StartArcMiniInstanceRequest_PlayStoreAutoUpdate_AUTO_UPDATE_OFF}));

TEST_P(SessionManagerDalvikMemoryProfileTest, DalvikMemoryProfile) {
  ExpectAndRunStartSession(kSaneEmail);

  arc::StartArcMiniInstanceRequest request;
  request.set_dalvik_memory_profile(GetParam());

  // First, start ARC for login screen.
  EXPECT_CALL(*init_controller_,
              TriggerImpulse(SessionManagerImpl::kStartArcInstanceImpulse,
                             StartArcInstanceExpectationsBuilder()
                                 .SetDalvikMemoryProfile(GetParam())
                                 .Build(),

                             InitDaemonController::TriggerMode::ASYNC))
      .WillOnce(Return(ByMove(dbus::Response::CreateEmpty())));

  brillo::ErrorPtr error;
  EXPECT_TRUE(impl_->StartArcMiniContainer(&error, SerializeAsBlob(request)));
}

INSTANTIATE_TEST_SUITE_P(
    ,
    SessionManagerDalvikMemoryProfileTest,
    ::testing::ValuesIn(
        {arc::StartArcMiniInstanceRequest::MEMORY_PROFILE_DEFAULT,
         arc::StartArcMiniInstanceRequest::MEMORY_PROFILE_4G,
         arc::StartArcMiniInstanceRequest::MEMORY_PROFILE_8G,
         arc::StartArcMiniInstanceRequest::MEMORY_PROFILE_16G}));

TEST_F(SessionManagerImplTest, UpgradeArcContainerForDemoSession) {
  ExpectAndRunStartSession(kSaneEmail);

  // First, start ARC for login screen.
  EXPECT_CALL(*init_controller_,
              TriggerImpulse(SessionManagerImpl::kStartArcInstanceImpulse,
                             StartArcInstanceExpectationsBuilder().Build(),
                             InitDaemonController::TriggerMode::ASYNC))
      .WillOnce(Return(ByMove(dbus::Response::CreateEmpty())));

  brillo::ErrorPtr error;
  EXPECT_TRUE(impl_->StartArcMiniContainer(
      &error, SerializeAsBlob(arc::StartArcMiniInstanceRequest())));

  // Then, upgrade it to a fully functional one.
  {
    brillo::ErrorPtr error;
    int64_t start_time = 0;
    EXPECT_FALSE(impl_->GetArcStartTimeTicks(&error, &start_time));
    ASSERT_TRUE(error.get());
    EXPECT_EQ(dbus_error::kNotStarted, error->GetCode());
  }

  EXPECT_CALL(*init_controller_,
              TriggerImpulseWithTimeoutAndError(
                  SessionManagerImpl::kContinueArcBootImpulse,
                  UpgradeContainerExpectationsBuilder()
                      .SetIsDemoSession(true)
                      .SetDemoSessionAppsPath(
                          "/run/imageloader/0.1/demo_apps/img.squash")
                      .Build(),
                  InitDaemonController::TriggerMode::SYNC,
                  SessionManagerImpl::kArcBootContinueTimeout, _))
      .WillOnce(Return(ByMove(dbus::Response::CreateEmpty())));
  EXPECT_CALL(
      *init_controller_,
      TriggerImpulse(SessionManagerImpl::kStopArcInstanceImpulse, ElementsAre(),
                     InitDaemonController::TriggerMode::SYNC))
      .WillOnce(Return(ByMove(dbus::Response::CreateEmpty())));

  auto upgrade_request = CreateUpgradeArcContainerRequest();
  upgrade_request.set_is_demo_session(true);
  upgrade_request.set_demo_session_apps_path(
      "/run/imageloader/0.1/demo_apps/img.squash");
  EXPECT_TRUE(
      impl_->UpgradeArcContainer(&error, SerializeAsBlob(upgrade_request)));
  EXPECT_TRUE(android_container_.running());

  EXPECT_TRUE(impl_->StopArcInstance(&error, std::string() /*account_id*/,
                                     false /*should_backup_log*/));
  EXPECT_FALSE(android_container_.running());
}

TEST_F(SessionManagerImplTest,
       UpgradeArcContainerForDemoSessionWithoutDemoApps) {
  ExpectAndRunStartSession(kSaneEmail);

  // First, start ARC for login screen.
  EXPECT_CALL(*init_controller_,
              TriggerImpulse(SessionManagerImpl::kStartArcInstanceImpulse,
                             StartArcInstanceExpectationsBuilder().Build(),
                             InitDaemonController::TriggerMode::ASYNC))
      .WillOnce(Return(ByMove(dbus::Response::CreateEmpty())));

  brillo::ErrorPtr error;
  EXPECT_TRUE(impl_->StartArcMiniContainer(
      &error, SerializeAsBlob(arc::StartArcMiniInstanceRequest())));

  // Then, upgrade it to a fully functional one.
  {
    brillo::ErrorPtr error;
    int64_t start_time = 0;
    EXPECT_FALSE(impl_->GetArcStartTimeTicks(&error, &start_time));
    ASSERT_TRUE(error.get());
    EXPECT_EQ(dbus_error::kNotStarted, error->GetCode());
  }

  EXPECT_CALL(
      *init_controller_,
      TriggerImpulseWithTimeoutAndError(
          SessionManagerImpl::kContinueArcBootImpulse,
          UpgradeContainerExpectationsBuilder().SetIsDemoSession(true).Build(),
          InitDaemonController::TriggerMode::SYNC,
          SessionManagerImpl::kArcBootContinueTimeout, _))
      .WillOnce(Return(ByMove(dbus::Response::CreateEmpty())));
  EXPECT_CALL(
      *init_controller_,
      TriggerImpulse(SessionManagerImpl::kStopArcInstanceImpulse, ElementsAre(),
                     InitDaemonController::TriggerMode::SYNC))
      .WillOnce(Return(ByMove(dbus::Response::CreateEmpty())));

  auto upgrade_request = CreateUpgradeArcContainerRequest();
  upgrade_request.set_is_demo_session(true);
  EXPECT_TRUE(
      impl_->UpgradeArcContainer(&error, SerializeAsBlob(upgrade_request)));
  EXPECT_TRUE(android_container_.running());

  EXPECT_TRUE(impl_->StopArcInstance(&error, std::string() /*account_id*/,
                                     false /*should_backup_log*/));
  EXPECT_FALSE(android_container_.running());
}

TEST_F(SessionManagerImplTest, UpgradeArcContainer_AdbSideloadingEnabled) {
  ExpectAndRunStartSession(kSaneEmail);
  SetUpArcMiniContainer();
  // Expect continue-arc-boot and start-arc-network impulses.
  EXPECT_CALL(*init_controller_,
              TriggerImpulseWithTimeoutAndError(
                  SessionManagerImpl::kContinueArcBootImpulse,
                  UpgradeContainerExpectationsBuilder()
                      .SetEnableAdbSideload(true)
                      .Build(),
                  InitDaemonController::TriggerMode::SYNC,
                  SessionManagerImpl::kArcBootContinueTimeout, _))
      .WillOnce(Return(ByMove(dbus::Response::CreateEmpty())));

  // Pretend ADB sideloading is already enabled.
  EXPECT_CALL(*arc_sideload_status_, IsAdbSideloadAllowed())
      .WillRepeatedly(Return(true));

  auto upgrade_request = CreateUpgradeArcContainerRequest();

  brillo::ErrorPtr error;
  EXPECT_TRUE(
      impl_->UpgradeArcContainer(&error, SerializeAsBlob(upgrade_request)));
  EXPECT_FALSE(error.get());
  EXPECT_TRUE(android_container_.running());
}

TEST_F(SessionManagerImplTest,
       UpgradeArcContainer_AdbSideloadingEnabled_ManagedAccount_Disallowed) {
  ExpectAndRunStartSession(kSaneEmail);
  SetUpArcMiniContainer();
  // Expect continue-arc-boot and start-arc-network impulses.
  EXPECT_CALL(*init_controller_,
              TriggerImpulseWithTimeoutAndError(
                  SessionManagerImpl::kContinueArcBootImpulse,
                  UpgradeContainerExpectationsBuilder()
                      .SetEnableAdbSideload(false)
                      .Build(),
                  InitDaemonController::TriggerMode::SYNC,
                  SessionManagerImpl::kArcBootContinueTimeout, _))
      .WillOnce(Return(ByMove(dbus::Response::CreateEmpty())));

  // Pretend ADB sideloading is already enabled.
  EXPECT_CALL(*arc_sideload_status_, IsAdbSideloadAllowed())
      .WillRepeatedly(Return(true));

  auto upgrade_request = CreateUpgradeArcContainerRequest();
  upgrade_request.set_is_account_managed(true);
  upgrade_request.set_is_managed_adb_sideloading_allowed(false);

  brillo::ErrorPtr error;
  EXPECT_TRUE(
      impl_->UpgradeArcContainer(&error, SerializeAsBlob(upgrade_request)));
  EXPECT_FALSE(error.get());
  EXPECT_TRUE(android_container_.running());
}

TEST_F(SessionManagerImplTest,
       UpgradeArcContainer_AdbSideloadingEnabled_ManagedAccount_Allowed) {
  ExpectAndRunStartSession(kSaneEmail);
  SetUpArcMiniContainer();
  // Expect continue-arc-boot and start-arc-network impulses.
  EXPECT_CALL(*init_controller_,
              TriggerImpulseWithTimeoutAndError(
                  SessionManagerImpl::kContinueArcBootImpulse,
                  UpgradeContainerExpectationsBuilder()
                      .SetEnableAdbSideload(true)
                      .Build(),
                  InitDaemonController::TriggerMode::SYNC,
                  SessionManagerImpl::kArcBootContinueTimeout, _))
      .WillOnce(Return(ByMove(dbus::Response::CreateEmpty())));

  // Pretend ADB sideloading is already enabled.
  EXPECT_CALL(*arc_sideload_status_, IsAdbSideloadAllowed())
      .WillRepeatedly(Return(true));

  auto upgrade_request = CreateUpgradeArcContainerRequest();
  upgrade_request.set_is_account_managed(true);
  upgrade_request.set_is_managed_adb_sideloading_allowed(true);

  brillo::ErrorPtr error;
  EXPECT_TRUE(
      impl_->UpgradeArcContainer(&error, SerializeAsBlob(upgrade_request)));
  EXPECT_FALSE(error.get());
  EXPECT_TRUE(android_container_.running());
}

TEST_F(SessionManagerImplTest, ArcNativeBridgeExperiment) {
  EXPECT_CALL(*init_controller_,
              TriggerImpulse(SessionManagerImpl::kStartArcInstanceImpulse,
                             StartArcInstanceExpectationsBuilder()
                                 .SetNativeBridgeExperiment(true)
                                 .Build(),
                             InitDaemonController::TriggerMode::ASYNC))
      .WillOnce(Return(ByMove(dbus::Response::CreateEmpty())));

  brillo::ErrorPtr error;
  arc::StartArcMiniInstanceRequest request;
  request.set_native_bridge_experiment(true);
  // Use for login screen mode for minimalistic test.
  EXPECT_TRUE(impl_->StartArcMiniContainer(&error, SerializeAsBlob(request)));
  EXPECT_FALSE(error.get());
}

TEST_F(SessionManagerImplTest, ArcFilePickerExperiment) {
  EXPECT_CALL(*init_controller_,
              TriggerImpulse(SessionManagerImpl::kStartArcInstanceImpulse,
                             StartArcInstanceExpectationsBuilder()
                                 .SetArcFilePickerExperiment(true)
                                 .Build(),
                             InitDaemonController::TriggerMode::ASYNC))
      .WillOnce(Return(ByMove(dbus::Response::CreateEmpty())));

  brillo::ErrorPtr error;
  arc::StartArcMiniInstanceRequest request;
  request.set_arc_file_picker_experiment(true);
  // Use for login screen mode for minimalistic test.
  EXPECT_TRUE(impl_->StartArcMiniContainer(&error, SerializeAsBlob(request)));
  EXPECT_FALSE(error.get());
}

TEST_F(SessionManagerImplTest, ArcCustomTabsExperiment) {
  EXPECT_CALL(*init_controller_,
              TriggerImpulse(SessionManagerImpl::kStartArcInstanceImpulse,
                             StartArcInstanceExpectationsBuilder()
                                 .SetArcCustomTabExperiment(true)
                                 .Build(),
                             InitDaemonController::TriggerMode::ASYNC))
      .WillOnce(Return(ByMove(dbus::Response::CreateEmpty())));

  brillo::ErrorPtr error;
  arc::StartArcMiniInstanceRequest request;
  request.set_arc_custom_tabs_experiment(true);
  // Use for login screen mode for minimalistic test.
  EXPECT_TRUE(impl_->StartArcMiniContainer(&error, SerializeAsBlob(request)));
  EXPECT_FALSE(error.get());
}

TEST_F(SessionManagerImplTest, ArcGeneratePai) {
  EXPECT_CALL(
      *init_controller_,
      TriggerImpulse(
          SessionManagerImpl::kStartArcInstanceImpulse,
          StartArcInstanceExpectationsBuilder().SetArcGeneratePai(true).Build(),
          InitDaemonController::TriggerMode::ASYNC))
      .WillOnce(Return(ByMove(dbus::Response::CreateEmpty())));

  brillo::ErrorPtr error;
  arc::StartArcMiniInstanceRequest request;
  request.set_arc_generate_pai(true);
  // Use for login screen mode for minimalistic test.
  EXPECT_TRUE(impl_->StartArcMiniContainer(&error, SerializeAsBlob(request)));
  EXPECT_FALSE(error.get());
}

TEST_F(SessionManagerImplTest, ArcLcdDensity) {
  constexpr int arc_lcd_density = 240;
  EXPECT_CALL(*init_controller_,
              TriggerImpulse(SessionManagerImpl::kStartArcInstanceImpulse,
                             StartArcInstanceExpectationsBuilder()
                                 .SetArcLcdDensity(arc_lcd_density)
                                 .Build(),
                             InitDaemonController::TriggerMode::ASYNC))
      .WillOnce(Return(ByMove(dbus::Response::CreateEmpty())));

  brillo::ErrorPtr error;
  arc::StartArcMiniInstanceRequest request;
  request.set_lcd_density(arc_lcd_density);
  // Use for login screen mode for minimalistic test.
  EXPECT_TRUE(impl_->StartArcMiniContainer(&error, SerializeAsBlob(request)));
  EXPECT_FALSE(error.get());
}

TEST_F(SessionManagerImplTest, ArcNoSession) {
  SetUpArcMiniContainer();

  brillo::ErrorPtr error;
  arc::UpgradeArcContainerRequest request = CreateUpgradeArcContainerRequest();
  EXPECT_FALSE(impl_->UpgradeArcContainer(&error, SerializeAsBlob(request)));
  ASSERT_TRUE(error.get());
  EXPECT_EQ(dbus_error::kSessionDoesNotExist, error->GetCode());
}

TEST_F(SessionManagerImplTest, ArcLowDisk) {
  ExpectAndRunStartSession(kSaneEmail);
  SetUpArcMiniContainer();
  // Emulate no free disk space.
  ON_CALL(utils_, AmountOfFreeDiskSpace(_)).WillByDefault(Return(0));

  brillo::ErrorPtr error;

  EXPECT_CALL(*exported_object(),
              SendSignal(SignalEq(login_manager::kArcInstanceStopped,
                                  ArcContainerStopReason::LOW_DISK_SPACE)))
      .Times(1);

  arc::UpgradeArcContainerRequest request = CreateUpgradeArcContainerRequest();
  EXPECT_FALSE(impl_->UpgradeArcContainer(&error, SerializeAsBlob(request)));
  ASSERT_TRUE(error.get());
  EXPECT_EQ(dbus_error::kLowFreeDisk, error->GetCode());
}

TEST_F(SessionManagerImplTest, ArcUpgradeCrash) {
  ExpectAndRunStartSession(kSaneEmail);

  // Overrides dev mode state.
  ON_CALL(utils_, GetDevModeState())
      .WillByDefault(Return(DevModeState::DEV_MODE_ON));

  EXPECT_CALL(
      *init_controller_,
      TriggerImpulse(
          SessionManagerImpl::kStartArcInstanceImpulse,
          StartArcInstanceExpectationsBuilder().SetDevMode(true).Build(),
          InitDaemonController::TriggerMode::ASYNC))
      .WillOnce(Return(ByMove(dbus::Response::CreateEmpty())));

  EXPECT_CALL(
      *init_controller_,
      TriggerImpulseWithTimeoutAndError(
          SessionManagerImpl::kContinueArcBootImpulse,
          UpgradeContainerExpectationsBuilder().SetDevMode(true).Build(),
          InitDaemonController::TriggerMode::SYNC,
          SessionManagerImpl::kArcBootContinueTimeout, _))
      .WillOnce(Return(ByMove(dbus::Response::CreateEmpty())));
  EXPECT_CALL(
      *init_controller_,
      TriggerImpulse(SessionManagerImpl::kStopArcInstanceImpulse, ElementsAre(),
                     InitDaemonController::TriggerMode::SYNC))
      .WillOnce(Return(ByMove(dbus::Response::CreateEmpty())));

  {
    brillo::ErrorPtr error;
    EXPECT_TRUE(impl_->StartArcMiniContainer(
        &error, SerializeAsBlob(arc::StartArcMiniInstanceRequest())));
    EXPECT_FALSE(error.get());
  }

  {
    brillo::ErrorPtr error;
    arc::UpgradeArcContainerRequest request =
        CreateUpgradeArcContainerRequest();
    EXPECT_TRUE(impl_->UpgradeArcContainer(&error, SerializeAsBlob(request)));
    EXPECT_FALSE(error.get());
  }
  EXPECT_TRUE(android_container_.running());

  EXPECT_CALL(*exported_object(),
              SendSignal(SignalEq(login_manager::kArcInstanceStopped,
                                  ArcContainerStopReason::CRASH)))
      .Times(1);

  android_container_.SimulateCrash();
  EXPECT_FALSE(android_container_.running());

  // This should now fail since the container was cleaned up already.
  {
    brillo::ErrorPtr error;
    EXPECT_FALSE(impl_->StopArcInstance(&error, std::string() /*account_id*/,
                                        false /*should_backup_log*/));
    ASSERT_TRUE(error.get());
    EXPECT_EQ(dbus_error::kContainerShutdownFail, error->GetCode());
  }
}

TEST_F(SessionManagerImplTest, LocaleAndPreferredLanguages) {
  ExpectAndRunStartSession(kSaneEmail);

  // First, start ARC for login screen.
  EXPECT_CALL(*init_controller_,
              TriggerImpulse(SessionManagerImpl::kStartArcInstanceImpulse,
                             StartArcInstanceExpectationsBuilder().Build(),
                             InitDaemonController::TriggerMode::ASYNC))
      .WillOnce(Return(ByMove(dbus::Response::CreateEmpty())));

  brillo::ErrorPtr error;
  EXPECT_TRUE(impl_->StartArcMiniContainer(
      &error, SerializeAsBlob(arc::StartArcMiniInstanceRequest())));

  // Then, upgrade it to a fully functional one.
  {
    brillo::ErrorPtr error;
    int64_t start_time = 0;
    EXPECT_FALSE(impl_->GetArcStartTimeTicks(&error, &start_time));
    ASSERT_TRUE(error.get());
    EXPECT_EQ(dbus_error::kNotStarted, error->GetCode());
  }

  EXPECT_CALL(*init_controller_,
              TriggerImpulseWithTimeoutAndError(
                  SessionManagerImpl::kContinueArcBootImpulse,
                  UpgradeContainerExpectationsBuilder()
                      .SetLocale("fr_FR")
                      .SetPreferredLanguages("ru,en")
                      .Build(),
                  InitDaemonController::TriggerMode::SYNC,
                  SessionManagerImpl::kArcBootContinueTimeout, _))
      .WillOnce(Return(ByMove(dbus::Response::CreateEmpty())));

  auto upgrade_request = CreateUpgradeArcContainerRequest();
  upgrade_request.set_locale("fr_FR");
  upgrade_request.add_preferred_languages("ru");
  upgrade_request.add_preferred_languages("en");
  EXPECT_TRUE(
      impl_->UpgradeArcContainer(&error, SerializeAsBlob(upgrade_request)));
  EXPECT_FALSE(error.get());
  EXPECT_TRUE(android_container_.running());
}

TEST_F(SessionManagerImplTest, UpgradeArcContainer_ArcNearbyShareEnabled) {
  ExpectAndRunStartSession(kSaneEmail);
  SetUpArcMiniContainer();

  // Expect continue-arc-boot and start-arc-network impulses.
  EXPECT_CALL(*init_controller_,
              TriggerImpulseWithTimeoutAndError(
                  SessionManagerImpl::kContinueArcBootImpulse,
                  UpgradeContainerExpectationsBuilder()
                      .SetEnableArcNearbyShare(true)
                      .Build(),
                  InitDaemonController::TriggerMode::SYNC,
                  SessionManagerImpl::kArcBootContinueTimeout, _))
      .WillOnce(Return(ByMove(dbus::Response::CreateEmpty())));

  auto upgrade_request = CreateUpgradeArcContainerRequest();
  upgrade_request.set_enable_arc_nearby_share(true);

  brillo::ErrorPtr error;
  EXPECT_TRUE(
      impl_->UpgradeArcContainer(&error, SerializeAsBlob(upgrade_request)));
  EXPECT_FALSE(error.get());
  EXPECT_TRUE(android_container_.running());
}

TEST_F(SessionManagerImplTest, UpgradeArcContainer_ArcNearbyShareDisabled) {
  ExpectAndRunStartSession(kSaneEmail);
  SetUpArcMiniContainer();

  // Expect continue-arc-boot and start-arc-network impulses.
  EXPECT_CALL(*init_controller_,
              TriggerImpulseWithTimeoutAndError(
                  SessionManagerImpl::kContinueArcBootImpulse,
                  UpgradeContainerExpectationsBuilder()
                      .SetEnableArcNearbyShare(false)
                      .Build(),
                  InitDaemonController::TriggerMode::SYNC,
                  SessionManagerImpl::kArcBootContinueTimeout, _))
      .WillOnce(Return(ByMove(dbus::Response::CreateEmpty())));

  auto upgrade_request = CreateUpgradeArcContainerRequest();
  upgrade_request.set_enable_arc_nearby_share(false);

  brillo::ErrorPtr error;
  EXPECT_TRUE(
      impl_->UpgradeArcContainer(&error, SerializeAsBlob(upgrade_request)));
  EXPECT_FALSE(error.get());
  EXPECT_TRUE(android_container_.running());
}

TEST_F(SessionManagerImplTest, UpgradeArcContainer_DisableUreadahead) {
  ExpectAndRunStartSession(kSaneEmail);
  SetUpArcMiniContainer();

  EXPECT_CALL(*init_controller_,
              TriggerImpulseWithTimeoutAndError(
                  SessionManagerImpl::kContinueArcBootImpulse,
                  UpgradeContainerExpectationsBuilder()
                      .SetDisableUreadahead(true)
                      .Build(),
                  InitDaemonController::TriggerMode::SYNC,
                  SessionManagerImpl::kArcBootContinueTimeout, _))
      .WillOnce(Return(ByMove(dbus::Response::CreateEmpty())));

  auto upgrade_request = CreateUpgradeArcContainerRequest();
  upgrade_request.set_disable_ureadahead(true);

  brillo::ErrorPtr error;
  EXPECT_TRUE(
      impl_->UpgradeArcContainer(&error, SerializeAsBlob(upgrade_request)));
  EXPECT_FALSE(error.get());
  EXPECT_TRUE(android_container_.running());
}
#else  // !USE_CHEETS

TEST_F(SessionManagerImplTest, ArcUnavailable) {
  ExpectAndRunStartSession(kSaneEmail);

  brillo::ErrorPtr error;
  EXPECT_FALSE(impl_->StartArcMiniContainer(
      &error, SerializeAsBlob(arc::StartArcMiniInstanceRequest())));
  ASSERT_TRUE(error.get());
  EXPECT_EQ(dbus_error::kNotAvailable, error->GetCode());
}
#endif

TEST_F(SessionManagerImplTest, SetArcCpuRestrictionFails) {
#if USE_CHEETS
  brillo::ErrorPtr error;
  EXPECT_FALSE(impl_->SetArcCpuRestriction(
      &error, static_cast<uint32_t>(NUM_CONTAINER_CPU_RESTRICTION_STATES)));
  ASSERT_TRUE(error.get());
  EXPECT_EQ(dbus_error::kArcCpuCgroupFail, error->GetCode());
#else
  brillo::ErrorPtr error;
  EXPECT_FALSE(impl_->SetArcCpuRestriction(
      &error, static_cast<uint32_t>(CONTAINER_CPU_RESTRICTION_BACKGROUND)));
  ASSERT_TRUE(error.get());
  EXPECT_EQ(dbus_error::kNotAvailable, error->GetCode());
#endif
}

TEST_F(SessionManagerImplTest, EmitArcBooted) {
#if USE_CHEETS
  EXPECT_CALL(*init_controller_,
              TriggerImpulse(SessionManagerImpl::kArcBootedImpulse,
                             ElementsAre(StartsWith("CHROMEOS_USER=")),
                             InitDaemonController::TriggerMode::ASYNC))
      .WillOnce(Return(ByMove(nullptr)));
  {
    brillo::ErrorPtr error;
    EXPECT_TRUE(impl_->EmitArcBooted(&error, kSaneEmail));
    EXPECT_FALSE(error.get());
  }

  EXPECT_CALL(
      *init_controller_,
      TriggerImpulse(SessionManagerImpl::kArcBootedImpulse, ElementsAre(),
                     InitDaemonController::TriggerMode::ASYNC))
      .WillOnce(Return(ByMove(nullptr)));
  {
    brillo::ErrorPtr error;
    EXPECT_TRUE(impl_->EmitArcBooted(&error, std::string()));
    EXPECT_FALSE(error.get());
  }
#else
  brillo::ErrorPtr error;
  EXPECT_FALSE(impl_->EmitArcBooted(&error, kSaneEmail));
  ASSERT_TRUE(error.get());
  EXPECT_EQ(dbus_error::kNotAvailable, error->GetCode());
#endif
}

TEST_F(SessionManagerImplTest, EnableAdbSideload) {
  EXPECT_CALL(*arc_sideload_status_, EnableAdbSideload(_));
  ResponseCapturer capturer;
  impl_->EnableAdbSideload(capturer.CreateMethodResponse<bool>());
}

TEST_F(SessionManagerImplTest, EnableAdbSideloadAfterLoggedIn) {
  base::FilePath logged_in_path(SessionManagerImpl::kLoggedInFlag);
  ASSERT_FALSE(utils_.Exists(logged_in_path));
  ASSERT_TRUE(utils_.AtomicFileWrite(logged_in_path, "1"));

  EXPECT_CALL(*arc_sideload_status_, EnableAdbSideload(_)).Times(0);

  ResponseCapturer capturer;
  impl_->EnableAdbSideload(capturer.CreateMethodResponse<bool>());

  ASSERT_NE(capturer.response(), nullptr);
  EXPECT_EQ(dbus_error::kSessionExists, capturer.response()->GetErrorName());
}

TEST_F(SessionManagerImplTest, QueryAdbSideload) {
  EXPECT_CALL(*arc_sideload_status_, QueryAdbSideload(_));
  ResponseCapturer capturer;
  impl_->QueryAdbSideload(capturer.CreateMethodResponse<bool>());
}

TEST_F(SessionManagerImplTest, StartBrowserDataMigrationCopy) {
  ExpectAndRunStartSession(kSaneEmail);
  const std::string mode = "copy";

  const std::string userhash = *SanitizeUserName(Username(kSaneEmail));
  EXPECT_CALL(manager_, SetBrowserDataMigrationArgsForUser(userhash, mode))
      .Times(1);

  brillo::ErrorPtr error;
  EXPECT_TRUE(impl_->StartBrowserDataMigration(&error, kSaneEmail, mode));
}

TEST_F(SessionManagerImplTest, StartBrowserDataMigrationMove) {
  ExpectAndRunStartSession(kSaneEmail);
  const std::string mode = "move";

  const std::string userhash = *SanitizeUserName(Username(kSaneEmail));
  EXPECT_CALL(manager_, SetBrowserDataMigrationArgsForUser(userhash, mode))
      .Times(1);

  brillo::ErrorPtr error;
  EXPECT_TRUE(impl_->StartBrowserDataMigration(&error, kSaneEmail, mode));
}

TEST_F(SessionManagerImplTest, StartBrowserDataMigrationAny) {
  ExpectAndRunStartSession(kSaneEmail);
  // Only Chrome needs to understand the values.
  const std::string mode = "any";

  const std::string userhash = *SanitizeUserName(Username(kSaneEmail));
  EXPECT_CALL(manager_, SetBrowserDataMigrationArgsForUser(userhash, mode))
      .Times(1);

  brillo::ErrorPtr error;
  EXPECT_TRUE(impl_->StartBrowserDataMigration(&error, kSaneEmail, mode));
}

TEST_F(SessionManagerImplTest, StartBrowserDataMigrationForNonLoggedInUser) {
  // If session has not been started for user,
  // |SetBrowserDataMigrationArgsForUser()| does not get called.
  const std::string userhash = *SanitizeUserName(Username(kSaneEmail));
  const std::string mode = "copy";
  EXPECT_CALL(manager_, SetBrowserDataMigrationArgsForUser(userhash, mode))
      .Times(0);

  brillo::ErrorPtr error;
  EXPECT_FALSE(impl_->StartBrowserDataMigration(&error, kSaneEmail, mode));
  EXPECT_EQ(error->GetCode(), dbus_error::kSessionDoesNotExist);
}

TEST_F(SessionManagerImplTest, StartBrowserDataMigrationForNonPrimaryUser) {
  const std::string second_user_email = "seconduser@gmail.com";
  const std::string mode = "copy";
  ExpectAndRunStartSession(kSaneEmail);
  ExpectAndRunStartSession(second_user_email);

  // Migration should only happen for primary user.
  const std::string userhash = *SanitizeUserName(Username(second_user_email));
  EXPECT_CALL(manager_, SetBrowserDataMigrationArgsForUser(userhash, mode))
      .Times(0);

  brillo::ErrorPtr error;
  EXPECT_FALSE(
      impl_->StartBrowserDataMigration(&error, second_user_email, mode));
  EXPECT_EQ(error->GetCode(), dbus_error::kInvalidAccount);
}

TEST_F(SessionManagerImplTest, StartBrowserDataBackwardMigration) {
  ExpectAndRunStartSession(kSaneEmail);

  const std::string userhash = *SanitizeUserName(Username(kSaneEmail));
  EXPECT_CALL(manager_, SetBrowserDataBackwardMigrationArgsForUser(userhash))
      .Times(1);

  brillo::ErrorPtr error;
  EXPECT_TRUE(impl_->StartBrowserDataBackwardMigration(&error, kSaneEmail));
}

TEST_F(SessionManagerImplTest,
       StartBrowserDataBackwardMigrationForNonLoggedInUser) {
  // If session has not been started for user,
  // |SetBrowserDataBackwardMigrationArgsForUser()| does not get called.
  const std::string userhash = *SanitizeUserName(Username(kSaneEmail));
  EXPECT_CALL(manager_, SetBrowserDataBackwardMigrationArgsForUser(userhash))
      .Times(0);

  brillo::ErrorPtr error;
  EXPECT_FALSE(impl_->StartBrowserDataBackwardMigration(&error, kSaneEmail));
  EXPECT_EQ(error->GetCode(), dbus_error::kSessionDoesNotExist);
}

TEST_F(SessionManagerImplTest,
       StartBrowserDataBackwardMigrationForNonPrimaryUser) {
  const std::string second_user_email = "seconduser@gmail.com";
  ExpectAndRunStartSession(kSaneEmail);
  ExpectAndRunStartSession(second_user_email);

  // Migration should only happen for primary user.
  const std::string userhash = *SanitizeUserName(Username(second_user_email));
  EXPECT_CALL(manager_, SetBrowserDataBackwardMigrationArgsForUser(userhash))
      .Times(0);

  brillo::ErrorPtr error;
  EXPECT_FALSE(
      impl_->StartBrowserDataBackwardMigration(&error, second_user_email));
  EXPECT_EQ(error->GetCode(), dbus_error::kInvalidAccount);
}

class StartTPMFirmwareUpdateTest : public SessionManagerImplTest {
 public:
  void SetUp() override {
    SessionManagerImplTest::SetUp();

    ON_CALL(utils_, Exists(_))
        .WillByDefault(Invoke(this, &StartTPMFirmwareUpdateTest::FileExists));
    ON_CALL(utils_, ReadFileToString(_, _))
        .WillByDefault(Invoke(this, &StartTPMFirmwareUpdateTest::ReadFile));
    ON_CALL(utils_, AtomicFileWrite(_, _))
        .WillByDefault(
            Invoke(this, &StartTPMFirmwareUpdateTest::AtomicWriteFile));
    SetDeviceMode("consumer");

    SetFileContents(SessionManagerImpl::kTPMFirmwareUpdateLocationFile,
                    "/lib/firmware/tpm/fake.bin");
    SetFileContents(SessionManagerImpl::kTPMFirmwareUpdateSRKVulnerableROCAFile,
                    "");
  }

  void TearDown() override {
    brillo::ErrorPtr error;
    bool result = impl_->StartTPMFirmwareUpdate(&error, update_mode_);
    if (expected_error_.empty()) {
      EXPECT_TRUE(result);
      EXPECT_FALSE(error);
      const auto& contents = file_contents_.find(
          SessionManagerImpl::kTPMFirmwareUpdateRequestFlagFile);
      ASSERT_NE(contents, file_contents_.end());
      EXPECT_EQ(update_mode_, contents->second);

      if (update_mode_ == "preserve_stateful") {
        EXPECT_EQ(1, file_contents_.count(
                         SessionManagerImpl::kStatefulPreservationRequestFile));
        EXPECT_EQ(1, crossystem_.VbGetSystemPropertyInt(
                         Crossystem::kClearTpmOwnerRequest));
      }
    } else {
      EXPECT_FALSE(result);
      ASSERT_TRUE(error);
      EXPECT_EQ(expected_error_, error->GetCode());
    }

    SessionManagerImplTest::TearDown();
  }

  void SetFileContents(const std::string& path, const std::string& contents) {
    file_contents_[path] = contents;
  }

  void DeleteFile(const std::string& path) { file_contents_.erase(path); }

  bool FileExists(const base::FilePath& path) {
    const auto entry = file_contents_.find(path.MaybeAsASCII());
    return entry != file_contents_.end();
  }

  bool ReadFile(const base::FilePath& path, std::string* str_out) {
    const auto entry = file_contents_.find(path.MaybeAsASCII());
    if (entry == file_contents_.end()) {
      return false;
    }
    *str_out = entry->second;
    return true;
  }

  bool AtomicWriteFile(const base::FilePath& path, const std::string& value) {
    file_contents_[path.value()] = value;
    return file_write_status_;
  }

  void ExpectError(const std::string& error) { expected_error_ = error; }

  void SetUpdateMode(const std::string& mode) { update_mode_ = mode; }

  std::string update_mode_ = "first_boot";
  std::string expected_error_;
  std::map<std::string, std::string> file_contents_;
  bool file_write_status_ = true;
};

TEST_F(StartTPMFirmwareUpdateTest, Success) {
  ExpectDeviceRestart(1);
}

TEST_F(StartTPMFirmwareUpdateTest, AlreadyLoggedIn) {
  SetFileContents(SessionManagerImpl::kLoggedInFlag, "");
  ExpectError(dbus_error::kSessionExists);
}

TEST_F(StartTPMFirmwareUpdateTest, BadUpdateMode) {
  SetUpdateMode("no_such_thing");
  ExpectError(dbus_error::kInvalidParameter);
}

TEST_F(StartTPMFirmwareUpdateTest, EnterpriseFirstBootNotSet) {
  SetDeviceMode("enterprise");
  ExpectError(dbus_error::kNotAvailable);
}

TEST_F(StartTPMFirmwareUpdateTest, EnterpriseFirstBootAllowed) {
  SetDeviceMode("enterprise");
  em::ChromeDeviceSettingsProto settings;
  settings.mutable_tpm_firmware_update_settings()
      ->set_allow_user_initiated_powerwash(true);
  SetDevicePolicy(settings);
  ExpectDeviceRestart(1);
}

TEST_F(StartTPMFirmwareUpdateTest, EnterprisePreserveStatefulNotSet) {
  SetUpdateMode("preserve_stateful");
  SetDeviceMode("enterprise");
  ExpectError(dbus_error::kNotAvailable);
}

TEST_F(StartTPMFirmwareUpdateTest, EnterprisePreserveStatefulAllowed) {
  SetUpdateMode("preserve_stateful");
  SetDeviceMode("enterprise");
  em::ChromeDeviceSettingsProto settings;
  settings.mutable_tpm_firmware_update_settings()
      ->set_allow_user_initiated_preserve_device_state(true);
  SetDevicePolicy(settings);
  ExpectDeviceRestart(1);
}

TEST_F(StartTPMFirmwareUpdateTest, EnterpriseCleanupDisallowed) {
  SetUpdateMode("cleanup");
  SetFileContents(SessionManagerImpl::kTPMFirmwareUpdateLocationFile, "");
  SetDeviceMode("enterprise");
  ExpectError(dbus_error::kNotAvailable);
}

TEST_F(StartTPMFirmwareUpdateTest, EnterpriseCleanupAllowed) {
  SetUpdateMode("cleanup");
  SetFileContents(SessionManagerImpl::kTPMFirmwareUpdateLocationFile, "");
  em::ChromeDeviceSettingsProto settings;
  settings.mutable_tpm_firmware_update_settings()
      ->set_allow_user_initiated_preserve_device_state(true);
  SetDevicePolicy(settings);
  ExpectDeviceRestart(1);
}

TEST_F(StartTPMFirmwareUpdateTest, AvailabilityNotDecided) {
  DeleteFile(SessionManagerImpl::kTPMFirmwareUpdateLocationFile);
  ExpectError(dbus_error::kNotAvailable);
}

TEST_F(StartTPMFirmwareUpdateTest, NoUpdateAvailable) {
  SetFileContents(SessionManagerImpl::kTPMFirmwareUpdateLocationFile, "");
  ExpectError(dbus_error::kNotAvailable);
}

TEST_F(StartTPMFirmwareUpdateTest, CleanupSRKVulnerable) {
  SetFileContents(SessionManagerImpl::kTPMFirmwareUpdateLocationFile, "");
  ExpectError(dbus_error::kNotAvailable);
}

TEST_F(StartTPMFirmwareUpdateTest, CleanupSRKNotVulnerable) {
  SetFileContents(SessionManagerImpl::kTPMFirmwareUpdateLocationFile, "");
  DeleteFile(SessionManagerImpl::kTPMFirmwareUpdateSRKVulnerableROCAFile);
  ExpectError(dbus_error::kNotAvailable);
}

TEST_F(StartTPMFirmwareUpdateTest, RequestFileWriteFailure) {
  file_write_status_ = false;
  ExpectError(dbus_error::kNotAvailable);
}

TEST_F(StartTPMFirmwareUpdateTest, PreserveStateful) {
  update_mode_ = "preserve_stateful";
  ExpectDeviceRestart(1);
}

}  // namespace login_manager

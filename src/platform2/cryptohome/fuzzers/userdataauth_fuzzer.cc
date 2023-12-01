// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>
#include <stdint.h>

#include <algorithm>
#include <memory>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/check_op.h>
#include <base/command_line.h>
#include <base/logging.h>
#include <base/memory/scoped_refptr.h>
#include <base/task/sequenced_task_runner.h>
#include <base/task/single_thread_task_runner.h>
#include <base/test/scoped_chromeos_version_info.h>
#include <base/test/task_environment.h>
#include <base/test/test_future.h>
#include <base/test/test_timeouts.h>
#include <base/time/time.h>
#include <brillo/dbus/dbus_object_test_helpers.h>
#include <brillo/dbus/dbus_object.h>
#include <brillo/fake_cryptohome.h>
#include <brillo/secure_blob.h>
#include <cryptohome/proto_bindings/UserDataAuth.pb.h>
#include <dbus/bus.h>
#include <dbus/cryptohome/dbus-constants.h>
#include <dbus/dbus.h>
#include <dbus/message.h>
#include <dbus/mock_bus.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <gmock/gmock.h>
#include <google/protobuf/stubs/logging.h>
#include <libhwsec/factory/fuzzed_factory.h>
#include <libhwsec-foundation/fuzzers/fuzzed_proto_generator.h>

#include "cryptohome/filesystem_layout.h"
#include "cryptohome/fuzzers/fuzzed_platform.h"
#include "cryptohome/platform.h"
#include "cryptohome/service_userdataauth.h"
#include "cryptohome/storage/cryptohome_vault_factory.h"
#include "cryptohome/storage/encrypted_container/backing_device_factory.h"
#include "cryptohome/storage/encrypted_container/encrypted_container_factory.h"
#include "cryptohome/storage/homedirs.h"
#include "cryptohome/storage/keyring/fake_keyring.h"
#include "cryptohome/storage/mock_mount_factory.h"
#include "cryptohome/storage/mount_factory.h"
#include "cryptohome/user_secret_stash/user_secret_stash.h"
#include "cryptohome/userdataauth.h"

namespace cryptohome {
namespace {

using ::brillo::Blob;
using ::brillo::BlobFromString;
using ::hwsec_foundation::FuzzedProtoGenerator;
using ::testing::_;
using ::testing::NiceMock;

// Run at most this number of "commands" when processing a single fuzzer input.
// This is chosen semi-arbitrarily, just to avoid spurious timeout reports.
constexpr int kMaxCommandCount = 10000;

constexpr char kStubSystemSalt[] = "stub-system-salt";
// A few typical values to choose from when simulating the system info in the
// fuzzer. We don't use completely random strings as only few aspects are
// relevant for code-under-test, and this way fuzzer can discover them quickly.
constexpr const char* kLsbReleaseVariants[] = {
    // A sample value for code running in production image.
    "CHROMEOS_RELEASE_TRACK=stable-channel\n"
    "CHROMEOS_RELEASE_VERSION=15160.0.0\n"
    "DEVICETYPE=CHROMEBOOK\n",
    // A sample value for code running in test image, and with a different
    // device type.
    "CHROMEOS_RELEASE_TRACK=testimage-channel\n"
    "CHROMEOS_RELEASE_VERSION=11012.0.2018_08_28_1422\n"
    "DEVICETYPE=CHROMEBOX\n",
    // An empty value to simulate failure.
    "",
};

// Performs initialization and holds state that's shared across all invocations
// of the fuzzer.
class Environment {
 public:
  Environment() {
    base::CommandLine::Init(0, nullptr);
    TestTimeouts::Initialize();
    // Suppress log spam from the code-under-test.
    logging::SetMinLogLevel(logging::LOGGING_FATAL);
  }

  base::test::TaskEnvironment& task_environment() { return task_environment_; }

 private:
  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME,
      base::test::TaskEnvironment::ThreadingMode::MAIN_THREAD_ONLY};
  // Initialize the system salt singleton with a stub value. Ideally we'd only
  // override the salt path and let the fuzzer explore the salt generation
  // flows, but for this to work we'd need to inject `Platform` into Libbrillo.
  brillo::cryptohome::home::FakeSystemSaltLoader system_salt_loader_{
      kStubSystemSalt};
  // Suppress log spam from protobuf helpers that complain about malformed
  // inputs.
  google::protobuf::LogSilencer log_silencer_;
};

std::unique_ptr<CryptohomeVaultFactory> CreateVaultFactory(
    Platform& platform, FuzzedDataProvider& provider) {
  // Only stub out `Keyring`, because unlike other classes its real
  // implementation does platform operations that don't go through `Platform`.
  auto container_factory = std::make_unique<EncryptedContainerFactory>(
      &platform, std::make_unique<FakeKeyring>(),
      std::make_unique<BackingDeviceFactory>(&platform));
  container_factory->set_allow_fscrypt_v2(provider.ConsumeBool());
  auto vault_factory = std::make_unique<CryptohomeVaultFactory>(
      &platform, std::move(container_factory));
  vault_factory->set_enable_application_containers(provider.ConsumeBool());
  return vault_factory;
}

std::unique_ptr<MountFactory> CreateMountFactory() {
  auto mount_factory = std::make_unique<MockMountFactory>();
  auto* mount_factory_ptr = mount_factory.get();
  // Configure the usage of in-process mount helper, as out-of-process
  // mounting is not fuzzing-compatible.
  EXPECT_CALL(*mount_factory, New(_, _, _, _, _))
      .WillRepeatedly([=](Platform* platform, HomeDirs* homedirs,
                          bool legacy_mount, bool bind_mount_downloads,
                          bool /*use_local_mounter*/) {
        return mount_factory_ptr->NewConcrete(platform, homedirs, legacy_mount,
                                              bind_mount_downloads,
                                              /*use_local_mounter=*/true);
      });
  return mount_factory;
}

std::string GenerateFuzzedDBusMethodName(
    const brillo::dbus_utils::DBusObject& dbus_object,
    const std::string& dbus_interface_name,
    FuzzedDataProvider& provider) {
  // The value to return if the code below fails to generate a valid one. It
  // must satisfy D-Bus restrictions on method names (e.g., be nonempty).
  static constexpr char kFallbackName[] = "foo";
  DCHECK(dbus_validate_member(kFallbackName, /*error=*/nullptr));

  const brillo::dbus_utils::DBusInterface* const dbus_interface =
      dbus_object.FindInterface(dbus_interface_name);
  CHECK(dbus_interface);

  // Generate the method name either by picking one of exported methods or by
  // creating a "random" string.
  const std::vector<std::string> exported_method_names =
      dbus_interface->GetMethodNames();
  // The max value in the range here is used to trigger the random generation.
  const size_t selected_method_index =
      provider.ConsumeIntegralInRange<size_t>(0, exported_method_names.size());
  if (selected_method_index < exported_method_names.size()) {
    return exported_method_names[selected_method_index];
  }

  std::string fuzzed_name = provider.ConsumeRandomLengthString();
  if (!dbus_validate_member(fuzzed_name.c_str(), /*error=*/nullptr)) {
    return kFallbackName;
  }
  return fuzzed_name;
}

std::unique_ptr<dbus::MethodCall> GenerateFuzzedDBusCallMessage(
    const brillo::dbus_utils::DBusObject& dbus_object,
    const std::string& dbus_interface_name,
    const std::string& dbus_method_name,
    const std::vector<Blob>& breadcrumbs,
    FuzzedDataProvider& provider) {
  auto dbus_call =
      std::make_unique<dbus::MethodCall>(dbus_interface_name, dbus_method_name);
  // The serial number can be hardcoded, since we never perform concurrent D-Bus
  // requests in the fuzzer.
  dbus_call->SetSerial(1);

  // Construct "random" arguments for the D-Bus call.
  dbus::MessageWriter dbus_writer(dbus_call.get());
  if (provider.ConsumeBool()) {
    FuzzedProtoGenerator generator(breadcrumbs, provider);
    Blob argument = generator.Generate();
    dbus_writer.AppendArrayOfBytes(argument.data(), argument.size());
  }

  return dbus_call;
}

std::unique_ptr<dbus::Response> RunBlockingDBusCall(
    std::unique_ptr<dbus::MethodCall> method_call_message,
    brillo::dbus_utils::DBusObject& dbus_object) {
  // Obtain the interface object for the name specified in the call.
  brillo::dbus_utils::DBusInterface* const dbus_interface =
      dbus_object.FindInterface(method_call_message->GetInterface());
  CHECK(dbus_interface);
  // Start the call.
  base::test::TestFuture<std::unique_ptr<dbus::Response>> dbus_response_future;
  brillo::dbus_utils::DBusInterfaceTestHelper::HandleMethodCall(
      dbus_interface, method_call_message.get(),
      dbus_response_future.GetCallback());
  // Wait for the reply and return it.
  return dbus_response_future.Take();
}

// Add new interesting blobs to `breadcrumbs` from `dbus_response`, if there's
// any (i.e., a reply field which we should try using in subsequent requests).
void UpdateBreadcrumbs(const std::string& dbus_method_name,
                       std::unique_ptr<dbus::Response> dbus_response,
                       std::vector<Blob>& breadcrumbs) {
  DCHECK(dbus_response);
  dbus::MessageReader reader(dbus_response.get());
  if (dbus_method_name == user_data_auth::kStartAuthSession) {
    user_data_auth::StartAuthSessionReply start_auth_session_reply;
    if (reader.PopArrayOfBytesAsProto(&start_auth_session_reply) &&
        !start_auth_session_reply.auth_session_id().empty()) {
      // Keep as a breadcrumb the AuthSessionId which the code-under-test
      // returned, so that the fuzzer can realistically test multiple D-Bus
      // calls against the same AuthSession (the IDs are random tokens, which
      // Libfuzzer can't "guess" itself).
      breadcrumbs.push_back(
          BlobFromString(start_auth_session_reply.auth_session_id()));
    }
  }
}

// Triggers a random D-Bus method call on the UserDataAuth interface.
void SimulateIncomingDBusCall(FuzzedDataProvider& provider,
                              brillo::dbus_utils::DBusObject& dbus_object,
                              std::vector<Blob>& breadcrumbs) {
  const std::string dbus_method_name = GenerateFuzzedDBusMethodName(
      dbus_object, user_data_auth::kUserDataAuthInterface, provider);
  std::unique_ptr<dbus::Response> dbus_response = RunBlockingDBusCall(
      GenerateFuzzedDBusCallMessage(dbus_object,
                                    user_data_auth::kUserDataAuthInterface,
                                    dbus_method_name, breadcrumbs, provider),
      dbus_object);
  if (dbus_response) {
    UpdateBreadcrumbs(dbus_method_name, std::move(dbus_response), breadcrumbs);
  }
}

// Simulates clocks moving forward.
void SimulateSleep(const base::TimeTicks& start_time,
                   Environment& env,
                   FuzzedDataProvider& provider) {
  // The constants are chosen semi-arbitrarily. The overall sum of sleeps should
  // be neither too short, as we want good test coverage, nor overly long, to
  // avoid timeouts due to periodic tasks scheduled by code-under-test.
  static constexpr base::TimeDelta kMaxSingleSleep = base::Minutes(1);
  static constexpr base::TimeDelta kMaxOverallSleep = base::Days(1);

  // Choose sleep duration. It's at most `kMaxSingleSleep`, but also the sum of
  // all sleeps is at most `kMaxOverallSleep`.
  base::TimeTicks max_time = start_time + kMaxOverallSleep;
  base::TimeDelta remaining_time = max_time - base::TimeTicks::Now();
  CHECK_GE(remaining_time, base::TimeDelta());
  base::TimeDelta current_sleep_max = std::min(kMaxSingleSleep, remaining_time);
  int64_t current_sleep = provider.ConsumeIntegralInRange<int64_t>(
      0, current_sleep_max.InMicroseconds());

  // Move clocks and execute scheduled tasks whose target times were reached.
  env.task_environment().FastForwardBy(base::Microseconds(current_sleep));
}

// Simulates "locking" the device. This corresponds to the real world's one-time
// operation of finalizing InstallAttributes during enterprise enrollment or
// first consumer user login. Until it's done, some mount-related operations
// fail and fuzzer can't test code in them.
void SimulateDeviceLocking(UserDataAuth& userdataauth,
                           FuzzedDataProvider& provider) {
  // We set specific attributes instead of completely "random" contents, as
  // empirically it's hard for the Libfuzzer to figure out the right strings.
  std::ignore = userdataauth.InstallAttributesSet(
      "enterprise.owned",
      BlobFromString(provider.ConsumeBool() ? "true" : "false"));
  std::ignore = userdataauth.InstallAttributesFinalize();
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;
  FuzzedDataProvider provider(data, size);

  // Prepare global singletons with per-test-case parameters.
  base::test::ScopedChromeOSVersionInfo scoped_version(
      provider.PickValueInArray(kLsbReleaseVariants),
      /*lsb_release_time=*/base::Time::UnixEpoch());

  // Prepare `UserDataAuth`'s dependencies.
  FuzzedPlatform platform(provider);
  std::unique_ptr<CryptohomeVaultFactory> vault_factory =
      CreateVaultFactory(platform, provider);
  std::unique_ptr<MountFactory> mount_factory = CreateMountFactory();
  hwsec::FuzzedFactory hwsec_factory(provider);
  auto bus =
      base::MakeRefCounted<NiceMock<dbus::MockBus>>(dbus::Bus::Options());
  auto mount_thread_bus =
      base::MakeRefCounted<NiceMock<dbus::MockBus>>(dbus::Bus::Options());
  // Set the USS experiment value to a "random" value. This is done in addition
  // to using `MockUssExperimentConfigFetcher` as the latter is a no-op.
  SetUssExperimentOverride uss_experiment_override(provider.ConsumeBool());

  // Prepare `UserDataAuth`. Set up a single-thread mode (which is not how the
  // daemon works in production, but allows faster and reproducible fuzzing).
  auto userdataauth = std::make_unique<UserDataAuth>();
  userdataauth->set_mount_task_runner(
      base::SingleThreadTaskRunner::GetCurrentDefault());
  userdataauth->set_platform(&platform);
  userdataauth->set_vault_factory_for_testing(vault_factory.get());
  userdataauth->set_mount_factory_for_testing(mount_factory.get());
  userdataauth->set_hwsec_factory(&hwsec_factory);
  if (!userdataauth->Initialize(mount_thread_bus)) {
    // This should be a rare case (e.g., the mocked system salt writing failed).
    return 0;
  }

  // Prepare `UserDataAuthAdaptor`. D-Bus handlers of the code-under-test become
  // registered on the given stub D-Bus object.
  brillo::dbus_utils::DBusObject dbus_object(
      /*object_manager=*/nullptr, /*bus=*/nullptr, /*object_path=*/{});
  UserDataAuthAdaptor userdataauth_adaptor(bus, &dbus_object,
                                           userdataauth.get());
  userdataauth_adaptor.RegisterAsync();

  // This is the main part of the fuzzer, where we exercise code-under-test
  // using various "random" commands.
  enum class Command {
    kIncomingDBusCall,  // Simulate an incoming D-Bus call.
    kSleep,             // Simulate clocks moving forward.
    kLockDevice,        // Simulates "locking" the device.
    // Must be the last item.
    kMaxValue = kLockDevice
  };
  const base::TimeTicks start_time = base::TimeTicks::Now();
  // `breadcrumbs` contain blobs which are useful to reuse across multiple calls
  // but which Libfuzzer cannot realistically generate itself.
  std::vector<Blob> breadcrumbs;
  for (int command_number = 0;
       command_number < kMaxCommandCount && provider.remaining_bytes() > 0;
       ++command_number) {
    switch (provider.ConsumeEnum<Command>()) {
      case Command::kIncomingDBusCall: {
        SimulateIncomingDBusCall(provider, dbus_object, breadcrumbs);
        break;
      }
      case Command::kSleep: {
        SimulateSleep(start_time, env, provider);
        break;
      }
      case Command::kLockDevice: {
        SimulateDeviceLocking(*userdataauth, provider);
        break;
      }
    }
  }

  // TODO(b/258547478): Remove this after `UserDataAuth` and
  // `UserDataAuthAdaptor` lifetime issues are resolved (they post tasks with
  // unretained pointers).
  env.task_environment().RunUntilIdle();

  return 0;
}

}  // namespace cryptohome

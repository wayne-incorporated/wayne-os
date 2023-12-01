// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "featured/feature_library.h"

#include <utility>

#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <base/no_destructor.h>
#include <base/strings/escape.h>
#include <base/strings/strcat.h>
#include <base/synchronization/lock.h>
#include <brillo/dbus/dbus_connection.h>
#include <brillo/dbus/dbus_method_invoker.h>
#include <brillo/dbus/dbus_proxy_util.h>
#include <brillo/errors/error.h>
#include <chromeos/dbus/service_constants.h>
#include <featured/proto_bindings/featured.pb.h>

namespace feature {

namespace {

// GetInstanceLock() must be held while using this variable.
PlatformFeatures* g_instance = nullptr;

}  // namespace

constexpr char kActiveTrialFileDirectory[] = "/run/featured/active";
constexpr char kFeatureLibInterface[] = "org.chromium.feature_lib";
constexpr char kFeatureLibPath[] = "/org/chromium/feature_lib";
constexpr char kRefetchSignal[] = "RefetchFeatureState";

PlatformFeatures::PlatformFeatures(scoped_refptr<dbus::Bus> bus,
                                   dbus::ObjectProxy* chrome_proxy,
                                   dbus::ObjectProxy* feature_proxy)
    : bus_(bus),
      chrome_proxy_(chrome_proxy),
      feature_proxy_(feature_proxy),
      active_trial_file_dir_(kActiveTrialFileDirectory) {
  base::AutoLock auto_lock(GetInstanceLock());
  CHECK(!g_instance);
  g_instance = this;
}

// static
bool PlatformFeatures::Initialize(scoped_refptr<dbus::Bus> bus) {
  auto* chrome_proxy = bus->GetObjectProxy(
      chromeos::kChromeFeaturesServiceName,
      dbus::ObjectPath(chromeos::kChromeFeaturesServicePath));
  if (!chrome_proxy) {
    LOG(ERROR) << "Failed to create object proxy for "
               << chromeos::kChromeFeaturesServiceName;
    return false;
  }

  auto* feature_proxy = bus->GetObjectProxy(kFeatureLibInterface,
                                            dbus::ObjectPath(kFeatureLibPath));
  if (!feature_proxy) {
    LOG(ERROR) << "Failed to create object proxy for " << kFeatureLibInterface;
    return false;
  }

  new PlatformFeatures(bus, chrome_proxy, feature_proxy);
  return true;
}

// static
void PlatformFeatures::InitializeForTesting(scoped_refptr<dbus::Bus> bus,
                                            dbus::ObjectProxy* chrome_proxy,
                                            dbus::ObjectProxy* feature_proxy) {
  new PlatformFeatures(bus, chrome_proxy, feature_proxy);
}

// static
void PlatformFeatures::ShutdownForTesting() {
  base::AutoLock auto_lock(GetInstanceLock());
  if (g_instance) {
    delete g_instance;
  }
}

// static
PlatformFeatures* PlatformFeatures::Get() {
  base::AutoLock auto_lock(GetInstanceLock());
  return g_instance;
}

PlatformFeatures::~PlatformFeatures() {
  GetInstanceLock().AssertAcquired();
  CHECK_EQ(this, g_instance);
  g_instance = nullptr;
}

void PlatformFeatures::IsEnabled(const VariationsFeature& feature,
                                 IsEnabledCallback callback) {
  DCHECK(CheckFeatureIdentity(feature)) << feature.name;

  chrome_proxy_->WaitForServiceToBeAvailable(base::BindOnce(
      &PlatformFeatures::OnWaitForServiceIsEnabled,
      weak_ptr_factory_.GetWeakPtr(), feature, std::move(callback)));
}

bool PlatformFeatures::IsEnabledBlockingWithTimeout(
    const VariationsFeature& feature, int timeout_ms) {
  DCHECK(CheckFeatureIdentity(feature)) << feature.name;

  dbus::MethodCall call(chromeos::kChromeFeaturesServiceInterface,
                        chromeos::kChromeFeaturesServiceIsFeatureEnabledMethod);
  dbus::MessageWriter writer(&call);
  writer.AppendString(feature.name);
  std::unique_ptr<dbus::Response> response = brillo::dbus_utils::CallDBusMethod(
      bus_, chrome_proxy_, &call, timeout_ms);
  if (!response) {
    return feature.default_state == FEATURE_ENABLED_BY_DEFAULT;
  }

  dbus::MessageReader reader(response.get());
  bool feature_enabled = false;
  if (!reader.PopBool(&feature_enabled)) {
    LOG(ERROR) << "failed to read bool from dbus result; using default value";
    return feature.default_state == FEATURE_ENABLED_BY_DEFAULT;
  }

  return feature_enabled;
}

void PlatformFeatures::OnWaitForServiceIsEnabled(
    const VariationsFeature& feature,
    IsEnabledCallback callback,
    bool available) {
  if (!available) {
    std::move(callback).Run(feature.default_state ==
                            FEATURE_ENABLED_BY_DEFAULT);
    LOG(ERROR) << "failed to connect to dbus service; using default value";
    return;
  }
  dbus::MethodCall call(chromeos::kChromeFeaturesServiceInterface,
                        chromeos::kChromeFeaturesServiceIsFeatureEnabledMethod);
  dbus::MessageWriter writer(&call);
  writer.AppendString(feature.name);
  chrome_proxy_->CallMethod(
      &call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT,
      base::BindOnce(&PlatformFeatures::HandleIsEnabledResponse,
                     weak_ptr_factory_.GetWeakPtr(), feature,
                     std::move(callback)));
}

void PlatformFeatures::HandleIsEnabledResponse(const VariationsFeature& feature,
                                               IsEnabledCallback callback,
                                               dbus::Response* response) {
  if (!response) {
    LOG(ERROR) << "dbus call failed; using default value";
    std::move(callback).Run(feature.default_state ==
                            FEATURE_ENABLED_BY_DEFAULT);
    return;
  }

  dbus::MessageReader reader(response);
  bool feature_enabled = false;
  if (!reader.PopBool(&feature_enabled)) {
    LOG(ERROR) << "failed to read bool from dbus result; using default value";
    std::move(callback).Run(feature.default_state ==
                            FEATURE_ENABLED_BY_DEFAULT);
    return;
  }

  std::move(callback).Run(feature_enabled);
}

void PlatformFeatures::GetParamsAndEnabled(
    const std::vector<const VariationsFeature*>& features,
    GetParamsCallback callback) {
  for (const auto* feature : features) {
    DCHECK(CheckFeatureIdentity(*feature)) << feature->name;
  }

  chrome_proxy_->WaitForServiceToBeAvailable(base::BindOnce(
      &PlatformFeatures::OnWaitForServiceGetParams,
      weak_ptr_factory_.GetWeakPtr(), features, std::move(callback)));
}

PlatformFeaturesInterface::ParamsResult
PlatformFeatures::GetParamsAndEnabledBlocking(
    const std::vector<const VariationsFeature*>& features) {
  for (const auto* feature : features) {
    DCHECK(CheckFeatureIdentity(*feature)) << feature->name;
  }

  dbus::MethodCall call(chromeos::kChromeFeaturesServiceInterface,
                        chromeos::kChromeFeaturesServiceGetFeatureParamsMethod);
  dbus::MessageWriter writer(&call);
  EncodeGetParamsArgument(&writer, features);
  std::unique_ptr<dbus::Response> response = brillo::dbus_utils::CallDBusMethod(
      bus_, chrome_proxy_, &call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT);
  return ParseGetParamsResponse(response.get(), features);
}

void PlatformFeatures::EncodeGetParamsArgument(
    dbus::MessageWriter* writer,
    const std::vector<const VariationsFeature*>& features) {
  dbus::MessageWriter array_writer(nullptr);
  writer->OpenArray("s", &array_writer);
  for (const auto* feature : features) {
    array_writer.AppendString(feature->name);
  }
  writer->CloseContainer(&array_writer);
}

PlatformFeaturesInterface::ParamsResult
PlatformFeatures::CreateDefaultGetParamsAndEnabledResponse(
    const std::vector<const VariationsFeature*>& features) {
  std::map<std::string, ParamsResultEntry> default_response;
  for (const auto* feature : features) {
    default_response[feature->name] = ParamsResultEntry{
        .enabled = feature->default_state == FEATURE_ENABLED_BY_DEFAULT,
    };
  }
  return default_response;
}

void PlatformFeatures::OnWaitForServiceGetParams(
    const std::vector<const VariationsFeature*>& features,
    GetParamsCallback callback,
    bool available) {
  if (!available) {
    LOG(ERROR) << "failed to connect to dbus service; using default value";
    std::move(callback).Run(CreateDefaultGetParamsAndEnabledResponse(features));
    return;
  }
  dbus::MethodCall call(chromeos::kChromeFeaturesServiceInterface,
                        chromeos::kChromeFeaturesServiceGetFeatureParamsMethod);
  dbus::MessageWriter writer(&call);
  EncodeGetParamsArgument(&writer, features);
  chrome_proxy_->CallMethod(
      &call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT,
      base::BindOnce(&PlatformFeatures::HandleGetParamsResponse,
                     weak_ptr_factory_.GetWeakPtr(), features,
                     std::move(callback)));
}

void PlatformFeatures::HandleGetParamsResponse(
    const std::vector<const VariationsFeature*>& features,
    GetParamsCallback callback,
    dbus::Response* response) {
  std::move(callback).Run(ParseGetParamsResponse(response, features));
}

PlatformFeatures::ParamsResult PlatformFeatures::ParseGetParamsResponse(
    dbus::Response* response,
    const std::vector<const VariationsFeature*>& features) {
  // Parse the response, which should be an array containing dict entries which
  // maps feature names to a struct containing:
  // * A bool for whether to use the overridden feature enable state
  // * A bool indicating the enable state (only valid if the first bool is true)
  // * A (possibly-empty) array of dict entries mapping parameter keys to values
  if (!response) {
    LOG(ERROR) << "dbus call failed; using default value";
    return CreateDefaultGetParamsAndEnabledResponse(features);
  }

  dbus::MessageReader reader(response);
  dbus::MessageReader array_reader(nullptr);
  if (!reader.PopArray(&array_reader)) {
    LOG(ERROR) << "failed to read array from dbus result; using default value";
    return CreateDefaultGetParamsAndEnabledResponse(features);
  }

  std::map<std::string, ParamsResultEntry> result;
  while (array_reader.HasMoreData()) {
    ParamsResultEntry entry;

    dbus::MessageReader feature_entry_reader(nullptr);
    if (!array_reader.PopDictEntry(&feature_entry_reader)) {
      LOG(ERROR) << "Failed to read dict from dbus result; using default.";
      return CreateDefaultGetParamsAndEnabledResponse(features);
    }

    // Get name
    std::string feature_name;
    if (!feature_entry_reader.PopString(&feature_name)) {
      LOG(ERROR) << "Failed to read string from dbus result; using default "
                 << "value";
      return CreateDefaultGetParamsAndEnabledResponse(features);
    }

    dbus::MessageReader struct_reader(nullptr);
    if (!feature_entry_reader.PopStruct(&struct_reader)) {
      LOG(ERROR) << "Failed to read struct from dbus result; using default "
                 << "value";
      return CreateDefaultGetParamsAndEnabledResponse(features);
    }

    // Get override state.
    bool use_override = false;
    bool override_value = false;
    if (!struct_reader.PopBool(&use_override) ||
        !struct_reader.PopBool(&override_value)) {
      LOG(ERROR) << "Failed to pop a bool; using default value";
      return CreateDefaultGetParamsAndEnabledResponse(features);
    } else {
      if (use_override) {
        entry.enabled = override_value;
      } else {
        // This is mildly inefficient, but the number of features passed to this
        // method is expected to be small (human magnitude), so it isn't a
        // prohibitive cost.
        for (const auto* feature : features) {
          if (feature->name == feature_name) {
            entry.enabled =
                feature->default_state == FEATURE_ENABLED_BY_DEFAULT;
          }
        }
      }
    }

    // Finally, get params.
    std::map<std::string, std::string> params;
    dbus::MessageReader params_array_reader(nullptr);
    if (!struct_reader.PopArray(&params_array_reader)) {
      LOG(ERROR) << "Failed to read params array; using default value";
      return CreateDefaultGetParamsAndEnabledResponse(features);
    }
    while (params_array_reader.HasMoreData()) {
      dbus::MessageReader entry_reader(nullptr);
      std::string key;
      std::string value;
      if (!params_array_reader.PopDictEntry(&entry_reader) ||
          !entry_reader.PopString(&key) || !entry_reader.PopString(&value)) {
        LOG(ERROR) << "failed to read dict entry; using default value";
        return CreateDefaultGetParamsAndEnabledResponse(features);
      }
      params[key] = value;
    }
    entry.params = std::move(params);

    result[feature_name] = entry;
  }

  return result;
}

bool PlatformFeatures::CheckFeatureIdentity(const VariationsFeature& feature) {
  base::AutoLock auto_lock(lock_);

  auto it = feature_identity_tracker_.find(feature.name);
  if (it == feature_identity_tracker_.end()) {
    // If it's not tracked yet, register it.
    feature_identity_tracker_[feature.name] = &feature;
    return true;
  }
  // Compare address of |feature| to the existing tracked entry.
  return it->second == &feature;
}

void PlatformFeatures::ListenForRefetchNeeded(
    base::RepeatingCallback<void(void)> signal_callback,
    base::OnceCallback<void(bool)> attached_callback) {
  feature_proxy_->ConnectToSignal(
      kFeatureLibInterface, kRefetchSignal,
      base::IgnoreArgs<dbus::Signal*>(signal_callback),
      base::BindOnce(&PlatformFeatures::OnConnectedCallback,
                     std::move(attached_callback)));
}

// static
void PlatformFeatures::OnConnectedCallback(
    base::OnceCallback<void(bool)> attached_callback,
    const std::string& interface,
    const std::string& signal,
    bool success) {
  if (!success) {
    LOG(ERROR) << "Failed to connect to " << interface << "." << signal;
  }
  std::move(attached_callback).Run(success);
}

// static
base::Lock& PlatformFeatures::GetInstanceLock() {
  static base::NoDestructor<base::Lock> lock;
  return *lock;
}

void PlatformFeatures::SetActiveTrialFileDirectoryForTesting(
    const base::FilePath& dir) {
  active_trial_file_dir_ = dir;
}

void PlatformFeatures::RecordActiveTrial(
    const featured::FeatureOverride& trial) {
  std::string escaped_trial_name =
      base::EscapeAllExceptUnreserved(trial.trial_name());
  std::string escaped_group_name =
      base::EscapeAllExceptUnreserved(trial.group_name());

  const base::FilePath filename(base::StrCat(
      {escaped_trial_name, kTrialGroupSeparator, escaped_group_name}));
  const base::FilePath full_path(active_trial_file_dir_.Append(filename));

  // Create file if it does not exist.
  // Note: This file gets automatically cleaned up on reboot if written to
  // kActiveTrialFileDirectory. The study is not treated as once-active,
  // always-active, across boots. The study will only be active for the rest of
  // the current boot unless activated again in a subsequent boot.
  base::File active_trial_file(full_path,
                               base::File::FLAG_CREATE | base::File::FLAG_READ);

  // Not an error if the trial file already exists.
  if ((!active_trial_file.IsValid()) &&
      (active_trial_file.error_details() !=
       base::File::Error::FILE_ERROR_EXISTS)) {
    PLOG(ERROR) << "Failed to create " << full_path
                << " for trial: " << trial.trial_name()
                << ", group: " << trial.group_name();
    return;
  }
}
}  // namespace feature

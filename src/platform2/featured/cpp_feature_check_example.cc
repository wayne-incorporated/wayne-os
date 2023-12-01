// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include <base/barrier_closure.h>
#include <base/files/file_descriptor_watcher_posix.h>
#include <base/functional/callback.h>
#include <base/logging.h>
#include <base/run_loop.h>
#include <base/task/single_thread_task_executor.h>
#include <base/task/thread_pool.h>
#include <base/task/thread_pool/thread_pool_instance.h>
#include <dbus/bus.h>

#include "featured/feature_library.h"

const struct VariationsFeature kCrOSLateBootMyAwesomeFeature = {
    .name = "CrOSLateBootMyAwesomeFeature",
    .default_state = FEATURE_DISABLED_BY_DEFAULT,
};

void EnabledCallback(base::RepeatingClosure barrier_closure, bool enabled) {
  LOG(INFO) << "Enabled? " << enabled;
  barrier_closure.Run();
}

void GetParamsCallback(base::RepeatingClosure barrier_closure,
                       feature::PlatformFeatures::ParamsResult result) {
  for (const auto& [name, entry] : result) {
    LOG(INFO) << "Feature: " << name;
    LOG(INFO) << "  Enabled?: " << entry.enabled;
    LOG(INFO) << "  Params?:";
    if (entry.params.empty()) {
      LOG(INFO) << "    No params";
      break;
    }
    for (const auto& [key, value] : entry.params) {
      LOG(INFO) << "   params['" << key << "'] = '" << value << "'";
    }
  }
  barrier_closure.Run();
}

void FetchState(feature::PlatformFeatures* feature_lib,
                base::RepeatingClosure barrier_closure) {
  feature_lib->IsEnabled(kCrOSLateBootMyAwesomeFeature,
                         base::BindOnce(&EnabledCallback, barrier_closure));

  feature_lib->GetParamsAndEnabled(
      {&kCrOSLateBootMyAwesomeFeature},
      base::BindOnce(&GetParamsCallback, barrier_closure));
}

void Refetch(feature::PlatformFeatures* feature_lib,
             base::RepeatingClosure barrier_closure) {
  LOG(INFO) << "Refetch";
  FetchState(feature_lib, barrier_closure);
}

void Ready(bool ready) {
  LOG(INFO) << "ready: " << std::boolalpha << ready;
}

int main(int argc, char* argv[]) {
  base::ThreadPoolInstance::CreateAndStartWithDefaultParams(
      "cpp_feature_check_example");
  base::SingleThreadTaskExecutor task_executor(base::MessagePumpType::IO);
  base::FileDescriptorWatcher watcher(task_executor.task_runner());

  LOG(INFO) << "Creating bus";
  dbus::Bus::Options options;
  options.bus_type = dbus::Bus::SYSTEM;
  options.dbus_task_runner =
      base::ThreadPool::CreateSequencedTaskRunner({base::MayBlock()});
  scoped_refptr<dbus::Bus> bus(new dbus::Bus(options));

  base::RunLoop loop;

  // 2 calls for the initial plus 2 for after chrome restarts.
  base::RepeatingClosure barrier_closure =
      base::BarrierClosure(4, loop.QuitClosure());

  LOG(INFO) << "Creating lib";
  CHECK(feature::PlatformFeatures::Initialize(bus))
      << "Failed to initialize lib";
  feature::PlatformFeatures* feature_lib = feature::PlatformFeatures::Get();
  LOG(INFO) << "ListenForRefetch";
  feature_lib->ListenForRefetchNeeded(
      base::BindRepeating(&Refetch, feature_lib, barrier_closure),
      base::BindOnce(&Ready));

  LOG(INFO) << "FetchState";
  FetchState(feature_lib, barrier_closure);

  loop.Run();
  base::ThreadPoolInstance::Get()->Shutdown();
}

// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <sysexits.h>
#include <memory>
#include <numeric>
#include <unordered_set>
#include <vector>

#include <base/logging.h>
#include <base/task/single_thread_task_runner.h>
#include <brillo/daemons/daemon.h>
#include <brillo/errors/error.h>
#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>
#include <dbus/bus.h>
#include <dbus/minios/dbus-constants.h>
#include <minios/proto_bindings/minios.pb.h>
#include <minios/client/dbus-proxies.h>

using dbus::Bus;
using org::chromium::MiniOsInterfaceProxy;

namespace minios {
namespace client {

// Constant to signal that we need to continue running the daemon after
// initialization.
constexpr int kContinueRunning = -1;
// Constant to signal an error exit code.
constexpr int kExitError = 1;

std::string ErrorPtrStr(const brillo::ErrorPtr& err) {
  std::ostringstream err_stream;
  err_stream << "Domain=" << err->GetDomain() << " "
             << "Error Code=" << err->GetCode() << " "
             << "Error Message=" << err->GetMessage();
  return err_stream.str();
}

class MiniOsClient : public brillo::Daemon {
 public:
  MiniOsClient(int argc, char** argv)
      : argc_(argc),
        argv_(argv),
        mini_os_proxy_(nullptr),
        weak_ptr_factory_(this) {}
  ~MiniOsClient() override = default;
  MiniOsClient(const MiniOsClient&) = delete;
  MiniOsClient& operator=(const MiniOsClient&) = delete;

 protected:
  int OnInit() override {
    if (int ret = Daemon::OnInit(); ret != EX_OK)
      return ret;
    Bus::Options options;
    options.bus_type = Bus::SYSTEM;
    scoped_refptr<Bus> bus{new Bus{options}};

    if (!bus->Connect()) {
      LOG(ERROR) << "DBus Service not available.";
      return EX_UNAVAILABLE;
    }

    mini_os_proxy_.reset(new MiniOsInterfaceProxy{bus});

    // We can't call QuitWithExitCode from OnInit(), so we delay the execution
    // of the ProcessFlags method after the Daemon initialization is done.
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, base::BindOnce(&MiniOsClient::ProcessFlagsAndExit,
                                  base::Unretained(this)));
    return EX_OK;
  }

 private:
  // Main commands implemented by the client.
  int GetState() {
    minios::State state;
    if (!mini_os_proxy_->GetState(&state, /*error=*/nullptr)) {
      LOG(ERROR) << "Failed to get MiniOS State info.";
      return EX_UNAVAILABLE;
    }

    LOG(INFO) << "State is " << State_States_Name(state.state());
    return EX_OK;
  }

  int ListNetworks() {
    std::vector<std::string> networks;
    if (!mini_os_proxy_->GetNetworks(&networks, /*error=*/nullptr)) {
      LOG(ERROR) << "Failed to get networks from MiniOS.";
      return EX_UNAVAILABLE;
    }

    if (networks.empty()) {
      LOG(INFO) << "No networks found.";
      return EX_OK;
    }

    LOG(INFO) << "Available networks:";
    for (const auto& network : networks) {
      printf("\t%s\n", network.c_str());
    }
    return EX_OK;
  }

  int NextScreen() {
    brillo::ErrorPtr err;
    if (!mini_os_proxy_->NextScreen(&err)) {
      LOG(ERROR) << "Failed to go to the next screen. Reason: "
                 << ErrorPtrStr(err);
      return kExitError;
    }
    return EX_OK;
  }

  int PrevScreen() {
    brillo::ErrorPtr err;
    if (!mini_os_proxy_->PrevScreen(&err)) {
      LOG(ERROR) << "Failed to go to the previous screen. Reason: "
                 << ErrorPtrStr(err);
      return kExitError;
    }
    return EX_OK;
  }

  int Reset() {
    brillo::ErrorPtr err;
    if (!mini_os_proxy_->ResetState(&err)) {
      LOG(ERROR) << "Failed to reset MiniOs. Reason: " << ErrorPtrStr(err);
      return kExitError;
    }
    return EX_OK;
  }

  int SetNetworkCredentials(const std::string& network_name,
                            const std::string& network_password) {
    if (!mini_os_proxy_->SetNetworkCredentials(network_name, network_password,
                                               /*error=*/nullptr)) {
      LOG(ERROR) << "Failed to set network credentials in MiniOS.";
      return EX_UNAVAILABLE;
    }

    LOG(INFO) << "Seeded MiniOS with credentials for " << network_name;
    return EX_OK;
  }

  int StartRecovery(const std::string& network_name,
                    const std::string& network_password,
                    bool wait_till_complete) {
    brillo::ErrorPtr err;
    if (!mini_os_proxy_->StartRecovery(network_name, network_password, &err)) {
      LOG(ERROR) << "Failed to set network credentials in MiniOS."
                 << "Reason: " << ErrorPtrStr(err);
      return kExitError;
    }
    if (wait_till_complete) {
      RegisterStatusHandlers();
      return kContinueRunning;
    }
    return EX_OK;
  }

  void OnStateChangedSignal(const State& state) {
    switch (state.state()) {
      case minios::State::NETWORK_SCANNING:
        LOG(INFO) << "Scanning networks -- please wait.";
        break;
      case minios::State::NETWORK_SELECTION:
        LOG(INFO) << "Waiting for network to be selected.";
        break;
      case minios::State::NETWORK_CREDENTIALS:
        LOG(INFO) << "Waiting for network password.";
        break;
      case minios::State::CONNECTING:
        LOG(INFO) << "Connecting -- please wait.";
        break;
      case minios::State::CONNECTED:
        LOG(INFO) << "Connected to a network.";
        break;
      case minios::State::RECOVERING:
        LOG(INFO) << "Attempting recovery -- please wait.";
        break;
      case minios::State::FINALIZING:
        LOG(INFO) << "Finalizing recovery -- please wait.";
        break;
      case minios::State::COMPLETED:
        LOG(INFO) << "Recovery completed -- rebooting.";
        exit(EX_OK);
        break;
      case minios::State::ERROR:
        LOG(ERROR) << "Recovery failed.";
        exit(kExitError);
        break;
      default:
        LOG(INFO) << "Got state update: State is "
                  << State_States_Name(state.state());
        break;
    }
  }

  void OnStateChangedSignalConnected(const std::string& interface_name,
                                     const std::string& signal_name,
                                     bool success) {
    if (!success) {
      LOG(ERROR) << "MiniOs OnStateChangedSignalConnected not successful";
    } else {
      LOG(INFO) << "MiniOs OnStateChangedSignalConnected successful";
    }
  }

  void RegisterStatusHandlers() {
    LOG(INFO) << "Register for status updates";
    mini_os_proxy_->RegisterMiniOsStateChangedSignalHandler(
        base::BindRepeating(&MiniOsClient::OnStateChangedSignal,
                            weak_ptr_factory_.GetWeakPtr()),
        base::BindRepeating(&MiniOsClient::OnStateChangedSignalConnected,
                            weak_ptr_factory_.GetWeakPtr()));
  }

  // Main method that parses and triggers all the actions based on the passed
  // flags. Returns the exit code of the program of kContinueRunning if it
  // should not exit.
  int ProcessFlags() {
    DEFINE_bool(get_networks, false, "Show the list of available networks.");
    DEFINE_bool(get_state, false, "Show the current state of MiniOs.");
    DEFINE_string(network_name, "", "The name of the network to connect to.");
    DEFINE_string(network_password, "",
                  "The password for the network to connect to.");
    DEFINE_bool(next_screen, false, "Navigate to the next MiniOs screen.");
    DEFINE_bool(prev_screen, false, "Navigate to the previous MiniOs screen.");
    DEFINE_bool(reset, false, "Reset MiniOs to its initial state.");
    DEFINE_bool(set_credentials, false,
                "Seed minios with network credentials.");
    DEFINE_bool(start_recovery, false, "Start the MiniOs recovery process.");
    DEFINE_bool(watch, false, "Wait and log status updates.");

    brillo::FlagHelper::Init(argc_, argv_,
                             "MiniOS Network Based Recovery Client");

    // These options are all mutually exclusive with one another.
    std::vector<bool> exclusive_flags{
        FLAGS_get_networks,  FLAGS_get_state, FLAGS_next_screen,
        FLAGS_prev_screen,   FLAGS_reset,     FLAGS_set_credentials,
        FLAGS_start_recovery};
    if (std::accumulate(exclusive_flags.begin(), exclusive_flags.end(), 0) >
        1) {
      LOG(ERROR)
          << "Multiple exclusive options selected. "
          << "Select only one of --get_error, --get_networks, --get_state, "
          << "--next_screen, --prev_screen, --reset, --set_credentials or "
          << "--start_recovery";
      return EX_USAGE;
    }

    if (FLAGS_get_networks) {
      return ListNetworks();
    }

    if (FLAGS_get_state) {
      return GetState();
    }

    if (FLAGS_next_screen) {
      return NextScreen();
    }

    if (FLAGS_prev_screen) {
      return PrevScreen();
    }

    if (FLAGS_reset) {
      return Reset();
    }

    if (FLAGS_set_credentials) {
      if (FLAGS_network_name.empty()) {
        LOG(ERROR)
            << "--set_credentials requires at least a network name and an "
               "optional password.";
        return EX_USAGE;
      }
      return SetNetworkCredentials(FLAGS_network_name, FLAGS_network_password);
    }

    if (FLAGS_start_recovery) {
      if (FLAGS_network_name.empty()) {
        LOG(ERROR)
            << "--start_recovery requires at least a network name and an "
               "optional password.";
        return EX_USAGE;
      }
      return StartRecovery(FLAGS_network_name, FLAGS_network_password,
                           FLAGS_watch);
    }

    if (FLAGS_watch) {
      RegisterStatusHandlers();
      return kContinueRunning;
    }

    if (!FLAGS_network_name.empty()) {
      LOG(ERROR) << "--network_name should be used with --set_credentials or "
                    "--start_recovery.";
      return EX_USAGE;
    }

    if (!FLAGS_network_password.empty()) {
      LOG(ERROR)
          << "--network_password should be used with --set_credentials and "
             "--network_name or --start_recovery and --network_name .";
      return EX_USAGE;
    }

    return EX_OK;
  }

  void ProcessFlagsAndExit() {
    int ret = ProcessFlags();
    if (ret != kContinueRunning)
      QuitWithExitCode(ret);
  }

  // Copy of argc and argv passed to main().
  int argc_;
  char** argv_;

  std::unique_ptr<org::chromium::MiniOsInterfaceProxyInterface> mini_os_proxy_;
  base::WeakPtrFactory<MiniOsClient> weak_ptr_factory_;
};

}  // namespace client
}  // namespace minios

int main(int argc, char** argv) {
  minios::client::MiniOsClient client(argc, argv);
  return client.Run();
}

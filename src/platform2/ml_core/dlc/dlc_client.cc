// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ml_core/dlc/dlc_client.h"

#include <memory>
#include <utility>
#include "base/files/file_path.h"
#include "base/functional/bind.h"

#include <base/strings/strcat.h>
#include <dbus/bus.h>
#include <dlcservice/proto_bindings/dlcservice.pb.h>
#include <dlcservice/dbus-constants.h>
#include <dlcservice/dbus-proxies.h>

namespace {
constexpr char kDlcId[] = "ml-core-internal";
constexpr uint8_t kMaxInstallAttempts = 5;
constexpr uint16_t kDlcInstallTimeout = 50000;
const base::TimeDelta kRetryDelays[kMaxInstallAttempts] = {
    base::Seconds(5), base::Seconds(10), base::Seconds(20), base::Seconds(40),
    base::Seconds(80)};

class DlcClientImpl : public cros::DlcClient {
 public:
  DlcClientImpl() = default;
  ~DlcClientImpl() override = default;

  void Initialize(
      base::OnceCallback<void(const base::FilePath&)> dlc_root_path_cb,
      base::OnceCallback<void(const std::string&)> error_cb) {
    dlc_root_path_cb_ = std::move(dlc_root_path_cb);
    error_cb_ = std::move(error_cb);
    LOG(INFO) << "Setting up DlcClient";

    dbus::Bus::Options opts;
    opts.bus_type = dbus::Bus::SYSTEM;
    bus_ = new dbus::Bus(std::move(opts));
    if (!bus_->Connect()) {
      LOG(ERROR) << "Failed to connect to system bus";
      return;
    }
    LOG(INFO) << "Connected to system bus";

    dlcservice_client_ =
        std::make_unique<org::chromium::DlcServiceInterfaceProxy>(bus_);

    base::WeakPtr<DlcClientImpl> weak_this = weak_factory_.GetWeakPtr();
    dlcservice_client_->RegisterDlcStateChangedSignalHandler(
        base::BindRepeating(&DlcClientImpl::OnDlcStateChanged, weak_this),
        base::BindOnce(&DlcClientImpl::OnDlcStateChangedConnect, weak_this));

    LOG(INFO) << "DlcClient setup complete";
  }

  void OnDlcStateChanged(const dlcservice::DlcState& dlc_state) {
    LOG(INFO) << "OnDlcStateChanged (" << dlc_state.id()
              << "): " << dlcservice::DlcState::State_Name(dlc_state.state());

    if (dlc_state.id() != kDlcId) {
      return;
    }

    switch (dlc_state.state()) {
      case dlcservice::DlcState::INSTALLED:
        LOG(INFO) << "Successfully installed DLC " << kDlcId << " at "
                  << dlc_state.root_path();
        InvokeSuccessCb(base::FilePath(dlc_state.root_path()));
        break;
      case dlcservice::DlcState::INSTALLING:
        LOG(INFO) << static_cast<int>(dlc_state.progress() * 100)
                  << "% installing DLC: " << kDlcId;
        break;
      case dlcservice::DlcState::NOT_INSTALLED: {
        InvokeErrorCb(base::StrCat({"Failed to install DLC: ", kDlcId,
                                    " Error: ", dlc_state.last_error_code()}));
        break;
      }
      default:
        InvokeErrorCb(base::StrCat({"Unknown error when installing: ", kDlcId,
                                    " Error: ", dlc_state.last_error_code()}));
        break;
    }
  }

  void OnDlcStateChangedConnect(const std::string& interface,
                                const std::string& signal,
                                const bool success) {
    LOG(INFO) << "OnDlcStateChangedConnect (" << interface << ":" << signal
              << "): " << (success ? "true" : "false");
    if (!success) {
      InvokeErrorCb(
          base::StrCat({"Error connecting ", interface, ". ", signal}));
    }
  }

  void InstallDlc() override { Install(/*attempt=*/1); }

  void Install(int attempt) {
    LOG(INFO) << "InstallDlc called for " << kDlcId << ", attempt: " << attempt;
    if (!bus_->IsConnected()) {
      InvokeErrorCb("Error calling dlcservice: DBus not connected");
      return;
    }

    brillo::ErrorPtr error;
    dlcservice::InstallRequest install_request;
    install_request.set_id(kDlcId);

    if (!dlcservice_client_->Install(install_request, &error,
                                     kDlcInstallTimeout)) {
      LOG(ERROR) << "Error calling dlcservice_client_->Install for " << kDlcId;
      if (error == nullptr) {
        InvokeErrorCb("Error calling dlcservice: unknown");
        return;
      }

      LOG(ERROR) << "Error code: " << error->GetCode()
                 << " msg: " << error->GetMessage();

      if (error->GetCode() == dlcservice::kErrorBusy) {
        attempt++;
        if (attempt > kMaxInstallAttempts) {
          auto err = base::StrCat(
              {"Install attempts for ", kDlcId, " exhausted, aborting."});
          LOG(ERROR) << err;
          InvokeErrorCb(err);
          return;
        }

        auto retry_delay = kRetryDelays[attempt - 1];
        LOG(ERROR) << "dlcservice is busy. Retrying in " << retry_delay;

        base::SequencedTaskRunner::GetCurrentDefault()->PostDelayedTask(
            FROM_HERE,
            base::BindOnce(&DlcClientImpl::Install, weak_factory_.GetWeakPtr(),
                           attempt),
            retry_delay);
        return;
      }
      InvokeErrorCb(
          base::StrCat({"Error calling dlcservice (code=", error->GetCode(),
                        "): ", error->GetMessage()}));
      return;
    }
    LOG(INFO) << "InstallDlc successfully initiated for " << kDlcId;
  }

  void InvokeSuccessCb(const base::FilePath& dlc_root_path) {
    if (dlc_root_path_cb_)
      std::move(dlc_root_path_cb_).Run(dlc_root_path);
  }

  void InvokeErrorCb(const std::string& error_msg) {
    if (error_cb_)
      std::move(error_cb_).Run(error_msg);
  }

  std::unique_ptr<org::chromium::DlcServiceInterfaceProxyInterface>
      dlcservice_client_;
  scoped_refptr<dbus::Bus> bus_;
  base::OnceCallback<void(const base::FilePath&)> dlc_root_path_cb_;
  base::OnceCallback<void(const std::string&)> error_cb_;
  base::WeakPtrFactory<DlcClientImpl> weak_factory_{this};
};

class DlcClientForTest : public cros::DlcClient {
 public:
  DlcClientForTest(
      base::OnceCallback<void(const base::FilePath&)> dlc_root_path_cb,
      base::OnceCallback<void(const std::string&)> error_cb,
      const base::FilePath path)
      : dlc_root_path_cb_(std::move(dlc_root_path_cb)),
        error_cb_(std::move(error_cb)),
        path_(path) {}

  void InstallDlc() override {
    base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, base::BindOnce(&DlcClientForTest::InvokeSuccessCb,
                                  base::Unretained(this)));
  }

  void InvokeSuccessCb() {
    if (dlc_root_path_cb_)
      std::move(dlc_root_path_cb_).Run(path_);
  }

  base::OnceCallback<void(const base::FilePath&)> dlc_root_path_cb_;
  base::OnceCallback<void(const std::string&)> error_cb_;
  const base::FilePath path_;
};

}  // namespace

namespace cros {

#ifdef USE_LOCAL_ML_CORE_INTERNAL
// TODO(nbowe): work out why this is building this lib once for ml_core
// then again for ml
const base::FilePath* path_for_test = new base::FilePath("/usr/local/lib64");
#else
const base::FilePath* path_for_test = nullptr;
#endif

std::unique_ptr<DlcClient> DlcClient::Create(
    base::OnceCallback<void(const base::FilePath&)> dlc_root_path_cb,
    base::OnceCallback<void(const std::string&)> error_cb) {
  if (path_for_test) {
    auto client = std::make_unique<DlcClientForTest>(
        std::move(dlc_root_path_cb), std::move(error_cb), *path_for_test);
    return client;
  } else {
    auto client = std::make_unique<DlcClientImpl>();
    client->Initialize(std::move(dlc_root_path_cb), std::move(error_cb));
    return client;
  }
}
void DlcClient::SetDlcPathForTest(const base::FilePath* path) {
  path_for_test = path;
}

}  // namespace cros

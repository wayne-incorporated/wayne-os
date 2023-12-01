// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <utility>

#include <base/logging.h>
#include <base/time/time.h>
#include <brillo/dbus/dbus_connection.h>
#include <libcrossystem/crossystem.h>
#include <libhwsec-foundation/tpm/tpm_version.h>
#include <tpm_manager/proto_bindings/tpm_manager.pb.h>
#include <tpm_manager-client/tpm_manager/dbus-proxies.h>

#if USE_TPM2
#include <trunks/trunks_dbus_proxy.h>
#include <trunks/trunks_factory_impl.h>
#endif

#if USE_TPM1
#include "libhwsec/overalls/overalls.h"
#endif

#include "libhwsec/platform/platform_impl.h"
#include "libhwsec/proxy/proxy_impl.h"

namespace {
// Default D-Bus connection Timeout
constexpr base::TimeDelta kDefaultTimeout = base::Minutes(5);
}  // namespace

namespace hwsec {

struct ProxyImpl::InnerData {
  brillo::DBusConnection connection;

#if USE_TPM1
  std::unique_ptr<hwsec::overalls::Overalls> overalls;
#endif

#if USE_TPM2
  std::unique_ptr<trunks::TrunksDBusProxy> trunks_dbus_proxy;
  std::unique_ptr<trunks::TrunksFactoryImpl> trunks_factory;
#endif

  std::unique_ptr<org::chromium::TpmManagerProxy> tpm_manager;
  std::unique_ptr<org::chromium::TpmNvramProxy> tpm_nvram;
  std::unique_ptr<crossystem::Crossystem> crossystem;
  std::unique_ptr<Platform> platform;
};

ProxyImpl::ProxyImpl() = default;

ProxyImpl::~ProxyImpl() = default;

bool ProxyImpl::Init() {
  inner_data_ = std::make_unique<ProxyImpl::InnerData>();

  // Initialize the D-Bus connection.

  scoped_refptr<dbus::Bus> bus =
      inner_data_->connection.ConnectWithTimeout(kDefaultTimeout);

  if (!bus) {
    LOG(ERROR) << "Failed to connect to system bus through libbrillo";
    return false;
  }

  // Initialize the internal data.

  TPM_SELECT_BEGIN;
  TPM1_SECTION({
    inner_data_->overalls = std::make_unique<hwsec::overalls::Overalls>();
  });
  TPM2_SECTION({
    inner_data_->trunks_dbus_proxy =
        std::make_unique<trunks::TrunksDBusProxy>(bus);
    if (!inner_data_->trunks_dbus_proxy->Init()) {
      LOG(ERROR) << "Failed to initialize trunks D-Bus proxy.";
      return false;
    }

    inner_data_->trunks_factory = std::make_unique<trunks::TrunksFactoryImpl>(
        inner_data_->trunks_dbus_proxy.get());
    if (!inner_data_->trunks_factory->Initialize()) {
      LOG(ERROR) << "Failed to initialize trunks factory.";
      return false;
    }
  });
  OTHER_TPM_SECTION({});
  TPM_SELECT_END;

  std::unique_ptr<org::chromium::TpmManagerProxy> tpm_manager;
  std::unique_ptr<org::chromium::TpmNvramProxy> tpm_nvram;

  inner_data_->tpm_manager =
      std::make_unique<org::chromium::TpmManagerProxy>(bus);
  inner_data_->tpm_nvram = std::make_unique<org::chromium::TpmNvramProxy>(bus);
  inner_data_->crossystem = std::make_unique<crossystem::Crossystem>();
  inner_data_->platform = std::make_unique<PlatformImpl>();

  // Export the pointer to the proxy interface.

  TPM_SELECT_BEGIN;
  TPM1_SECTION({ Proxy::SetOveralls(inner_data_->overalls.get()); });
  TPM2_SECTION({
    Proxy::SetTrunksCommandTransceiver(inner_data_->trunks_dbus_proxy.get());
    Proxy::SetTrunksFactory(inner_data_->trunks_factory.get());
  });
  OTHER_TPM_SECTION({});
  TPM_SELECT_END;

  Proxy::SetTpmManager(inner_data_->tpm_manager.get());
  Proxy::SetTpmNvram(inner_data_->tpm_nvram.get());
  Proxy::SetCrossystem(inner_data_->crossystem.get());
  Proxy::SetPlatform(inner_data_->platform.get());

  return true;
}

}  // namespace hwsec

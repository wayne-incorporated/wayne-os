// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/mojom/mojo_passpoint_service.h"

#include <memory>
#include <utility>
#include <vector>

#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>

#include "mojom/passpoint.mojom.h"
#include "shill/certificate_file.h"
#include "shill/manager.h"
#include "shill/refptr_types.h"
#include "shill/wifi/passpoint_credentials.h"
#include "shill/wifi/wifi_provider.h"
#include "shill/wifi/wifi_service.h"

namespace shill {

namespace mojom = chromeos::connectivity::mojom;

constexpr char kPEMHeader[] = "-----BEGIN CERTIFICATE-----";
constexpr char kPEMFooter[] = "-----END CERTIFICATE-----";

MojoPasspointService::MojoPasspointService(Manager* manager)
    : manager_(manager) {}

MojoPasspointService::~MojoPasspointService() = default;

void MojoPasspointService::GetPasspointSubscription(
    const std::string& id, GetPasspointSubscriptionCallback callback) {
  WiFiProvider* provider = manager_->wifi_provider();
  CHECK(provider);

  PasspointCredentialsRefPtr creds = provider->FindCredentials(id);
  if (!creds) {
    LOG(WARNING) << __func__ << " Credentials " << id << " not found";
    std::move(callback).Run(nullptr);
    return;
  }

  std::move(callback).Run(CredentialsToSubscription(creds));
}

void MojoPasspointService::ListPasspointSubscriptions(
    ListPasspointSubscriptionsCallback callback) {
  WiFiProvider* provider = manager_->wifi_provider();
  CHECK(provider);

  std::vector<mojom::PasspointSubscriptionPtr> subs;
  for (const auto& creds : provider->GetCredentials()) {
    subs.push_back(CredentialsToSubscription(creds));
  }

  std::move(callback).Run(std::move(subs));
}

void MojoPasspointService::DeletePasspointSubscription(
    const std::string& id, DeletePasspointSubscriptionCallback callback) {
  WiFiProvider* provider = manager_->wifi_provider();
  CHECK(provider);

  PasspointCredentialsRefPtr creds = provider->FindCredentials(id);
  if (!creds) {
    LOG(WARNING) << __func__ << " Credentials " << id << " not found";
    std::move(callback).Run(false);
    return;
  }

  if (!provider->ForgetCredentials(creds)) {
    LOG(ERROR) << __func__ << " failed to forget credentials " << id;
    std::move(callback).Run(false);
    return;
  }

  std::move(callback).Run(true);
}

void MojoPasspointService::RegisterPasspointListener(
    mojo::PendingRemote<mojom::PasspointEventsListener> listener) {
  listeners_.Add(std::move(listener));
}

void MojoPasspointService::OnPasspointCredentialsAdded(
    const PasspointCredentialsRefPtr& creds) {
  for (auto& listener : listeners_) {
    listener->OnPasspointSubscriptionAdded(CredentialsToSubscription(creds));
  }
}

void MojoPasspointService::OnPasspointCredentialsRemoved(
    const PasspointCredentialsRefPtr& creds) {
  for (auto& listener : listeners_) {
    listener->OnPasspointSubscriptionRemoved(CredentialsToSubscription(creds));
  }
}

mojom::PasspointSubscriptionPtr MojoPasspointService::CredentialsToSubscription(
    const PasspointCredentialsRefPtr creds) {
  WiFiProvider* provider = manager_->wifi_provider();
  CHECK(provider);
  CHECK(creds);

  std::string ca_pem;
  if (!creds->eap().ca_cert_pem().empty()) {
    std::string content = CertificateFile::ExtractHexData(
        base::JoinString(creds->eap().ca_cert_pem(), "\n"));
    ca_pem = base::StringPrintf("%s\n%s\n%s\n", kPEMHeader, content.c_str(),
                                kPEMFooter);
  }

  return mojom::PasspointSubscription::New(
      creds->id(), creds->domains(), creds->friendly_name(),
      creds->android_package_name(), ca_pem,
      creds->expiration_time_milliseconds());
}

}  // namespace shill

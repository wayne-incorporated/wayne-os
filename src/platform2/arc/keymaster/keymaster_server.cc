// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/keymaster/keymaster_server.h"

#include <utility>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/task/single_thread_task_runner.h>
#include <base/threading/platform_thread.h>
#include <keymaster/android_keymaster_messages.h>
#include <mojo/cert_store.mojom.h>
#include <mojo/keymaster.mojom.h>

#include "arc/keymaster/conversion.h"

// The implementations of |arc::mojom::KeymasterServer| methods below have the
// following overall pattern:
//
// * Generate an std::unique_ptr to a Keymaster request data structure from the
//   arguments received from Mojo, usually through the helpers in conversion.h.
//
// * Execute the operation in |backend->keymaster()|, posting this task to a
//   background thread. This produces a Keymaster response data structure.
//
// * Post the response to a callback that runs on the original thread (in this
//   case, the Mojo thread where the request started).
//
// * Convert the Keymaster response to the Mojo return values, and run the
//   result callback.
//
namespace arc {
namespace keymaster {

namespace {

constexpr size_t kOperationTableSize = 16;

}  // namespace

KeymasterServer::Backend::Backend()
    : context_(new context::ArcKeymasterContext()),
      keymaster_(context_, kOperationTableSize) {}

KeymasterServer::Backend::~Backend() = default;

KeymasterServer::KeymasterServer()
    : backend_thread_("BackendKeymasterThread"), weak_ptr_factory_(this) {
  CHECK(backend_thread_.Start()) << "Failed to start keymaster thread";
}

KeymasterServer::~KeymasterServer() = default;

void KeymasterServer::UpdateContextPlaceholderKeys(
    std::vector<mojom::ChromeOsKeyPtr> keys,
    base::OnceCallback<void(bool)> callback) {
  base::OnceCallback<void(bool)> callback_in_original_runner = base::BindOnce(
      [](scoped_refptr<base::TaskRunner> original_task_runner,
         base::OnceCallback<void(bool)> callback, bool success) {
        original_task_runner->PostTask(
            FROM_HERE, base::BindOnce(std::move(callback), success));
      },
      base::SingleThreadTaskRunner::GetCurrentDefault(), std::move(callback));

  backend_thread_.task_runner()->PostTask(
      FROM_HERE, base::BindOnce(
                     [](context::ArcKeymasterContext* context,
                        std::vector<mojom::ChromeOsKeyPtr> keys,
                        base::OnceCallback<void(bool)> callback) {
                       // |context| is guaranteed valid here because it's owned
                       // by |backend_|, which outlives the |backend_thread_|
                       // this runs on.
                       context->set_placeholder_keys(std::move(keys));
                       std::move(callback).Run(/*success=*/true);
                     },
                     backend_.context(), std::move(keys),
                     std::move(callback_in_original_runner)));
}

void KeymasterServer::SetSystemVersion(uint32_t os_version,
                                       uint32_t os_patchlevel) {
  backend_thread_.task_runner()->PostTask(
      FROM_HERE, base::BindOnce(
                     [](context::ArcKeymasterContext* context,
                        uint32_t os_version, uint32_t os_patchlevel) {
                       // |context| is guaranteed valid here because it's owned
                       // by |backend_|, which outlives the |backend_thread_|
                       // this runs on.
                       context->SetSystemVersion(os_version, os_patchlevel);
                     },
                     backend_.context(), os_version, os_patchlevel));
}

template <typename KmMember, typename KmRequest, typename KmResponse>
void KeymasterServer::RunKeymasterRequest(
    const base::Location& location,
    KmMember member,
    std::unique_ptr<KmRequest> request,
    base::OnceCallback<void(std::unique_ptr<KmResponse>)> callback) {
  // Post the Keymaster operation to a background thread while capturing the
  // current task runner.
  backend_thread_.task_runner()->PostTask(
      location,
      base::BindOnce(
          [](const base::Location& location,
             scoped_refptr<base::TaskRunner> original_task_runner,
             ::keymaster::AndroidKeymaster* keymaster, KmMember member,
             std::unique_ptr<KmRequest> request,
             base::OnceCallback<void(std::unique_ptr<KmResponse>)> callback) {
            // Prepare a Keymaster response data structure.
            auto response = std::make_unique<KmResponse>();
            // Execute the operation.
            (*keymaster.*member)(*request, response.get());
            // Post |callback| to the |original_task_runner| given |response|.
            original_task_runner->PostTask(
                location,
                base::BindOnce(std::move(callback), std::move(response)));
          },
          location, base::SingleThreadTaskRunner::GetCurrentDefault(),
          backend_.keymaster(), member, std::move(request),
          std::move(callback)));
}

void KeymasterServer::AddRngEntropy(const std::vector<uint8_t>& data,
                                    AddRngEntropyCallback callback) {
  // Convert input |data| into |km_request|. All data is deep copied to avoid
  // use-after-free.
  auto km_request = std::make_unique<::keymaster::AddEntropyRequest>();
  ConvertToMessage(data, &km_request->random_data);

  // Call keymaster.
  RunKeymasterRequest(
      FROM_HERE, &::keymaster::AndroidKeymaster::AddRngEntropy,
      std::move(km_request),
      base::BindOnce(
          [](AddRngEntropyCallback callback,
             std::unique_ptr<::keymaster::AddEntropyResponse> km_response) {
            // Run callback.
            std::move(callback).Run(km_response->error);
          },
          std::move(callback)));
}

void KeymasterServer::GetKeyCharacteristics(
    ::arc::mojom::GetKeyCharacteristicsRequestPtr request,
    GetKeyCharacteristicsCallback callback) {
  // Convert input |request| into |km_request|. All data is deep copied to avoid
  // use-after-free.
  auto km_request = MakeGetKeyCharacteristicsRequest(request);

  // Call keymaster.
  RunKeymasterRequest(
      FROM_HERE, &::keymaster::AndroidKeymaster::GetKeyCharacteristics,
      std::move(km_request),
      base::BindOnce(
          [](GetKeyCharacteristicsCallback callback,
             std::unique_ptr<::keymaster::GetKeyCharacteristicsResponse>
                 km_response) {
            // Prepare mojo response.
            auto response = MakeGetKeyCharacteristicsResult(*km_response);
            // Run callback.
            std::move(callback).Run(std::move(response));
          },
          std::move(callback)));
}

void KeymasterServer::GenerateKey(
    std::vector<::arc::mojom::KeyParameterPtr> key_params,
    GenerateKeyCallback callback) {
  // Convert input |key_params| into |km_request|. All data is deep copied to
  // avoid use-after-free.
  auto km_request = MakeGenerateKeyRequest(key_params);

  // Call keymaster.
  RunKeymasterRequest(
      FROM_HERE, &::keymaster::AndroidKeymaster::GenerateKey,
      std::move(km_request),
      base::BindOnce(
          [](GenerateKeyCallback callback,
             std::unique_ptr<::keymaster::GenerateKeyResponse> km_response) {
            // Prepare mojo response.
            auto response = MakeGenerateKeyResult(*km_response);
            // Run callback.
            std::move(callback).Run(std::move(response));
          },
          std::move(callback)));
}

void KeymasterServer::ImportKey(arc::mojom::ImportKeyRequestPtr request,
                                ImportKeyCallback callback) {
  // Convert input |request| into |km_request|. All data is deep copied to avoid
  // use-after-free.
  auto km_request = MakeImportKeyRequest(request);

  // Call keymaster.
  RunKeymasterRequest(
      FROM_HERE, &::keymaster::AndroidKeymaster::ImportKey,
      std::move(km_request),
      base::BindOnce(
          [](ImportKeyCallback callback,
             std::unique_ptr<::keymaster::ImportKeyResponse> km_response) {
            // Prepare mojo response.
            auto response = MakeImportKeyResult(*km_response);
            // Run callback.
            std::move(callback).Run(std::move(response));
          },
          std::move(callback)));
}

void KeymasterServer::ExportKey(arc::mojom::ExportKeyRequestPtr request,
                                ExportKeyCallback callback) {
  // Convert input |request| into |km_request|. All data is deep copied to avoid
  // use-after-free.
  auto km_request = MakeExportKeyRequest(request);

  // Call keymaster.
  RunKeymasterRequest(
      FROM_HERE, &::keymaster::AndroidKeymaster::ExportKey,
      std::move(km_request),
      base::BindOnce(
          [](ExportKeyCallback callback,
             std::unique_ptr<::keymaster::ExportKeyResponse> km_response) {
            // Prepare mojo response.
            auto response = MakeExportKeyResult(*km_response);
            // Run callback.
            std::move(callback).Run(std::move(response));
          },
          std::move(callback)));
}

void KeymasterServer::AttestKey(arc::mojom::AttestKeyRequestPtr request,
                                AttestKeyCallback callback) {
  // Convert input |request| into |km_request|. All data is deep copied to avoid
  // use-after-free.
  auto km_request = MakeAttestKeyRequest(request);

  // Call keymaster.
  RunKeymasterRequest(
      FROM_HERE, &::keymaster::AndroidKeymaster::AttestKey,
      std::move(km_request),
      base::BindOnce(
          [](AttestKeyCallback callback,
             std::unique_ptr<::keymaster::AttestKeyResponse> km_response) {
            // Prepare mojo response.
            auto response = MakeAttestKeyResult(*km_response);
            // Run callback.
            std::move(callback).Run(std::move(response));
          },
          std::move(callback)));
}

void KeymasterServer::UpgradeKey(arc::mojom::UpgradeKeyRequestPtr request,
                                 UpgradeKeyCallback callback) {
  // Convert input |request| into |km_request|. All data is deep copied to avoid
  // use-after-free.
  auto km_request = MakeUpgradeKeyRequest(request);

  // Call keymaster.
  RunKeymasterRequest(
      FROM_HERE, &::keymaster::AndroidKeymaster::UpgradeKey,
      std::move(km_request),
      base::BindOnce(
          [](UpgradeKeyCallback callback,
             std::unique_ptr<::keymaster::UpgradeKeyResponse> km_response) {
            // Prepare mojo response.
            auto response = MakeUpgradeKeyResult(*km_response);
            // Run callback.
            std::move(callback).Run(std::move(response));
          },
          std::move(callback)));
}

void KeymasterServer::DeleteKey(const std::vector<uint8_t>& key_blob,
                                DeleteKeyCallback callback) {
  // Convert input |key_blob| into |km_request|. All data is deep copied to
  // avoid use-after-free.
  auto km_request = std::make_unique<::keymaster::DeleteKeyRequest>();
  km_request->SetKeyMaterial(key_blob.data(), key_blob.size());

  // Call keymaster.
  RunKeymasterRequest(
      FROM_HERE, &::keymaster::AndroidKeymaster::DeleteKey,
      std::move(km_request),
      base::BindOnce(
          [](DeleteKeyCallback callback,
             std::unique_ptr<::keymaster::DeleteKeyResponse> km_response) {
            // Run callback.
            std::move(callback).Run(km_response->error);
          },
          std::move(callback)));
}

void KeymasterServer::DeleteAllKeys(DeleteAllKeysCallback callback) {
  // Prepare keymaster request.
  auto km_request = std::make_unique<::keymaster::DeleteAllKeysRequest>();

  // Call keymaster.
  RunKeymasterRequest(
      FROM_HERE, &::keymaster::AndroidKeymaster::DeleteAllKeys,
      std::move(km_request),
      base::BindOnce(
          [](DeleteAllKeysCallback callback,
             std::unique_ptr<::keymaster::DeleteAllKeysResponse> km_response) {
            // Run callback.
            std::move(callback).Run(km_response->error);
          },
          std::move(callback)));
}

void KeymasterServer::Begin(arc::mojom::BeginRequestPtr request,
                            BeginCallback callback) {
  // Convert input |request| into |km_request|. All data is deep copied to avoid
  // use-after-free.
  auto km_request = MakeBeginOperationRequest(request);

  // Call keymaster.
  RunKeymasterRequest(
      FROM_HERE, &::keymaster::AndroidKeymaster::BeginOperation,
      std::move(km_request),
      base::BindOnce(
          [](BeginCallback callback,
             std::unique_ptr<::keymaster::BeginOperationResponse> km_response) {
            // Prepare mojo response.
            auto response = MakeBeginResult(*km_response);
            // Run callback.
            std::move(callback).Run(std::move(response));
          },
          std::move(callback)));
}

void KeymasterServer::Update(arc::mojom::UpdateRequestPtr request,
                             UpdateCallback callback) {
  // Convert input |request| into |km_request|. All data is deep copied to avoid
  // use-after-free.
  auto km_request = MakeUpdateOperationRequest(request);

  // Call keymaster.
  RunKeymasterRequest(
      FROM_HERE, &::keymaster::AndroidKeymaster::UpdateOperation,
      std::move(km_request),
      base::BindOnce(
          [](UpdateCallback callback,
             std::unique_ptr<::keymaster::UpdateOperationResponse>
                 km_response) {
            // Prepare mojo response.
            auto response = MakeUpdateResult(*km_response);
            // Run callback.
            std::move(callback).Run(std::move(response));
          },
          std::move(callback)));
}

void KeymasterServer::Finish(arc::mojom::FinishRequestPtr request,
                             FinishCallback callback) {
  // Convert input |request| into |km_request|. All data is deep copied to avoid
  // use-after-free.
  auto km_request = MakeFinishOperationRequest(request);

  // Call keymaster.
  RunKeymasterRequest(
      FROM_HERE, &::keymaster::AndroidKeymaster::FinishOperation,
      std::move(km_request),
      base::BindOnce(
          [](FinishCallback callback,
             std::unique_ptr<::keymaster::FinishOperationResponse>
                 km_response) {
            // Prepare mojo response.
            auto response = MakeFinishResult(*km_response);
            // Run callback.
            std::move(callback).Run(std::move(response));
          },
          std::move(callback)));
}

void KeymasterServer::Abort(uint64_t op_handle, AbortCallback callback) {
  // Prepare keymaster request.
  auto km_request = std::make_unique<::keymaster::AbortOperationRequest>();
  km_request->op_handle = op_handle;

  // Call keymaster.
  RunKeymasterRequest(
      FROM_HERE, &::keymaster::AndroidKeymaster::AbortOperation,
      std::move(km_request),
      base::BindOnce(
          [](AbortCallback callback,
             std::unique_ptr<::keymaster::AbortOperationResponse> km_response) {
            // Run callback.
            std::move(callback).Run(km_response->error);
          },
          std::move(callback)));
}

}  // namespace keymaster
}  // namespace arc

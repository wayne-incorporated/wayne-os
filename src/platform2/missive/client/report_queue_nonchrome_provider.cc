// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "missive/client/report_queue_nonchrome_provider.h"

#include <memory>
#include <string>
#include <utility>

#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/memory/scoped_refptr.h>
#include <base/memory/singleton.h>
#include <base/strings/strcat.h>
#include <base/strings/string_number_conversions.h>
#include <base/task/bind_post_task.h>
#include <base/task/sequenced_task_runner.h>

#include "missive/client/empty_dm_token_retriever.h"
#include "missive/client/missive_client.h"
#include "missive/client/report_queue.h"
#include "missive/client/report_queue_configuration.h"
#include "missive/client/report_queue_impl.h"
#include "missive/client/report_queue_provider.h"
#include "missive/proto/record_constants.pb.h"
#include "missive/storage/missive_storage_module.h"
#include "missive/storage/missive_storage_module_delegate_impl.h"
#include "missive/storage/storage_module_interface.h"
#include "missive/util/status.h"
#include "missive/util/statusor.h"

namespace reporting {

NonChromeReportQueueProvider::NonChromeReportQueueProvider()
    : ReportQueueProvider(
          base::BindRepeating(
              [](base::OnceCallback<void(
                     StatusOr<scoped_refptr<StorageModuleInterface>>)>
                     storage_created_cb) {
                CreateMissiveStorageModule(std::move(storage_created_cb));
              }),
          base::SequencedTaskRunner::GetCurrentDefault()),
      actual_provider_(this) {}

void NonChromeReportQueueProvider::ConfigureReportQueue(
    std::unique_ptr<ReportQueueConfiguration> configuration,
    ReportQueueProvider::ReportQueueConfiguredCallback completion_cb) {
  // If DM token has already been set (only likely for testing purposes or
  // until pre-existing events are migrated over to use event types instead),
  // we do nothing and trigger completion callback with report queue config.
  if (!configuration->dm_token().empty()) {
    std::move(completion_cb).Run(std::move(configuration));
    return;
  }

  if (configuration->event_type() != EventType::kDevice) {
    std::move(completion_cb)
        .Run(Status(error::INTERNAL,
                    base::StrCat({"No DM token retriever found for event type=",
                                  base::NumberToString(static_cast<int>(
                                      configuration->event_type()))})));
    return;
  }
  auto dm_token_retriever = std::make_unique<EmptyDMTokenRetriever>();
  dm_token_retriever->RetrieveDMToken(base::BindOnce(
      [](std::unique_ptr<ReportQueueConfiguration> configuration,
         ReportQueueProvider::ReportQueueConfiguredCallback completion_cb,
         StatusOr<std::string> dm_token_result) {
        // Trigger completion callback with error if there was an error
        // retrieving DM token.
        if (!dm_token_result.ok()) {
          std::move(completion_cb).Run(dm_token_result.status());
          return;
        }

        // Set DM token in config and trigger completion callback with the
        // corresponding result.
        auto config_result =
            configuration->SetDMToken(dm_token_result.ValueOrDie());

        // Fail on error
        if (!config_result.ok()) {
          std::move(completion_cb).Run(config_result);
          return;
        }

        // Success, run completion callback with updated config
        std::move(completion_cb).Run(std::move(configuration));
      },
      std::move(configuration), std::move(completion_cb)));
}

// static
NonChromeReportQueueProvider* NonChromeReportQueueProvider::GetInstance() {
  return base::Singleton<NonChromeReportQueueProvider>::get();
}

void NonChromeReportQueueProvider::SetForTesting(
    ReportQueueProvider* provider) {
  actual_provider_ = provider;
}

// static
void NonChromeReportQueueProvider::CreateMissiveStorageModule(
    base::OnceCallback<void(StatusOr<scoped_refptr<StorageModuleInterface>>)>
        cb) {
  MissiveClient* const missive_client = MissiveClient::Get();
  if (!missive_client) {
    std::move(cb).Run(Status(
        error::FAILED_PRECONDITION,
        "Missive Client unavailable, probably has not been initialized"));
    return;
  }
  // Refer to the storage module.
  auto missive_storage_module_delegate =
      std::make_unique<MissiveStorageModuleDelegateImpl>(
          base::BindPostTask(missive_client->origin_task_runner(),
                             base::BindRepeating(&MissiveClient::EnqueueRecord,
                                                 missive_client->GetWeakPtr())),
          base::BindPostTask(
              missive_client->origin_task_runner(),
              base::BindRepeating(&MissiveClient::Flush,
                                  missive_client->GetWeakPtr())));
  auto missive_storage_module =
      MissiveStorageModule::Create(std::move(missive_storage_module_delegate));
  if (!missive_storage_module) {
    std::move(cb).Run(Status(error::FAILED_PRECONDITION,
                             "Missive Storage Module failed to create"));
    return;
  }
  LOG(WARNING) << "Store reporting data by a Missive daemon";
  std::move(cb).Run(missive_storage_module);
  return;
}

// static
ReportQueueProvider* ReportQueueProvider::GetInstance() {
  return NonChromeReportQueueProvider::GetInstance()->actual_provider();
}

}  // namespace reporting

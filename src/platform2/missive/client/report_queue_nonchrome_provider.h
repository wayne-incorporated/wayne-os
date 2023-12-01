// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MISSIVE_CLIENT_REPORT_QUEUE_NONCHROME_PROVIDER_H_
#define MISSIVE_CLIENT_REPORT_QUEUE_NONCHROME_PROVIDER_H_

#include <memory>
#include <string>

#include <base/functional/callback.h>
#include <base/memory/scoped_refptr.h>

#include "missive/client/report_queue.h"
#include "missive/client/report_queue_configuration.h"
#include "missive/client/report_queue_provider.h"
#include "missive/proto/record_constants.pb.h"
#include "missive/storage/storage_module_interface.h"
#include "missive/util/statusor.h"

namespace reporting {

class NonChromeReportQueueProvider : public ReportQueueProvider {
 public:
  NonChromeReportQueueProvider();

  void ConfigureReportQueue(
      std::unique_ptr<ReportQueueConfiguration> report_queue_config,
      ReportQueueConfiguredCallback completion_cb) override;

  static NonChromeReportQueueProvider* GetInstance();

  ReportQueueProvider* actual_provider() const { return actual_provider_; }

  void SetForTesting(ReportQueueProvider* provider);

 private:
  static void CreateMissiveStorageModule(
      base::OnceCallback<void(StatusOr<scoped_refptr<StorageModuleInterface>>)>
          cb);

  ReportQueueProvider* actual_provider_;
};

}  // namespace reporting

#endif  // MISSIVE_CLIENT_REPORT_QUEUE_NONCHROME_PROVIDER_H_

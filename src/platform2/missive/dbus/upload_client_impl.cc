// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "missive/dbus/upload_client_impl.h"

#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "base/run_loop.h"
#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <base/memory/scoped_refptr.h>
#include <base/task/bind_post_task.h>
#include <dbus/bus.h>
#include <dbus/object_path.h>
#include <dbus/message.h>
#include <chromeos/dbus/service_constants.h>

#include "missive/proto/interface.pb.h"
#include "missive/proto/record.pb.h"
#include "missive/util/disconnectable_client.h"
#include "missive/util/status.h"
#include "missive/util/statusor.h"

namespace reporting {

UploadClientImpl::UploadClientImpl(scoped_refptr<dbus::Bus> bus,
                                   dbus::ObjectProxy* chrome_proxy)
    : UploadClient(bus->GetOriginTaskRunner()),
      bus_(bus),
      chrome_proxy_(chrome_proxy),
      client_(nullptr, base::OnTaskRunnerDeleter(bus_->GetOriginTaskRunner())) {
  bus->AssertOnOriginThread();
  chrome_proxy_->SetNameOwnerChangedCallback(base::BindRepeating(
      &UploadClientImpl::OwnerChanged, weak_ptr_factory_.GetWeakPtr()));
  chrome_proxy_->WaitForServiceToBeAvailable(base::BindOnce(
      &UploadClientImpl::ServerAvailable, weak_ptr_factory_.GetWeakPtr()));
}
UploadClientImpl::~UploadClientImpl() {
  bus_->GetOriginTaskRunner()->PostTask(
      FROM_HERE,
      base::BindOnce(
          [](scoped_refptr<dbus::Bus> bus) {
            // Remove proxy if it was set. Ignore result.
            bus->AssertOnOriginThread();
            bus->RemoveObjectProxy(
                chromeos::kChromeReportingServiceName,
                dbus::ObjectPath(chromeos::kChromeReportingServicePath),
                base::BindOnce(
                    []() { LOG(INFO) << "Upload client disconnected"; }));
          },
          bus_));
}

// static
void UploadClient::Create(
    scoped_refptr<dbus::Bus> bus,
    base::OnceCallback<void(StatusOr<scoped_refptr<UploadClient>>)> cb) {
  bus->GetOriginTaskRunner()->PostTask(
      FROM_HERE,
      base::BindOnce(
          [](scoped_refptr<dbus::Bus> bus,
             base::OnceCallback<void(StatusOr<scoped_refptr<UploadClientImpl>>)>
                 cb) {
            bus->AssertOnOriginThread();
            dbus::ObjectProxy* chrome_proxy = bus->GetObjectProxy(
                chromeos::kChromeReportingServiceName,
                dbus::ObjectPath(chromeos::kChromeReportingServicePath));
            CHECK(chrome_proxy);
            UploadClientImpl::Create(bus, chrome_proxy, std::move(cb));
          },
          bus,
          // Callback needs conversion of the result from UploadClientImpl to
          // UplocalClient.
          base::BindOnce(
              [](base::OnceCallback<void(StatusOr<scoped_refptr<UploadClient>>)>
                     cb,
                 StatusOr<scoped_refptr<UploadClientImpl>> result) {
                std::move(cb).Run(std::move(result));
              },
              std::move(cb))));
}

// static
void UploadClientImpl::Create(
    scoped_refptr<dbus::Bus> bus,
    dbus::ObjectProxy* chrome_proxy,
    base::OnceCallback<void(StatusOr<scoped_refptr<UploadClientImpl>>)> cb) {
  bus->GetDBusTaskRunner()->PostTask(
      FROM_HERE,
      base::BindOnce(
          [](scoped_refptr<dbus::Bus> bus, dbus::ObjectProxy* chrome_proxy,
             base::OnceCallback<void(StatusOr<scoped_refptr<UploadClientImpl>>)>
                 cb) {
            CHECK(bus->Connect());
            CHECK(bus->SetUpAsyncOperations());
            std::move(cb).Run(
                base::WrapRefCounted(new UploadClientImpl(bus, chrome_proxy)));
          },
          bus, base::Unretained(chrome_proxy), std::move(cb)));
}

// Class implements DisconnectableClient::Delegate specifically for dBus
// calls. Logic that handles dBus connect/disconnect cases remains with the
// base class.
class UploadEncryptedRecordDelegate : public DisconnectableClient::Delegate {
 public:
  UploadEncryptedRecordDelegate(
      std::vector<EncryptedRecord> records,
      const bool need_encryption_keys,
      uint64_t remaining_storage_capacity,
      std::optional<uint64_t> new_events_rate,
      scoped_refptr<dbus::Bus> bus,
      dbus::ObjectProxy* chrome_proxy,
      UploadClient::HandleUploadResponseCallback response_callback)
      : bus_(bus),
        chrome_proxy_(chrome_proxy),
        response_callback_(std::move(response_callback)) {
    bus_->AssertOnOriginThread();
    // Build the request.
    for (const auto& record : records) {
      request_.add_encrypted_record()->CheckTypeAndMergeFrom(record);
    }
    request_.set_need_encryption_keys(need_encryption_keys);
    request_.set_remaining_storage_capacity(remaining_storage_capacity);
    // If for some reason new events rate couldn't be calculated, leave the
    // field absent.
    if (new_events_rate.has_value()) {
      request_.set_new_events_rate(new_events_rate.value());
    }
  }

  // Implementation of DisconnectableClient::Delegate
  void DoCall(base::OnceClosure cb) final {
    bus_->AssertOnOriginThread();
    base::ScopedClosureRunner autorun(std::move(cb));
    dbus::MethodCall method_call(
        chromeos::kChromeReportingServiceInterface,
        chromeos::kChromeReportingServiceUploadEncryptedRecordMethod);
    dbus::MessageWriter writer(&method_call);
    if (!writer.AppendProtoAsArrayOfBytes(request_)) {
      Status status(error::UNKNOWN,
                    "MessageWriter was unable to append the request.");
      LOG(ERROR) << status;
      std::move(response_callback_).Run(status);
      return;
    }

    // Make a dBus call.
    chrome_proxy_->CallMethod(
        &method_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT,
        base::BindPostTask(
            bus_->GetOriginTaskRunner(),
            base::BindOnce(&UploadEncryptedRecordDelegate::DoResponse,
                           weak_ptr_factory_.GetWeakPtr(),
                           std::move(autorun))));
  }

  // Process dBus response, if status is OK, or error otherwise.
  void Respond(Status status) final {
    bus_->AssertOnOriginThread();
    if (!response_callback_) {
      return;
    }

    if (!status.ok()) {
      std::move(response_callback_).Run(status);
      return;
    }

    if (!response_) {
      std::move(response_callback_)
          .Run(Status(error::UNAVAILABLE,
                      "Chrome is not responding, upload skipped."));
      return;
    }

    dbus::MessageReader reader(response_);
    UploadEncryptedRecordResponse response_body;
    if (!reader.PopArrayOfBytesAsProto(&response_body)) {
      std::move(response_callback_)
          .Run(Status(error::INTERNAL, "Response was not parsable."));
      return;
    }

    std::move(response_callback_).Run(std::move(response_body));
  }

 private:
  void DoResponse(base::ScopedClosureRunner autorun, dbus::Response* response) {
    bus_->AssertOnOriginThread();
    if (!response) {
      Respond(Status(error::UNAVAILABLE, "Returned no response"));
      return;
    }
    response_ = response;
  }

  dbus::Response* response_{nullptr};
  scoped_refptr<dbus::Bus> const bus_;
  dbus::ObjectProxy* const chrome_proxy_;

  UploadEncryptedRecordRequest request_;
  UploadClient::HandleUploadResponseCallback response_callback_;

  // Weak pointer factory - must be last member of the class.
  base::WeakPtrFactory<UploadEncryptedRecordDelegate> weak_ptr_factory_{this};
};

void UploadClientImpl::MaybeMakeCall(
    std::vector<EncryptedRecord> records,
    const bool need_encryption_keys,
    uint64_t remaining_storage_capacity,
    std::optional<uint64_t> new_events_rate,
    HandleUploadResponseCallback response_callback) {
  bus_->AssertOnOriginThread();
  auto delegate = std::make_unique<UploadEncryptedRecordDelegate>(
      std::move(records), need_encryption_keys, remaining_storage_capacity,
      new_events_rate, bus_, chrome_proxy_, std::move(response_callback));
  GetDisconnectableClient()->MaybeMakeCall(std::move(delegate));
}

DisconnectableClient* UploadClientImpl::GetDisconnectableClient() {
  bus_->AssertOnOriginThread();
  if (!client_) {
    client_ = std::unique_ptr<DisconnectableClient, base::OnTaskRunnerDeleter>(
        new DisconnectableClient(bus_->GetOriginTaskRunner()),
        base::OnTaskRunnerDeleter(bus_->GetOriginTaskRunner()));
  }
  return client_.get();
}

void UploadClientImpl::SendEncryptedRecords(
    std::vector<EncryptedRecord> records,
    const bool need_encryption_keys,
    uint64_t remaining_storage_capacity,
    std::optional<uint64_t> new_events_rate,
    HandleUploadResponseCallback response_callback) {
  bus_->GetOriginTaskRunner()->PostTask(
      FROM_HERE,
      base::BindOnce(&UploadClientImpl::MaybeMakeCall,
                     weak_ptr_factory_.GetWeakPtr(), std::move(records),
                     need_encryption_keys, remaining_storage_capacity,
                     new_events_rate, std::move(response_callback)));
}

void UploadClientImpl::OwnerChanged(const std::string& old_owner,
                                    const std::string& new_owner) {
  bus_->AssertOnOriginThread();
  GetDisconnectableClient()->SetAvailability(
      /*is_available=*/!new_owner.empty());
}

void UploadClientImpl::ServerAvailable(bool service_is_available) {
  bus_->AssertOnOriginThread();
  GetDisconnectableClient()->SetAvailability(
      /*is_available=*/service_is_available);
}

void UploadClientImpl::SetAvailabilityForTest(bool is_available) {
  base::RunLoop run_loop;
  bus_->GetOriginTaskRunner()->PostTask(
      FROM_HERE, base::BindOnce(&UploadClientImpl::ServerAvailable,
                                base::Unretained(this), is_available));
  bus_->GetOriginTaskRunner()->PostTask(FROM_HERE, run_loop.QuitClosure());
  run_loop.Run();
}
}  // namespace reporting

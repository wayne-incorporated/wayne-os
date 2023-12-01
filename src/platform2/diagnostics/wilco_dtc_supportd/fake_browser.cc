// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/wilco_dtc_supportd/fake_browser.h"

#include <memory>
#include <utility>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/strings/string_piece.h>
#include <dbus/message.h>
#include <dbus/wilco_dtc_supportd/dbus-constants.h>
#include <mojo/public/cpp/bindings/pending_remote.h>
#include <mojo/public/cpp/system/buffer.h>

#include "diagnostics/wilco_dtc_supportd/utils/mojo_utils.h"

namespace diagnostics {
namespace wilco {

using MojomWilcoDtcSupportdService =
    chromeos::wilco_dtc_supportd::mojom::WilcoDtcSupportdService;

FakeBrowser::FakeBrowser(
    mojo::Remote<MojomWilcoDtcSupportdServiceFactory>*
        wilco_dtc_supportd_service_factory,
    DBusMethodCallCallback bootstrap_mojo_connection_dbus_method)
    : wilco_dtc_supportd_service_factory_(wilco_dtc_supportd_service_factory),
      bootstrap_mojo_connection_dbus_method_(
          bootstrap_mojo_connection_dbus_method),
      wilco_dtc_supportd_client_receiver_(
          &wilco_dtc_supportd_client_ /* impl */) {
  DCHECK(wilco_dtc_supportd_service_factory_);
  DCHECK(!bootstrap_mojo_connection_dbus_method.is_null());
}

FakeBrowser::~FakeBrowser() = default;

bool FakeBrowser::BootstrapMojoConnection(
    FakeMojoFdGenerator* fake_mojo_fd_generator,
    base::OnceClosure bootstrap_mojo_connection_callback) {
  if (!CallBootstrapMojoConnectionDBusMethod(fake_mojo_fd_generator)) {
    std::move(bootstrap_mojo_connection_callback).Run();
    return false;
  }

  CallGetServiceMojoMethod(std::move(bootstrap_mojo_connection_callback));
  return true;
}

bool FakeBrowser::SendUiMessageToWilcoDtc(
    const std::string& json_message,
    base::OnceCallback<void(mojo::ScopedHandle)> callback) {
  mojo::ScopedHandle handle = CreateReadOnlySharedMemoryRegionMojoHandle(
      base::StringPiece(json_message));
  if (!handle.is_valid()) {
    return false;
  }
  wilco_dtc_supportd_service_->SendUiMessageToWilcoDtc(std::move(handle),
                                                       std::move(callback));
  return true;
}

void FakeBrowser::NotifyConfigurationDataChanged() {
  wilco_dtc_supportd_service_->NotifyConfigurationDataChanged();
}

bool FakeBrowser::CallBootstrapMojoConnectionDBusMethod(
    FakeMojoFdGenerator* fake_mojo_fd_generator) {
  // Prepare input data for the D-Bus call.
  const int kFakeMethodCallSerial = 1;
  dbus::MethodCall method_call(kWilcoDtcSupportdServiceInterface,
                               kWilcoDtcSupportdBootstrapMojoConnectionMethod);
  method_call.SetSerial(kFakeMethodCallSerial);
  dbus::MessageWriter message_writer(&method_call);
  message_writer.AppendFileDescriptor(fake_mojo_fd_generator->MakeFd().get());

  // Storage for the output data returned by the D-Bus call.
  std::unique_ptr<dbus::Response> response;
  const auto response_writer_callback = base::BindRepeating(
      [](std::unique_ptr<dbus::Response>* response,
         std::unique_ptr<dbus::Response> passed_response) {
        *response = std::move(passed_response);
      },
      &response);

  // Call the D-Bus method and extract its result.
  if (bootstrap_mojo_connection_dbus_method_.is_null())
    return false;
  bootstrap_mojo_connection_dbus_method_.Run(&method_call,
                                             response_writer_callback);
  return response && response->GetMessageType() != dbus::Message::MESSAGE_ERROR;
}

void FakeBrowser::CallGetServiceMojoMethod(
    base::OnceClosure get_service_mojo_method_callback) {
  // Queue a Mojo GetService() method call that allows to establish full-duplex
  // Mojo communication with the tested Mojo service.
  // After this call, |wilco_dtc_supportd_service_| can be used for requests
  // to the tested service and |wilco_dtc_supportd_client_| for receiving
  // requests made by the tested service. Note that despite that GetService() is
  // an asynchronous call, it's actually allowed to use
  // |wilco_dtc_supportd_service_| straight away, before the call completes.
  DCHECK(wilco_dtc_supportd_service_factory_);
  DCHECK(*wilco_dtc_supportd_service_factory_);
  mojo::PendingRemote<MojomWilcoDtcSupportdClient>
      wilco_dtc_supportd_client_proxy;
  wilco_dtc_supportd_client_receiver_.Bind(
      wilco_dtc_supportd_client_proxy.InitWithNewPipeAndPassReceiver());
  (*wilco_dtc_supportd_service_factory_)
      ->GetService(wilco_dtc_supportd_service_.BindNewPipeAndPassReceiver(),
                   std::move(wilco_dtc_supportd_client_proxy),
                   std::move(get_service_mojo_method_callback));
}

}  // namespace wilco
}  // namespace diagnostics

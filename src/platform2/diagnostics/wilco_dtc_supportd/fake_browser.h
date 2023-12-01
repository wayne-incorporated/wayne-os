// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_WILCO_DTC_SUPPORTD_FAKE_BROWSER_H_
#define DIAGNOSTICS_WILCO_DTC_SUPPORTD_FAKE_BROWSER_H_

#include <string>

#include <base/functional/callback.h>
#include <dbus/mock_exported_object.h>
#include <gmock/gmock.h>
#include <mojo/public/cpp/bindings/receiver.h>
#include <mojo/public/cpp/bindings/remote.h>

#include "diagnostics/mojom/public/wilco_dtc_supportd.mojom.h"
#include "diagnostics/wilco_dtc_supportd/mock_mojo_client.h"
#include "diagnostics/wilco_dtc_supportd/utils/mojo_test_utils.h"

namespace diagnostics {
namespace wilco {

// Helper class that allows to test communication between the browser and the
// tested code of the wilco_dtc_supportd daemon.
class FakeBrowser final {
 public:
  using DBusMethodCallCallback = dbus::ExportedObject::MethodCallCallback;

  using MojomWilcoDtcSupportdClient =
      chromeos::wilco_dtc_supportd::mojom::WilcoDtcSupportdClient;
  using MojomWilcoDtcSupportdService =
      chromeos::wilco_dtc_supportd::mojom::WilcoDtcSupportdService;
  using MojomWilcoDtcSupportdServiceFactory =
      chromeos::wilco_dtc_supportd::mojom::WilcoDtcSupportdServiceFactory;

  // |wilco_dtc_supportd_service_factory_ptr| is a pointer to the tested
  // WilcoDtcSupportdServiceFactory instance.
  // |bootstrap_mojo_connection_dbus_method| is the callback that the tested
  // code exposed as the BootstrapMojoConnection D-Bus method.
  FakeBrowser(mojo::Remote<MojomWilcoDtcSupportdServiceFactory>*
                  wilco_dtc_supportd_service_factory,
              DBusMethodCallCallback bootstrap_mojo_connection_dbus_method);
  FakeBrowser(const FakeBrowser&) = delete;
  FakeBrowser& operator=(const FakeBrowser&) = delete;

  ~FakeBrowser();

  // Returns a mock WilcoDtcSupportdClient instance, whose methods are invoked
  // when FakeBrowser receives incoming Mojo calls from the tested code.
  testing::StrictMock<MockMojoClient>* wilco_dtc_supportd_client() {
    return &wilco_dtc_supportd_client_;
  }

  // Call the BootstrapMojoConnection D-Bus method. Returns whether the D-Bus
  // call returned success.
  // |fake_mojo_fd_generator| is the fake file descriptor generator.
  // |bootstrap_mojo_connection_callback| is called when the boostrapping of the
  // mojo connection succeeds or fails.
  //
  // It's not allowed to call this method again after a successful completion.
  bool BootstrapMojoConnection(
      FakeMojoFdGenerator* fake_mojo_fd_generator,
      base::OnceClosure bootstrap_mojo_connection_callback);

  // Call the |SendUiMessageToWilcoDtc| Mojo method
  // on wilco_dtc_supportd daemon, which will call the |HandleMessageFromUi|
  // gRPC method on wilco_dtc.
  //
  // It simulates message sent from diagnostics UI extension to wilco_dtc.
  //
  // Returns false when we were not able to copy |json_message| into shared
  // buffer.
  //
  // Must be called only after a successful invocation of
  // BootstrapMojoConnection().
  bool SendUiMessageToWilcoDtc(
      const std::string& json_message,
      base::OnceCallback<void(mojo::ScopedHandle)> callback);

  // Call the |NotifyConfigurationDataChanged| Mojo method on wilco_dtc_supportd
  // daemon, which will call the corresponding gRPC method on wilco_dtc.
  //
  // It simulates the notification sent from the browser to wilco_dtc.
  //
  // Must be called only after a successful invocation of
  // BootstrapMojoConnection().
  void NotifyConfigurationDataChanged();

 private:
  // Calls |bootstrap_mojo_connection_dbus_method_| with a fake file descriptor.
  // Returns whether the method call succeeded (it's expected to happen
  // synchronously).
  bool CallBootstrapMojoConnectionDBusMethod(
      FakeMojoFdGenerator* fake_mojo_fd_generator);

  // Calls GetService() Mojo method on
  // |wilco_dtc_supportd_service_factory_|, initializes
  // |wilco_dtc_supportd_service_ptr_| so that it points to the tested service,
  // registers |wilco_dtc_supportd_client_| to handle incoming Mojo requests.
  // |get_service_mojo_method_callback| is called when the full-duplex Mojo
  // communication with the tested Mojo service is established.
  void CallGetServiceMojoMethod(
      base::OnceClosure get_service_mojo_method_callback);

  // Unowned. Points to the tested WilcoDtcSupportdServiceFactory instance.
  mojo::Remote<MojomWilcoDtcSupportdServiceFactory>* const
      wilco_dtc_supportd_service_factory_;
  // Fake substitute for the BootstrapMojoConnection() D-Bus method.
  DBusMethodCallCallback bootstrap_mojo_connection_dbus_method_;

  // Mock WilcoDtcSupportdClient instance. After an invocation of
  // CallGetServiceMojoMethod() it becomes registered to receive incoming Mojo
  // requests from the tested code.
  testing::StrictMock<MockMojoClient> wilco_dtc_supportd_client_;
  // Mojo receiver that is associated with |wilco_dtc_supportd_client_|.
  mojo::Receiver<MojomWilcoDtcSupportdClient>
      wilco_dtc_supportd_client_receiver_;

  // Mojo interface pointer to the WilcoDtcSupportdService service exposed by
  // the tested code. Gets initialized after a call to
  // CallGetServiceMojoMethod().
  mojo::Remote<MojomWilcoDtcSupportdService> wilco_dtc_supportd_service_;
};

}  // namespace wilco
}  // namespace diagnostics

#endif  // DIAGNOSTICS_WILCO_DTC_SUPPORTD_FAKE_BROWSER_H_

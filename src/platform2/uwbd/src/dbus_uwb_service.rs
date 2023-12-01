// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use tokio::runtime::Runtime;
use uwb_core::service::{
    default_runtime, ProtoUwbService, UwbServiceBuilder, UwbServiceCallbackSendBuilder,
};
use uwb_core::uci::pcapng_uci_logger_factory::PcapngUciLoggerFactoryBuilder;

use crate::dbus_bindings::server::OrgChromiumUwbd;
use crate::dbus_uwb_service_callback::DBusUwbServiceCallback;
use crate::uci_hal_impl::UciHalImpl;

pub struct DBusUwbService {
    service: ProtoUwbService,

    /// The working runtime, which should outlives the UwbService.
    ///
    /// Because the fields of a struct are dropped in declaration order, this field is guaranteed
    /// to be dropped after UwbService.
    _runtime: Runtime,
}

impl DBusUwbService {
    pub fn new(callback: DBusUwbServiceCallback) -> Option<Self> {
        let runtime = default_runtime()?;
        let uci_logger_factory = PcapngUciLoggerFactoryBuilder::new()
            .runtime_handle(runtime.handle().to_owned())
            .log_path("/var/tmp".into())
            .filename_prefix("uwb_uci".to_owned())
            .buffer_size(0)
            .build()?;
        let service = UwbServiceBuilder::new()
            .runtime_handle(runtime.handle().to_owned())
            .callback_builder(UwbServiceCallbackSendBuilder::new(callback))
            .uci_hal(UciHalImpl {})
            .uci_logger_factory(uci_logger_factory)
            .build()?;

        Some(Self {
            service: ProtoUwbService::new(service),
            _runtime: runtime,
        })
    }
}

/// Generate the DBusUwbService's method that delegates the command to ProtoUwbService.
///
/// generate_method!() is used for the method without argument.
/// generate_method_with_request!() is used for the method with a Vec<u8> argument.
macro_rules! generate_method {
    ($method_name:ident) => {
        fn $method_name(&mut self) -> Result<Vec<u8>, dbus::MethodErr> {
            self.service
                .$method_name()
                .map_err(|e| dbus::MethodErr::failed(&e))
        }
    };
}
macro_rules! generate_method_with_request {
    ($method_name:ident) => {
        fn $method_name(&mut self, request: Vec<u8>) -> Result<Vec<u8>, dbus::MethodErr> {
            self.service
                .$method_name(&request)
                .map_err(|e| dbus::MethodErr::failed(&e))
        }
    };
}

impl OrgChromiumUwbd for DBusUwbService {
    generate_method!(enable);
    generate_method!(disable);
    generate_method_with_request!(set_logger_mode);
    generate_method_with_request!(init_session);
    generate_method_with_request!(deinit_session);
    generate_method_with_request!(start_ranging);
    generate_method_with_request!(stop_ranging);
    generate_method_with_request!(session_params);
    generate_method_with_request!(reconfigure);
    generate_method_with_request!(update_controller_multicast_list);
    generate_method_with_request!(android_set_country_code);
    generate_method!(android_get_power_stats);
    generate_method_with_request!(raw_uci_cmd);
}

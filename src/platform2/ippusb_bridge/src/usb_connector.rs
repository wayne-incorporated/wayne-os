// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::VecDeque;
use std::fmt;
use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use std::vec::Vec;

use libchromeos::deprecated::{EventFd, PollContext};
use libchromeos::sys::{debug, error, info};
use rusb::{Direction, GlobalContext, Registration, TransferType, UsbContext};
use sync::{Condvar, Mutex};

const USB_TRANSFER_TIMEOUT: Duration = Duration::from_secs(60);
const USB_CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug)]
pub enum Error {
    ClaimInterface(u8, rusb::Error),
    ReleaseInterface(u8, rusb::Error),
    DetachDrivers(u8, rusb::Error),
    AttachDrivers(u8, rusb::Error),
    DeviceList(rusb::Error),
    OpenDevice(rusb::Error),
    CleanupThread(io::Error),
    ReadConfigDescriptor(rusb::Error),
    ReadDeviceDescriptor(rusb::Error),
    RegisterCallback(rusb::Error),
    SetActiveConfig(rusb::Error),
    SetAlternateSetting(u8, rusb::Error),
    NoDevice,
    NoFreeInterface,
    NotIppUsb,
    Poll(libchromeos::sys::Error),
}

impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Error::*;
        match self {
            ClaimInterface(i, err) => write!(f, "Failed to claim interface {}: {}", i, err),
            ReleaseInterface(i, err) => write!(f, "Failed to release interface {}: {}", i, err),
            DetachDrivers(i, err) => write!(
                f,
                "Failed to detach kernel driver for interface {}: {}",
                i, err
            ),
            AttachDrivers(i, err) => write!(
                f,
                "Failed to attach kernel driver for interface {}, {}",
                i, err
            ),
            DeviceList(err) => write!(f, "Failed to read device list: {}", err),
            OpenDevice(err) => write!(f, "Failed to open device: {}", err),
            CleanupThread(err) => write!(f, "Failed to start cleanup thread: {}", err),
            ReadConfigDescriptor(err) => write!(f, "Failed to read config descriptor: {}", err),
            ReadDeviceDescriptor(err) => write!(f, "Failed to read device descriptor: {}", err),
            RegisterCallback(err) => write!(f, "Failed to register for hotplug callback: {}", err),
            SetActiveConfig(err) => write!(f, "Failed to set active config: {}", err),
            SetAlternateSetting(i, err) => write!(
                f,
                "Failed to set interface {} alternate setting: {}",
                i, err
            ),
            NoDevice => write!(f, "No valid IPP USB device found."),
            NoFreeInterface => write!(f, "There is no free IPP USB interface to claim."),
            NotIppUsb => write!(f, "The specified device is not an IPP USB device."),
            Poll(err) => write!(f, "Error polling shutdown fd: {}", err),
        }
    }
}

type Result<T> = std::result::Result<T, Error>;

fn is_ippusb_interface(descriptor: &rusb::InterfaceDescriptor) -> bool {
    descriptor.class_code() == 0x07
        && descriptor.sub_class_code() == 0x01
        && descriptor.protocol_code() == 0x04
}

fn interface_contains_ippusb(interface: &rusb::Interface) -> bool {
    for descriptor in interface.descriptors() {
        if is_ippusb_interface(&descriptor) {
            return true;
        }
    }
    false
}

fn set_device_config(handle: &mut rusb::DeviceHandle<GlobalContext>, new_config: u8) -> Result<()> {
    let cur_config = handle
        .device()
        .active_config_descriptor()
        .map_err(Error::ReadConfigDescriptor)?;

    // While detaching any outstanding kernel drivers for the current config, keep
    // track of non-printer drivers so we can restore them after setting the config.
    let mut restore_interfaces = Vec::new();
    for interface in cur_config.interfaces() {
        if !interface_contains_ippusb(&interface) {
            match handle.kernel_driver_active(interface.number()) {
                Ok(false) => continue, // No active driver.
                Err(e) => return Err(Error::DetachDrivers(interface.number(), e)),
                _ => {}
            }

            info!(
                "Temporarily detaching kernel driver for non-printer interface {}",
                interface.number()
            );
            restore_interfaces.push(interface.number());
        }

        match handle.detach_kernel_driver(interface.number()) {
            Err(e) if e != rusb::Error::NotFound => {
                return Err(Error::DetachDrivers(interface.number(), e))
            }
            _ => {}
        }
    }

    info!(
        "Switching from configuration {} to {}",
        cur_config.number(),
        new_config
    );
    handle
        .set_active_configuration(new_config)
        .map_err(Error::SetActiveConfig)?;

    // Try to put back the previously detached drivers.  We don't return an error if one
    // of these fails because it won't prevent us from claiming the IPP-USB interfaces later.
    for inum in restore_interfaces {
        handle
            .attach_kernel_driver(inum)
            .unwrap_or_else(|e| error!("Failed to reattach driver for interface {}: {}", inum, e));
    }

    Ok(())
}

/// The information for an interface descriptor that supports IPPUSB.
/// Bulk transfers can be read/written to the in/out endpoints, respectively.
#[derive(Copy, Clone)]
struct IppusbDescriptor {
    interface_number: u8,
    alternate_setting: u8,
    in_endpoint: u8,
    out_endpoint: u8,
}

/// The configuration and descriptors that support IPPUSB for a USB device.
///  A valid IppusbDevice will have at least two interfaces.
struct IppusbDevice {
    config: u8,
    interfaces: Vec<IppusbDescriptor>,
}

/// Given a libusb Device, searches through the device's configurations to see if there is a
/// particular configuration that supports IPP over USB.  If such a configuration is found, returns
/// an IppusbDevice struct, which specifies the configuration as well as the IPPUSB interfaces
/// within that configuration.
///
/// If the given device does not support IPP over USB, returns None.
///
/// A device is considered to support IPP over USB if it has a configuration with at least two
/// IPPUSB interfaces.
///
/// An interface is considered an IPPUSB interface if it has the proper class, sub-class, and
/// protocol, and if it has a bulk-in and bulk-out endpoint.
fn read_ippusb_device_info<T: UsbContext>(
    device: &rusb::Device<T>,
) -> Result<Option<IppusbDevice>> {
    let desc = device
        .device_descriptor()
        .map_err(Error::ReadDeviceDescriptor)?;
    for i in 0..desc.num_configurations() {
        let config = device
            .config_descriptor(i)
            .map_err(Error::ReadConfigDescriptor)?;

        let mut interfaces = Vec::new();
        for interface in config.interfaces() {
            'alternates: for alternate in interface.descriptors() {
                if !is_ippusb_interface(&alternate) {
                    continue;
                }
                info!(
                    "Device {}:{} - Found IPPUSB interface. config {}, interface {}, alternate {}",
                    device.bus_number(),
                    device.address(),
                    config.number(),
                    interface.number(),
                    alternate.setting_number()
                );

                // Find the bulk in and out endpoints for this interface.
                let mut in_endpoint: Option<u8> = None;
                let mut out_endpoint: Option<u8> = None;
                for endpoint in alternate.endpoint_descriptors() {
                    match (endpoint.direction(), endpoint.transfer_type()) {
                        (Direction::In, TransferType::Bulk) => {
                            in_endpoint.get_or_insert(endpoint.address());
                        }
                        (Direction::Out, TransferType::Bulk) => {
                            out_endpoint.get_or_insert(endpoint.address());
                        }
                        _ => {}
                    };

                    if in_endpoint.is_some() && out_endpoint.is_some() {
                        break;
                    }
                }

                if let (Some(in_endpoint), Some(out_endpoint)) = (in_endpoint, out_endpoint) {
                    interfaces.push(IppusbDescriptor {
                        interface_number: interface.number(),
                        alternate_setting: alternate.setting_number(),
                        in_endpoint,
                        out_endpoint,
                    });
                    // We must consider at most one alternate setting when detecting IPPUSB
                    // interfaces.
                    break 'alternates;
                }
            }
        }

        // A device must have at least two IPPUSB interfaces in order to be considered an IPPUSB device.
        if interfaces.len() >= 2 {
            return Ok(Some(IppusbDevice {
                config: config.number(),
                interfaces,
            }));
        }
    }

    Ok(None)
}

struct ClaimedInterface {
    handle: rusb::DeviceHandle<GlobalContext>,
    descriptor: IppusbDescriptor,
}

impl ClaimedInterface {
    /// Send a USB claim for our interface and switch it to the correct alternate setting.
    fn claim(&mut self) -> Result<()> {
        self.handle
            .claim_interface(self.descriptor.interface_number)
            .map_err(|e| Error::ClaimInterface(self.descriptor.interface_number, e))?;
        self.handle
            .set_alternate_setting(
                self.descriptor.interface_number,
                self.descriptor.alternate_setting,
            )
            .map_err(|e| Error::SetAlternateSetting(self.descriptor.interface_number, e))
    }

    /// Send a USB release for our interface.
    fn release(&mut self) -> Result<()> {
        self.handle
            .release_interface(self.descriptor.interface_number)
            .map_err(|e| Error::ReleaseInterface(self.descriptor.interface_number, e))
    }
}

/// InterfaceManagerState contains the internal state of InterfaceManager.  It is intended to
/// be shared across InterfaceManager instances and protected by a mutex.
struct InterfaceManagerState {
    interfaces: VecDeque<ClaimedInterface>,
    handle: rusb::DeviceHandle<GlobalContext>,
    usb_config: u8,
    active: usize,
    pending_cleanup: bool,
    next_cleanup: Instant,
}

impl InterfaceManagerState {
    fn claim_all(&mut self) -> Result<()> {
        // Detach any outstanding kernel drivers for the current config before attempting
        // to switch to our desired config.
        let config = self
            .handle
            .device()
            .active_config_descriptor()
            .map_err(Error::ReadConfigDescriptor)?;

        if config.number() != self.usb_config {
            set_device_config(&mut self.handle, self.usb_config)?;
        }

        for interface in &mut self.interfaces {
            if let Err(e) = interface.claim() {
                // We don't bother to free any successfully claimed interfaces because
                // it's not an error to try to claim them again when the next connection
                // arrives.
                error!(
                    "Failed to reclaim interface {}: {}",
                    interface.descriptor.interface_number, e
                );
                return Err(e);
            }
        }
        Ok(())
    }

    fn release_all(&mut self) -> Result<()> {
        for interface in &mut self.interfaces {
            interface.release()?;
        }
        Ok(())
    }
}

/// InterfaceManager is responsible for managing a pool of claimed USB interfaces.
/// At construction, it is provided with a set of interfaces, and then clients
/// can use its member functions in order to request and free interfaces.
///
/// If no interfaces are currently available, requesting an interface will block
/// until an interface is freed by another thread.
///
/// InterfaceManager maintains the invariant that interfaces are claimed when
/// handed out.  It expects newly-inserted interfaces to be claimed by libusb and
/// it ensures that they are still claimed when retrieved.  Internally it releases
/// and claims free interfaces to allow sharing with other programs that might need
/// to access the USB interfaces.
#[derive(Clone)]
pub struct InterfaceManager {
    interface_available: Arc<Condvar>,
    state: Arc<Mutex<InterfaceManagerState>>,
}

impl InterfaceManager {
    fn new(
        handle: rusb::DeviceHandle<GlobalContext>,
        usb_config: u8,
        interfaces: Vec<ClaimedInterface>,
    ) -> Self {
        let mut deque: VecDeque<ClaimedInterface> = interfaces.into();
        for interface in &mut deque {
            interface.release().unwrap_or_else(|e| {
                error!(
                    "Failed to release interface {}: {}",
                    interface.descriptor.interface_number, e
                );
            });
        }
        Self {
            interface_available: Arc::new(Condvar::new()),
            state: Arc::new(Mutex::new(InterfaceManagerState {
                interfaces: deque,
                handle,
                usb_config,
                active: 0,
                pending_cleanup: false,
                next_cleanup: Instant::now(),
            })),
        }
    }

    /// Start a separate thread to release interfaces.  Interfaces are released once
    /// USB_CLEANUP_TIMEOUT elapses with no activity after all interfaces are internally
    /// returned.
    fn start_cleanup_thread(&mut self) -> Result<std::thread::JoinHandle<()>> {
        let manager = self.clone();

        let handle = thread::Builder::new()
            .name("interface cleanup".into())
            .spawn(move || {
                debug!("Cleanup thread starting");
                let mut state = manager.state.lock();

                // We wait in two phases:
                // 1. As long as no cleanup is pending or there is an active interface, we need to
                //    wait indefinitely.  Each interface sets pending_cleanup when it is returned,
                //    so this will eventually drop to 0 active interfaces with a cleanup pending.
                // 2. Once cleanup is needed and there are no active interfaces, we wait for a
                //    timeout.  If another connection comes during the timeout, we go back to the
                //    previous phase.
                'outer: loop {
                    // Phase 1: Wait for cleanup to be needed and all active interfaces to be
                    // returned.
                    state = manager
                        .interface_available
                        .wait_while(state, |t| t.active > 0 || !t.pending_cleanup);

                    // Phase 2: Wait for the cleanup time to arrive.
                    // 1. If an interface is claimed and returned during the timeout, we will
                    //    detect this because the timeout will be extended.  We can simply wait
                    //    more if this happens.
                    // 2. If an interface is claimed and is still active after our timeout, there's
                    //    no need to keep waking up.  Go back to phase 1 and wait for the active
                    //    interfaces to be returned.
                    // 3. Once everything remains the same for the whole timeout period, we can
                    //    exit the while loop and release all the interfaces.
                    while state.next_cleanup > Instant::now() {
                        let wait = state.next_cleanup - Instant::now();
                        let result =
                            manager
                                .interface_available
                                .wait_timeout_while(state, wait, |t| t.active == 0);
                        state = result.0; // Throw away the timed out part of the result.
                        if state.active > 0 {
                            continue 'outer;
                        }
                    }

                    // Now we know that there must be no active clients and the cleanup time must
                    // have arrived:
                    // 1.  If there were an active client, the check inside the while loop above
                    //     would have gone back to the outer loop.
                    // 2.  If the cleanup time hadn't arrived, the inner while loop wouldn't have
                    //     exited.
                    // This means we can safely release all the interfaces without affecting any
                    // active connections.
                    assert_eq!(state.active, 0, "Active interfaces not expected");
                    assert!(
                        Instant::now() >= state.next_cleanup,
                        "Cleanup time not arrived"
                    );
                    debug!("Releasing all USB interfaces");
                    match state.release_all() {
                        Ok(()) => {}

                        // If the device was unplugged, don't bother to print an error.  We're
                        // about to exit anyway.
                        Err(Error::ReleaseInterface(_, rusb::Error::NoDevice)) => {}

                        // If this failed for some other reason, we're in some bad state.  There
                        // are no active interfaces, so restarting won't interrupt an active
                        // connection.  We should just quit and let upstart reset us back to a
                        // known good state.
                        Err(e) => panic!("Failed to release interfaces: {}", e),
                    };
                    state.pending_cleanup = false;
                }
            })
            .map_err(Error::CleanupThread)?;

        Ok(handle)
    }

    /// Get an interface from the pool of tracked interfaces.
    /// Will block until an interface is available.
    /// If interfaces are currently not claimed, will first set the active device
    /// configuration and re-claim USB interfaces.
    fn request_interface(&mut self) -> Result<ClaimedInterface> {
        let mut state = self.state.lock();

        if state.active == 0 && !state.pending_cleanup {
            debug!("Claiming all interfaces");
            state.claim_all()?;
            state.pending_cleanup = true;
        }
        state.active += 1;

        loop {
            if let Some(interface) = state.interfaces.pop_front() {
                debug!(
                    "* Using interface {}",
                    interface.descriptor.interface_number
                );
                return Ok(interface);
            }

            state = self.interface_available.wait(state);
        }
    }

    /// Return an interface to the pool of interfaces.
    fn free_interface(&mut self, interface: ClaimedInterface) {
        debug!(
            "* Returning interface {}",
            interface.descriptor.interface_number
        );
        let mut state = self.state.lock();
        state.interfaces.push_back(interface);
        state.next_cleanup = Instant::now() + USB_CLEANUP_TIMEOUT;
        state.pending_cleanup = true;
        state.active -= 1;

        // Use notify_all instead of notify_one because the cleanup thread may also be
        // waiting on this condition variable.
        self.interface_available.notify_all();
    }
}

pub struct UnplugDetector {
    event_thread_run: Arc<AtomicBool>,
    // These are always Some until the destructor runs.
    registration: Option<Registration<GlobalContext>>,
    event_thread: Option<std::thread::JoinHandle<()>>,
    join_event_thread: bool,
}

impl UnplugDetector {
    pub fn new(
        device: rusb::Device<GlobalContext>,
        shutdown_fd: EventFd,
        shutdown: &'static AtomicBool,
        delay_shutdown: bool,
    ) -> Result<Self> {
        let handler = CallbackHandler::new(device, shutdown_fd, shutdown, delay_shutdown);
        let context = GlobalContext::default();
        let registration = context
            .register_callback(None, None, None, Box::new(handler))
            .map_err(Error::RegisterCallback)?;

        // Spawn thread to handle triggering the plug/unplug events.
        // While this is technically busy looping, the thread wakes up
        // only once every 60 seconds unless an event is detected.
        // When the callback is unregistered in Drop, an unplug event will
        // be triggered so we will wake up immediately.
        let run = Arc::new(AtomicBool::new(true));
        let thread_run = run.clone();
        let event_thread = std::thread::spawn(move || {
            while thread_run.load(Ordering::Relaxed) {
                let result = context.handle_events(None);
                if let Err(e) = result {
                    error!("Failed to handle libusb events: {}", e);
                }
            }
            info!("Shutting down libusb event thread.");
        });

        Ok(Self {
            event_thread_run: run,
            registration: Some(registration),
            event_thread: Some(event_thread),
            join_event_thread: !delay_shutdown, // Only wait if we're not managed by upstart.
        })
    }
}

impl Drop for UnplugDetector {
    fn drop(&mut self) {
        self.event_thread_run.store(false, Ordering::Relaxed);

        // The callback is unregistered when the registration is dropped.
        // Unwrap is safe because self.registration is always Some until we drop it here.
        drop(self.registration.take().unwrap());

        // Dropping the callback above wakes the event thread, so this should complete quickly.
        // Unwrap is safe because event_thread only becomes None at drop.
        let t = self.event_thread.take().unwrap();
        if self.join_event_thread {
            t.join()
                .unwrap_or_else(|e| error!("Failed to join event thread: {:?}", e));
        }
    }
}

struct CallbackHandler {
    device: rusb::Device<GlobalContext>,
    shutdown_fd: EventFd,
    shutdown_requested: &'static AtomicBool,
    delay_shutdown: bool,
}

impl CallbackHandler {
    fn new(
        device: rusb::Device<GlobalContext>,
        shutdown_fd: EventFd,
        shutdown_requested: &'static AtomicBool,
        delay_shutdown: bool,
    ) -> Self {
        Self {
            device,
            shutdown_fd,
            shutdown_requested,
            delay_shutdown,
        }
    }

    // If delayed shutdown is requested, wait for another shutdown event for up to 2s.
    // This gives upstart time to send the process a signal after a USB devices is unplugged.
    fn wait_for_shutdown(&mut self) -> Result<()> {
        if !self.delay_shutdown {
            return Ok(());
        }

        if self.shutdown_requested.load(Ordering::Relaxed) {
            // No need to wait if shutdown has already been requested from another source.
            return Ok(());
        }

        info!("Waiting for shutdown signal");
        let timeout = Duration::from_secs(2);
        let ctx: PollContext<u32> = PollContext::new().map_err(Error::Poll)?;
        ctx.add(&self.shutdown_fd, 1).map_err(Error::Poll)?;
        ctx.wait_timeout(timeout).map_err(Error::Poll)?;
        Ok(())
    }
}

impl rusb::Hotplug<GlobalContext> for CallbackHandler {
    fn device_arrived(&mut self, _device: rusb::Device<GlobalContext>) {
        // Do nothing.
    }

    fn device_left(&mut self, device: rusb::Device<GlobalContext>) {
        if device == self.device {
            info!("Device was unplugged, shutting down");

            if let Err(e) = self.wait_for_shutdown() {
                error!("Failed to wait for signal: {}", e);
            }

            self.shutdown_requested.store(true, Ordering::Relaxed);
            if let Err(e) = self.shutdown_fd.write(1) {
                error!("Failed to trigger shutdown: {}", e);
            }
        }
    }
}

/// A UsbConnector represents an active connection to an IPPUSB device.
/// Users can temporarily request a UsbConnection from the UsbConnector using
/// get_connection(), and use that UsbConnection to perform I/O to the device.
#[derive(Clone)]
pub struct UsbConnector {
    verbose_log: bool,
    handle: Arc<rusb::DeviceHandle<GlobalContext>>,
    manager: InterfaceManager,
}

impl UsbConnector {
    pub fn new(verbose_log: bool, bus_device: Option<(u8, u8)>) -> Result<UsbConnector> {
        let device_list = rusb::DeviceList::new().map_err(Error::DeviceList)?;

        let (device, info) = match bus_device {
            Some((bus, address)) => {
                let device = device_list
                    .iter()
                    .find(|d| d.bus_number() == bus && d.address() == address)
                    .ok_or(Error::NoDevice)?;

                let info = read_ippusb_device_info(&device)?.ok_or(Error::NotIppUsb)?;
                (device, info)
            }
            None => {
                let mut selected_device: Option<(rusb::Device<GlobalContext>, IppusbDevice)> = None;
                for device in device_list.iter() {
                    if let Some(info) = read_ippusb_device_info(&device)? {
                        selected_device = Some((device, info));
                        break;
                    }
                }
                selected_device.ok_or(Error::NoDevice)?
            }
        };

        info!(
            "Selected device {}:{}",
            device.bus_number(),
            device.address()
        );
        let mut handle = device.open().map_err(Error::OpenDevice)?;
        handle
            .set_auto_detach_kernel_driver(true)
            .map_err(|e| Error::DetachDrivers(u8::MAX, e))?; // Use MAX to mean "no interface".

        set_device_config(&mut handle, info.config)?;

        // Open the IPPUSB interfaces.
        let mut connections = Vec::new();
        for descriptor in info.interfaces {
            let mut interface_handle = device.open().map_err(Error::OpenDevice)?;
            interface_handle
                .claim_interface(descriptor.interface_number)
                .map_err(|e| Error::ClaimInterface(descriptor.interface_number, e))?;
            interface_handle
                .set_alternate_setting(descriptor.interface_number, descriptor.alternate_setting)
                .map_err(|e| Error::SetAlternateSetting(descriptor.interface_number, e))?;
            connections.push(ClaimedInterface {
                handle: interface_handle,
                descriptor,
            });
        }

        let mgr_handle = device.open().map_err(Error::OpenDevice)?;
        let mut manager = InterfaceManager::new(mgr_handle, info.config, connections);
        manager.start_cleanup_thread()?;

        Ok(UsbConnector {
            verbose_log,
            handle: Arc::new(handle),
            manager,
        })
    }

    pub fn device(&self) -> rusb::Device<GlobalContext> {
        self.handle.device()
    }

    pub fn get_connection(&mut self) -> Result<UsbConnection> {
        let interface = self.manager.request_interface()?;
        Ok(UsbConnection::new(
            self.verbose_log,
            self.manager.clone(),
            interface,
        ))
    }
}

/// A struct representing a claimed IPPUSB interface. The owner of this struct
/// can communicate with the IPPUSB device via the Read and Write.
pub struct UsbConnection {
    verbose_log: bool,
    manager: InterfaceManager,
    // `interface` is never None until the UsbConnection is dropped, at which point the
    // ClaimedInterface is returned to the pool of connections in InterfaceManager.
    interface: Option<ClaimedInterface>,
}

impl UsbConnection {
    fn new(verbose_log: bool, manager: InterfaceManager, interface: ClaimedInterface) -> Self {
        Self {
            verbose_log,
            manager,
            interface: Some(interface),
        }
    }
}

impl Drop for UsbConnection {
    fn drop(&mut self) {
        // Unwrap because interface only becomes None at drop.
        let interface = self.interface.take().unwrap();
        self.manager.free_interface(interface);
    }
}

fn to_io_error(err: rusb::Error) -> io::Error {
    let kind = match err {
        rusb::Error::InvalidParam => io::ErrorKind::InvalidInput,
        rusb::Error::NotFound => io::ErrorKind::NotFound,
        rusb::Error::Timeout => io::ErrorKind::TimedOut,
        rusb::Error::Pipe => io::ErrorKind::BrokenPipe,
        rusb::Error::Interrupted => io::ErrorKind::Interrupted,
        _ => io::ErrorKind::Other,
    };
    io::Error::new(kind, err)
}

impl Write for &UsbConnection {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Unwrap because interface only becomes None at drop.
        let interface = self.interface.as_ref().unwrap();
        let endpoint = interface.descriptor.out_endpoint;
        let written = interface
            .handle
            .write_bulk(endpoint, buf, USB_TRANSFER_TIMEOUT)
            .map_err(to_io_error)?;

        if self.verbose_log {
            let mut output = String::new();
            for byte in buf[..written].iter() {
                let c = *byte as char;
                if c == '\n' {
                    output.push(c);
                } else {
                    for v in c.escape_default() {
                        output.push(v);
                    }
                }
            }
            debug!("USB write:\n{}", output);
        }

        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Read for &UsbConnection {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Unwrap because interface only becomes None at drop.
        let interface = self.interface.as_ref().unwrap();
        let endpoint = interface.descriptor.in_endpoint;
        let start = Instant::now();
        let mut result = interface
            .handle
            .read_bulk(endpoint, buf, USB_TRANSFER_TIMEOUT)
            .map_err(to_io_error);
        let mut zero_reads = 0;

        // USB reads cannot hit EOF. We will retry after a short delay so that higher-level
        // readers can pretend this doesn't exist.
        while let Ok(0) = result {
            zero_reads += 1;
            if start.elapsed() > USB_TRANSFER_TIMEOUT {
                result = Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Timed out waiting for non-zero USB read",
                ));
                break;
            }
            thread::sleep(Duration::from_millis(10));
            result = interface
                .handle
                .read_bulk(endpoint, buf, USB_TRANSFER_TIMEOUT)
                .map_err(to_io_error);
        }

        if zero_reads > 0 {
            debug!(
                "Spent {}ms waiting for {} 0-byte USB reads",
                start.elapsed().as_millis(),
                zero_reads
            );
        }
        result
    }
}

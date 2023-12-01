// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/// Handles the D-Bus interface for resume.
use std::sync::mpsc::channel;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use dbus::blocking::Connection;
use dbus::channel::MatchingReceiver; // For start_receive
use dbus::message::MatchRule;
use dbus_crossroads::Crossroads;
use log::{debug, error};

const HIBERMAN_DBUS_NAME: &str = "org.chromium.Hibernate";
const HIBERMAN_DBUS_PATH: &str = "/org/chromium/Hibernate";
const HIBERMAN_RESUME_DBUS_INTERFACE: &str = "org.chromium.HibernateResumeInterface";

pub enum DBusEvent {
    UserAuthWithAccountId { account_id: String },
    UserAuthWithSessionId { session_id: Vec<u8> },
    AbortRequest { reason: String },
}

/// The hiberman D-Bus server. The D-Bus interface provides functions for notifying
/// the server about user authentications and for requesting the abort of a pending
/// resume from hibernate.
pub struct DBusServer {
    _completion_sender: crossbeam_channel::Sender<()>,
    completion_receiver: Option<crossbeam_channel::Receiver<()>>,
}

impl DBusServer {
    /// Create a DBusServer instance.
    pub fn new() -> Self {
        let (sender, receiver) = crossbeam_channel::bounded::<()>(0);

        Self {
            _completion_sender: sender,
            completion_receiver: Some(receiver),
        }
    }

    // Waits for a D-Bus event and returns it
    //
    // There are 2 channels for communication between the main thread and the D-Bus server thread. The
    // main thread notifies resume completion to the D-Bus thread via the completion channel
    // (completion_{sender|receiver}). The D-Bus thread sends the auth events to the main thread via
    // the channels (user_auth_{sender|receiver}) and (user_auth_session{sender|receiver}).
    //
    // The event channel's type is std::sync::mpsc::channel (multi producer single consumer
    // channel) because the sender needs to be cloned for multiple D-Bus methods. The completion
    // channel's type is crossbeam_channel::Receiver (multi producer multi consumer channel) because
    // the receiver needs to be cloned for multiple D-Bus methods.
    //
    // Reference: dbus_crossroads example:
    //   https://github.com/diwic/dbus-rs/tree/master/dbus-crossroads/examples
    pub fn wait_for_event(&mut self) -> Result<DBusEvent> {
        let completion_receiver = self.completion_receiver.take().unwrap();

        // Clone the completion_receiver for multiple closures. Each closure needs to own its receiver.
        let completion_as_receiver = completion_receiver.clone();
        let completion_abort_receiver = completion_receiver.clone();

        let (sender, receiver) = channel();
        let abort_sender = sender.clone();
        let user_auth_session_sender = sender.clone();
        let user_auth_sender = sender;

        let conn = Connection::new_system().context("Failed to start local dbus connection")?;
        conn.request_name(HIBERMAN_DBUS_NAME, false, false, false)
            .context("Failed to request dbus name")?;

        let mut crossroads = Crossroads::new();
        // Build a new HibernateResumeInterface.
        let iface_token = crossroads.register(HIBERMAN_RESUME_DBUS_INTERFACE, |b| {
            b.method(
                "ResumeFromHibernate",
                ("account_id",),
                (),
                move |_, _, (account_id,): (String,)| {
                    // Send the auth event to the main thread.
                    if let Err(e) =
                        user_auth_sender.send(DBusEvent::UserAuthWithAccountId { account_id })
                    {
                        error!(
                            "Failed to send resume account id request to the main thread: {:?}",
                            e
                        );
                    }
                    // recv() returns an error when the sender is dropped.
                    _ = completion_receiver.recv();
                    debug!("ResumeFromHibernate completing");
                    Ok(())
                },
            );

            b.method(
                "ResumeFromHibernateAS",
                ("auth_session_id",),
                (),
                move |_, _, (session_id,): (Vec<u8>,)| {
                    // Send the auth event to the main thread.
                    if let Err(e) =
                        user_auth_session_sender.send(DBusEvent::UserAuthWithSessionId { session_id })
                    {
                        error!(
                            "Failed to send resume auth session id request to the main thread: {:?}",
                            e
                        );
                    }
                    // recv() returns an error when the sender is dropped.
                    _ = completion_as_receiver.recv();
                    debug!("ResumeFromHibernateAS completing");
                    Ok(())
                },
            );

            b.method(
                "AbortResume",
                ("reason",),
                (),
                move |_, _, (reason,): (String,)| {
                    // Send the abort request to the main thread.
                    if let Err(e) = abort_sender.send(DBusEvent::AbortRequest { reason }) {
                        error!(
                            "Failed to send resume abort request to the main thread: {:?}",
                            e
                        );
                    }
                    // recv() returns an error when the sender is dropped.
                    _ = completion_abort_receiver.recv();
                    debug!("AbortResume completing");
                    Ok(())
                },
            );
        });

        // Use an empty context object as we don't have shared state.
        struct ResumeDbusContext {}
        crossroads.insert(HIBERMAN_DBUS_PATH, &[iface_token], ResumeDbusContext {});

        // The D-Bus methods are handled by the crossroads instance.
        conn.start_receive(
            MatchRule::new_method_call(),
            Box::new(move |msg, conn| {
                if let Err(e) = crossroads.handle_message(msg, conn) {
                    error!("Failed to handle message: {:?}", e);
                    false
                } else {
                    true
                }
            }),
        );

        // Spawn a thread to process D-Bus messages.
        thread::spawn(move || loop {
            // When conn.process() times out, it returns Ok(false) and re-enters the loop. Longer
            // timeout makes this D-Bus server thread waking up less when it's waiting for the D-Bus
            // message (e.g. the user might not sign in for thirty minutes).
            if let Err(e) = conn.process(Duration::from_secs(30)) {
                error!("Failed to process dbus message: {:?}", e);
            }
        });

        let event = receiver.recv()?;
        Ok(event)
    }
}

// Define the timeout to connect to the dbus system.
const DEFAULT_DBUS_TIMEOUT: Duration = Duration::from_secs(10);

/// Send an abort request over dbus to cancel a pending resume. The hiberman process calling this
/// function might not be the same as the hiberman process serving the dbus requests. For example,
/// a developer may invoke the abort resume subcommand.
pub fn send_abort(reason: &str) -> Result<()> {
    let conn = Connection::new_system().context("Failed to connect to dbus for send abort")?;
    let proxy = conn.with_proxy(HIBERMAN_DBUS_NAME, HIBERMAN_DBUS_PATH, DEFAULT_DBUS_TIMEOUT);

    proxy
        .method_call(HIBERMAN_RESUME_DBUS_INTERFACE, "AbortResume", (reason,))
        .context("Failed to send abort request")?;
    debug!("Sent AbortResume request");
    Ok(())
}

// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::vm_grpc::proto::concierge_service::{
    GetVmInfoRequest, GetVmInfoResponse, VmStartedSignal, VmStoppedSignal,
};
use crate::vm_grpc::vm_grpc_client::VmGrpcClient;
use crate::vm_grpc::vm_grpc_server::VmGrpcServer;

use anyhow::{bail, Result};
use dbus::channel::MatchingReceiver;
use dbus::message::MatchRule;
use dbus::nonblock::Proxy;
use dbus::nonblock::SyncConnection;
use dbus::Message;
use libchromeos::sys::{info, warn};
use once_cell::sync::Lazy;
use protobuf::CodedInputStream;
use protobuf::Message as protoMessage;
use std::path::Path;
use std::sync::atomic::AtomicI64;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

// VSOCK port to use for accepting GRPC socket connections.
const RESOURCED_GRPC_SERVER_PORT: u16 = 5551;

// VSOCK port where resourced can connect a client.
const GUEST_VM_GRPC_SERVER_PORT: u16 = 5553;

// Timeout in ms for making a dbus method calls to other services.
const DBUS_PROXY_TIMEOUT_MS: u64 = 1000;

// VSOCK CID for accepting any serverside connection.
const CID_ANY: i16 = -1;

// Name for the borealis VM.
const BOREALIS_VM_NAME: &str = "borealis";

static VM_GRPC_SERVER_STOP_REQ: Lazy<Mutex<bool>> = Lazy::new(|| Mutex::new(false));

pub fn vm_server_stop_requested() -> bool {
    match VM_GRPC_SERVER_STOP_REQ.lock() {
        Ok(data) => *data,
        Err(_) => {
            warn!("Could not acquire lock for  VM_GRPC_SERVER_STOP_REQ");
            false
        }
    }
}

fn request_vm_server_stop() -> Result<()> {
    match VM_GRPC_SERVER_STOP_REQ.lock() {
        Ok(mut data) => {
            *data = true;
        }
        Err(_) => bail!("GRPC server stop request failed"),
    };
    Ok(())
}

pub fn vm_server_stop_req_reset() {
    match VM_GRPC_SERVER_STOP_REQ.lock() {
        Ok(mut data) => *data = false,
        Err(_) => {
            warn!("Could not reset grpc_server_stop_request.");
            warn!("Grpc server may not restart in future requests.");
        }
    }
}

fn vm_grpc_init(borealis_cid: i16) -> Result<VmGrpcServer> {
    // if server is already with a different cid, restart it with new cid.
    // client is expected to timeout and drop
    let root = Path::new("/");
    let pkt_tx_interval = Arc::new(AtomicI64::new(-1));
    let pkt_tx_interval_clone = pkt_tx_interval.clone();

    let server = VmGrpcServer::run(CID_ANY, RESOURCED_GRPC_SERVER_PORT, root, pkt_tx_interval)?;
    VmGrpcClient::run(
        borealis_cid,
        GUEST_VM_GRPC_SERVER_PORT,
        root,
        pkt_tx_interval_clone,
    )?;

    Ok(server)
}

/// Extracts the CID for the borealis VM from the a VmStarterSignal D-bus message.
///
/// Function consumes a VmStarterSignal and extracts the vm_cid if the vm_name is borealis.
/// conn`: pre-initialized non-blocking dbus connection object.
///
/// # Return: Result object with userhash embedded.
fn get_borealis_cid_from_vm_started_signal(msg: &Message) -> Result<i16> {
    let raw_buffer: Vec<u8> = msg.read1()?;
    let input = &mut CodedInputStream::from_bytes(&raw_buffer);
    let mut borealis_vm = VmStartedSignal::new();
    borealis_vm.merge_from(input)?;
    let name_vm = borealis_vm.get_name();
    if name_vm != BOREALIS_VM_NAME {
        bail!("ignoring VmStartedSIgnal for {}.", name_vm)
    }
    let borealis_cid = borealis_vm.get_vm_info().get_cid() as i16;
    Ok(borealis_cid)
}

fn vm_stopped_signal_is_for_borealis(msg: &Message) -> Result<bool> {
    let byte_array: Vec<u8> = msg.read1()?;
    let mut vm_stopped_payload = VmStoppedSignal::new();
    vm_stopped_payload.merge_from_bytes(&byte_array)?;
    Ok(vm_stopped_payload.get_name() == BOREALIS_VM_NAME)
}

/// Function to retrieve cryptohome.
///
/// `conn`: pre-initialized non-blocking dbus connection object.
///
/// # Return: Result object with userhash embedded.
async fn retrieve_primary_session(conn: Arc<SyncConnection>) -> Result<String> {
    let session_proxy = Proxy::new(
        "org.chromium.SessionManager",
        "/org/chromium/SessionManager",
        Duration::from_millis(DBUS_PROXY_TIMEOUT_MS),
        conn,
    );

    let (_user_name, session_id): (String, String) = session_proxy
        .method_call(
            "org.chromium.SessionManagerInterface",
            "RetrievePrimarySession",
            (),
        )
        .await?;

    Ok(session_id)
}

/// Function to retrieve borealis CID.
///
/// This function makes a dbus call to session_manager to retrieve the cryptohome value.
/// The cryptohome value is used to call concierge for borealis vm_info, which contains
/// the borealis cid.
/// Each dbus call has a 1 second timeout, total blocking time for this function is 2 seconds.
///
/// `conn`: pre-initialized non-blocking dbus connection object.
///
/// # Return: Result object with borealis CID embedded.
async fn get_borealis_cid_from_concierge_async(conn: Arc<SyncConnection>) -> Result<i16> {
    let mut vm_info_request = GetVmInfoRequest::default();
    vm_info_request.set_name(BOREALIS_VM_NAME.to_string());
    vm_info_request.set_owner_id(retrieve_primary_session(conn.clone()).await?);

    let concierge_proxy = Proxy::new(
        "org.chromium.VmConcierge",
        "/org/chromium/VmConcierge",
        Duration::from_millis(DBUS_PROXY_TIMEOUT_MS),
        conn,
    );

    let concierge_resp: (Vec<u8>,) = concierge_proxy
        .method_call(
            "org.chromium.VmConcierge",
            "GetVmInfo",
            (vm_info_request.write_to_bytes()?,),
        )
        .await?;

    let dbus_resp_bytes = &mut CodedInputStream::from_bytes(&(concierge_resp.0));

    let mut get_vm_info_resp = GetVmInfoResponse::new();
    get_vm_info_resp.merge_from(dbus_resp_bytes)?;

    let cid = get_vm_info_resp.get_vm_info().get_cid() as i16;

    // CID values [-1,0,1,2] are reserved.  Sanity check the received CID.
    if cid > 2 {
        Ok(cid)
    } else {
        bail!("Could not get a valid CID");
    }
}

/// Registers for dbus signals.
///
/// This function registers callbacks for `VmStoppedSignal` and `VmStartedSignal` from concierge.
/// At VM start, it will retrieve the VM CID and start a new grpc server/client pair.
/// On VM stop, it will teardown the server.  Client will independently teardown after 1s of
/// inactivity.
///
/// `conn`: pre-initialized non-blocking dbus connection object.
///
/// # Return: Emtpty Result object.
pub async fn register_dbus_hooks_async(conn: Arc<SyncConnection>) -> Result<()> {
    let vm_stopped_rule = MatchRule::new_signal("org.chromium.VmConcierge", "VmStoppedSignal");
    let vm_started_rule = MatchRule::new_signal("org.chromium.VmConcierge", "VmStartedSignal");

    if conn
        .add_match_no_cb(&vm_started_rule.match_str())
        .await
        .is_err()
    {
        warn!("Unable to set filtering of VmStarted dbus message.")
    }

    conn.start_receive(
        vm_started_rule,
        Box::new(|msg, _| {
            if let Ok(cid) =
                crate::vm_grpc::vm_grpc_util::get_borealis_cid_from_vm_started_signal(&msg)
            {
                if let Err(e) = vm_grpc_init(cid) {
                    warn!("Failed to initialize GRPC client/server pair. {}", e);
                }
            }

            true
        }),
    );

    if conn
        .add_match_no_cb(&vm_stopped_rule.match_str())
        .await
        .is_err()
    {
        warn!("Unable to set filtering of VmStarted dbus message.")
    }

    conn.start_receive(
        vm_stopped_rule,
        Box::new(|msg, _| {
            if vm_stopped_signal_is_for_borealis(&msg).unwrap_or(false) {
                info!("Got vm_stopped signal.");
                if let Err(e) = request_vm_server_stop() {
                    warn!("Could not request grpc server stop. {:?}", e);
                }
            }

            true
        }),
    );

    Ok(())
}

/// Checks for borealis instance on-demand.
///
/// This functions checks to see if there is an existing borealis instance running.  If there is,
/// it will start a new server/client pair and send a an init packet.  2 dbus calls have a max
/// timeout of 2 seconds.
///
/// `conn`: pre-initialized non-blocking dbus connection object.
///
/// # Return: Emtpty Result object.
pub async fn handle_startup_borealis_state_async(conn: Arc<SyncConnection>) -> Result<()> {
    if let Ok(borealis_cid) = get_borealis_cid_from_concierge_async(conn).await {
        info!("Borealis VM is already running.  CID: {}", borealis_cid);
        vm_grpc_init(borealis_cid)?;
    } else {
        info!("No borealis instance detected at resourced startup");
    }

    Ok(())
}

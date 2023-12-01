// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Provides the command "wireguard" for crosh which can configure and control a WireGuard service
// in Shill.

use std::{collections::HashMap, io};

use dbus::{
    self,
    arg::{ArgType, RefArg, Variant},
    blocking::Connection,
};
use libchromeos::sys::error;
use system_api::client::OrgChromiumFlimflamManager;
use system_api::client::OrgChromiumFlimflamService;

use crate::{
    dispatcher::{self, Arguments, Command, Dispatcher},
    util::{is_consumer_device, DEFAULT_DBUS_TIMEOUT},
};

const USAGE: &str = r#"wireguard <cmd> [<args>]

Available subcommands:

list
    Show all configured WireGuard services.
show <name>
    Show the WireGuard service with name <name>.
new <name>
    Create a new WireGuard service with name <name>.
del <name>
    Delete the configured WireGuard service with name <name>.
set <name> [local-ip <ip1>[,<ip2>]] [private-key] [mtu <mtu>] [dns <ip1>[,<ip2>]...]
           [peer <base64-public-key> [remove]
                                     [endpoint <hostname>/<ip>:<port>]
                                     [preshared-key]
                                     [allowed-ips <ip1>/<cidr1>[,<ip2>/<cidr2>]...]
                                     [persistent-keepalive <interval seconds>] ]...
    Configure properties for the WireGuard service with name <name>. Most options should
    have the same meaning and usage as in `wireguard-tools` (and `wg-quick`). Exceptions
    are:
    - At most one IPv4 address and one IPv6 address is supported for `local-ip`.
    - If `dns` is not set, it will be defaulted to "8.8.8.8,8.8.4.4".
    - If `mtu` is not set, it will be determined automatically. Set it to 0 to reset the
      existing value.
    - `endpoint` must be set before using `connect` command.
    - `private-key` and `preshared-key` take no parameters. If they are used, this command
      will prompt you to change the key (or remove the key) via stdin, to avoid leaving
      them in the history of shell.
connect <name>
    Connect to the configured WireGuard service with name <name>.
disconnect <name>
    Disconnect from the configured WireGuard service with name <name>.
"#;

pub fn register(dispatcher: &mut Dispatcher) {
    if let Ok(true) = is_consumer_device() {
        dispatcher.register_command(
            Command::new(
                "wireguard".to_string(),
                USAGE.to_string(),
                "Utility to configure and control a WireGuard VPN service".to_string(),
            )
            .set_command_callback(Some(execute_wireguard)),
        );
    }
}

#[derive(Debug)]
enum Error {
    InvalidArguments(String),
    ServiceNotFound(String),
    ServiceAlreadyExists(String),
    ServiceNotConnectable {
        service_name: String,
        reason: String,
    },
    VpnDisabled,
    WireGuardUnavailable,
    Internal(String),
}

fn execute_wireguard(_cmd: &Command, args: &Arguments) -> Result<(), dispatcher::Error> {
    let convert_err = |err: Error| match err {
        Error::InvalidArguments(val) => dispatcher::Error::CommandInvalidArguments(val),
        Error::ServiceNotFound(val) => {
            println!("WireGuard service with name {} does not exist", val);
            dispatcher::Error::CommandReturnedError
        }
        Error::ServiceAlreadyExists(val) => {
            println!("WireGuard service with name {} already exists", val);
            dispatcher::Error::CommandReturnedError
        }
        Error::ServiceNotConnectable {
            service_name,
            reason,
        } => {
            println!(
                "WireGuard service with name {} is not connectable: {}",
                service_name, reason
            );
            dispatcher::Error::CommandReturnedError
        }
        Error::VpnDisabled => {
            println!("VPN is disabled on this device");
            dispatcher::Error::CommandReturnedError
        }
        Error::WireGuardUnavailable => {
            println!("WireGuard is not available on this device");
            dispatcher::Error::CommandReturnedError
        }
        Error::Internal(val) => {
            error!("ERROR: {}", val);
            dispatcher::Error::CommandReturnedError
        }
    };

    check_wireguard_support().map_err(convert_err)?;

    let args: Vec<&str> = args.get_args().iter().map(String::as_str).collect();
    match args.as_slice() {
        [] => Err(Error::InvalidArguments("no command".to_string())),
        ["show"] | ["list"] => wireguard_list(),
        ["show", service_name] => wireguard_show(service_name),
        ["new", service_name] => wireguard_new(service_name),
        ["del", service_name] => wireguard_del(service_name),
        ["set", service_name, remaining @ ..] => wireguard_set(service_name, remaining),
        ["connect", service_name] => wireguard_connect(service_name),
        ["disconnect", service_name] => wireguard_disconnect(service_name),
        [other, ..] => Err(Error::InvalidArguments(other.to_string())),
    }
    .map_err(convert_err)
}

// Represents the properties returned by GetProperties method from D-Bus.
type InputPropMap = HashMap<String, Variant<Box<dyn RefArg>>>;
// Represents the properties nested as a value of another property in the InputPropMap.
type InnerPropMap<'a> = HashMap<&'a str, &'a dyn RefArg>;
// Represents the properties used to configure a service via D-Bus.
type OutputPropMap = HashMap<String, Variant<Box<dyn RefArg>>>;

// Helper functions for reading a value with a specific type from a property map.
trait GetPropExt {
    fn get_arg(&self, key: &str) -> Result<&dyn RefArg, Error>;

    fn get_str(&self, key: &str) -> Result<&str, Error> {
        self.get_arg(key)?
            .as_str()
            .ok_or_else(|| get_prop_error(key, "str"))
    }

    fn get_string(&self, key: &str) -> Result<String, Error> {
        Ok(self.get_str(key)?.to_string())
    }

    fn get_i32(&self, key: &str) -> Result<i32, Error> {
        self.get_arg(key)?
            .as_i64()
            .map(|x| x as i32)
            .ok_or_else(|| get_prop_error(key, "i32"))
    }

    fn get_strings(&self, key: &str) -> Result<Vec<String>, Error> {
        self.get_arg(key)?
            .as_iter()
            .ok_or_else(|| get_prop_error(key, "vec"))?
            .map(|arg| {
                arg.as_str()
                    .ok_or_else(|| get_prop_error(key, "str"))
                    .map(|x| x.to_string())
            })
            .collect()
    }

    fn get_inner_prop_map(&self, key: &str) -> Result<InnerPropMap, Error> {
        parse_arg_to_map(self.get_arg(key)?).ok_or_else(|| get_prop_error(key, "map"))
    }

    fn get_inner_prop_maps(&self, key: &str) -> Result<Vec<InnerPropMap>, Error> {
        self.get_arg(key)?
            .as_iter()
            .ok_or_else(|| get_prop_error(key, "vec"))?
            .map(|arg| parse_arg_to_map(arg).ok_or_else(|| get_prop_error(key, "map")))
            .collect()
    }
}

fn get_prop_error(k: &str, t: &str) -> Error {
    Error::Internal(format!("Failed to parse properties {} with type {}", k, t))
}

fn parse_arg_to_map(arg: &dyn RefArg) -> Option<InnerPropMap> {
    let mut kvs = HashMap::new();
    let mut itr = arg.as_iter()?;
    while let Some(val) = itr.next() {
        let key = val.as_str()?;
        let next = itr.next()?;
        // Unwraps it if the value type is Variant, since it may affect iterating over the inner
        // value if the inner type is dict.
        if next.arg_type() == ArgType::Variant {
            let mut inner_itr = next.as_iter().unwrap();
            kvs.insert(key, inner_itr.next().unwrap());
        } else {
            kvs.insert(key, next);
        }
    }
    Some(kvs)
}

impl GetPropExt for InputPropMap {
    fn get_arg(&self, key: &str) -> Result<&dyn RefArg, Error> {
        Ok(&self
            .get(&key.to_string())
            .ok_or_else(|| get_prop_error(key, "ref_arg"))?
            .0)
    }
}

impl GetPropExt for InnerPropMap<'_> {
    fn get_arg(&self, key: &str) -> Result<&dyn RefArg, Error> {
        Ok(self
            .get(key)
            .ok_or_else(|| get_prop_error(key, "ref_arg"))?)
    }
}

// The following constants are defined in system_api/dbus/shill/dbus-constants.h.
// Also see shill/doc/manager-api.txt and shill/doc/service-api.txt for their meanings.

// Property names for manager.
const PROPERTY_PROHIBITED_TECHNOLOGIES: &str = "ProhibitedTechnologies";
const PROPERTY_SERVICES: &str = "Services";
const PROPERTY_SUPPORTED_VPN_TYPES: &str = "SupportedVPNTypes";

// Property names for service.
const PROPERTY_TYPE: &str = "Type";
const PROPERTY_NAME: &str = "Name";
const PROPERTY_PROVIDER_TYPE: &str = "Provider.Type";
const PROPERTY_PROVIDER_HOST: &str = "Provider.Host";
const PROPERTY_WIREGUARD_IP_ADDRESS: &str = "WireGuard.IPAddress";
const PROPERTY_WIREGUARD_PRIVATE_KEY: &str = "WireGuard.PrivateKey";
const PROPERTY_WIREGUARD_PUBLIC_KEY: &str = "WireGuard.PublicKey";
const PROPERTY_WIREGUARD_PEERS: &str = "WireGuard.Peers";
const PROPERTY_STATIC_IP_CONFIG: &str = "StaticIPConfig";
const PROPERTY_SAVE_CREDENTIALS: &str = "SaveCredentials";

// Property names for WireGuard in "WireGuard.Peers".
const PROPERTY_PEER_PUBLIC_KEY: &str = "PublicKey";
const PROPERTY_PEER_PRESHARED_KEY: &str = "PresharedKey";
const PROPERTY_PEER_ENDPOINT: &str = "Endpoint";
const PROPERTY_PEER_ALLOWED_IPS: &str = "AllowedIPs";
const PROPERTY_PEER_PERSISTENT_KEEPALIVE: &str = "PersistentKeepalive";

// Property names in "StaticIPConfig"
const PROPERTY_NAME_SERVERS: &str = "NameServers";
const PROPERTY_MTU: &str = "Mtu";

// Property values.
const TYPE_VPN: &str = "vpn";
const TYPE_WIREGUARD: &str = "wireguard";

// Represents a WireGuard service in Shill.
#[derive(Clone, Debug, PartialEq)]
struct WireGuardService {
    path: Option<String>,
    name: String,
    local_ips: Vec<String>,
    private_key: Option<String>,
    public_key: String,
    mtu: Option<i32>,
    name_servers: Option<Vec<String>>,
    peers: Vec<WireGuardPeer>,
}

#[derive(Clone, Debug, PartialEq)]
struct WireGuardPeer {
    public_key: String,
    endpoint: String,
    allowed_ips: String,
    persistent_keepalive: String,
    preshared_key: Option<String>,
}

impl WireGuardService {
    fn parse_from_prop_map(service_properties: &InputPropMap) -> Result<Self, Error> {
        let service_name = service_properties.get_str(PROPERTY_NAME)?;

        let not_wg_service_err =
            Error::ServiceNotFound(format!("{} is not a WireGuard VPN service", service_name));

        let service_type = service_properties.get_str(PROPERTY_TYPE)?;
        if service_type != TYPE_VPN {
            return Err(not_wg_service_err);
        }

        // The value of the "Provider" property is a map. Translates it into a HashMap at first.
        let provider_properties = service_properties.get_inner_prop_map("Provider")?;

        // Reads dns servers, and mtu from StaticIPConfig. This property and all the sub-properties
        // could be empty.
        let mut mtu = None;
        let mut name_servers = None;
        if let Ok(props) = service_properties.get_inner_prop_map(PROPERTY_STATIC_IP_CONFIG) {
            // Note that the ok() below may potentially ignore some real parsing failures. It
            // should not happen if shill is working correctly so we use ok() here for simplicity.
            name_servers = props.get_strings(PROPERTY_NAME_SERVERS).ok();
            mtu = props.get_i32(PROPERTY_MTU).ok();
        }

        if provider_properties.get_str(PROPERTY_TYPE)? != TYPE_WIREGUARD {
            return Err(not_wg_service_err);
        }

        let ret = WireGuardService {
            path: None,
            name: service_name.to_string(),
            local_ips: provider_properties.get_strings(PROPERTY_WIREGUARD_IP_ADDRESS)?,
            private_key: None,
            public_key: provider_properties.get_string(PROPERTY_WIREGUARD_PUBLIC_KEY)?,
            mtu,
            name_servers,
            peers: provider_properties
                .get_inner_prop_maps(PROPERTY_WIREGUARD_PEERS)?
                .into_iter()
                .map(|p| {
                    Ok(WireGuardPeer {
                        public_key: p.get_string(PROPERTY_PEER_PUBLIC_KEY)?,
                        endpoint: p.get_string(PROPERTY_PEER_ENDPOINT)?,
                        allowed_ips: p.get_string(PROPERTY_PEER_ALLOWED_IPS)?,
                        persistent_keepalive: p.get_string(PROPERTY_PEER_PERSISTENT_KEEPALIVE)?,
                        preshared_key: None,
                    })
                })
                .collect::<Result<Vec<WireGuardPeer>, Error>>()?,
        };

        Ok(ret)
    }

    fn encode_into_prop_map(&self) -> OutputPropMap {
        let mut properties: OutputPropMap = HashMap::new();
        let mut insert_props_field = |k: &'static str, v: Box<dyn RefArg>| {
            properties.insert(k.to_string(), Variant(v));
        };

        insert_props_field(PROPERTY_TYPE, Box::new(TYPE_VPN.to_string()));
        insert_props_field(PROPERTY_NAME, Box::new(self.name.to_string()));
        insert_props_field(PROPERTY_PROVIDER_TYPE, Box::new(TYPE_WIREGUARD.to_string()));
        insert_props_field(PROPERTY_PROVIDER_HOST, Box::new(TYPE_WIREGUARD.to_string()));
        insert_props_field(
            PROPERTY_WIREGUARD_IP_ADDRESS,
            Box::new(self.local_ips.clone()),
        );
        if let Some(val) = &self.private_key {
            insert_props_field(PROPERTY_WIREGUARD_PRIVATE_KEY, Box::new(val.to_string()));
        }

        let mut static_ip_properties = HashMap::new();
        let mut insert_ip_field = |k: &str, v: Box<dyn RefArg>| {
            static_ip_properties.insert(k.to_string(), Variant(v));
        };
        if let Some(name_servers) = &self.name_servers {
            insert_ip_field(PROPERTY_NAME_SERVERS, Box::new(name_servers.clone()));
        } else {
            insert_ip_field(
                PROPERTY_NAME_SERVERS,
                Box::new(vec!["8.8.8.8".to_string(), "8.8.4.4".to_string()]),
            );
        }
        if let Some(mtu) = self.mtu {
            insert_ip_field(PROPERTY_MTU, Box::new(mtu));
        }
        if !static_ip_properties.is_empty() {
            properties.insert(
                PROPERTY_STATIC_IP_CONFIG.to_string(),
                Variant(Box::new(static_ip_properties)),
            );
        }

        let mut peers_buf = Vec::new();
        for peer in &self.peers {
            let mut peer_properties = HashMap::new();
            let mut insert_peer_field = |k: &str, v: &str| {
                peer_properties.insert(k.to_string(), v.to_string());
            };
            insert_peer_field(PROPERTY_PEER_PUBLIC_KEY, &peer.public_key);
            insert_peer_field(PROPERTY_PEER_ENDPOINT, &peer.endpoint);
            insert_peer_field(PROPERTY_PEER_ALLOWED_IPS, &peer.allowed_ips);
            insert_peer_field(
                PROPERTY_PEER_PERSISTENT_KEEPALIVE,
                &peer.persistent_keepalive,
            );
            if let Some(val) = &peer.preshared_key {
                insert_peer_field(PROPERTY_PEER_PRESHARED_KEY, val);
            }
            peers_buf.push(peer_properties);
        }
        properties.insert(
            PROPERTY_WIREGUARD_PEERS.to_string(),
            Variant(Box::new(peers_buf)),
        );

        // Always persists keys.
        properties.insert(
            PROPERTY_SAVE_CREDENTIALS.to_string(),
            Variant(Box::new(true)),
        );

        properties
    }

    // Updates the service by |args| from `wireguard set` command. If `private-key` or
    // `preshared-key` is specified, keys will be read from |reader|, which is usually stdin.
    fn update_from_args<R: io::BufRead>(
        &mut self,
        args: &[&str],
        mut reader: R,
    ) -> Result<(), Error> {
        use option_util::*;

        // May point to a peer in |self.peers| which is being processed currently.
        let mut current_peer = None;
        // Indicates if |current_peer| is a peer added in this command.
        let mut is_new_peer = false;

        let mut iter = args.iter();
        while let Some(key) = iter.next() {
            let no_peer_err = Error::InvalidArguments(format!(
                "Option '{}' should appear after a peer is specified",
                key
            ));

            // Forwards the iterator to read the value for the currently processing option.
            let mut get_next_as_val = || {
                iter.next().ok_or_else(|| {
                    Error::InvalidArguments(format!(
                        "Option '{}' expects one parameter but none is given",
                        key
                    ))
                })
            };

            match *key {
                "local-ip" => self.local_ips = parse_local_ip(get_next_as_val()?)?,
                "dns" => self.name_servers = parse_dns(get_next_as_val()?)?,
                "mtu" => self.mtu = parse_mtu(get_next_as_val()?)?,
                "private-key" => {
                    let lines = [
                        "Change private key for this service (or press <Enter> directly",
                        "to let the system generate a random key).",
                        "New key: ",
                    ];
                    let prompt = lines.join("\n");
                    self.private_key = Some(read_key(&prompt, &mut reader)?);
                }
                "peer" => {
                    let pubkey = parse_peer(get_next_as_val()?)?;
                    current_peer = self.peers.iter_mut().find(|x| x.public_key == pubkey);
                    is_new_peer = current_peer.is_none();
                    if is_new_peer {
                        self.peers.push(WireGuardPeer {
                            public_key: pubkey,
                            endpoint: "".to_string(),
                            allowed_ips: "".to_string(),
                            persistent_keepalive: "".to_string(),
                            preshared_key: None,
                        });
                        current_peer = self.peers.last_mut();
                    }
                }
                "remove" => {
                    if is_new_peer {
                        return Err(Error::InvalidArguments(
                            "Peer to be removed does not exist".to_string(),
                        ));
                    }
                    let pubkey = current_peer.as_mut().ok_or(no_peer_err)?.public_key.clone();
                    current_peer = None;
                    self.peers.retain(|x| x.public_key != pubkey);
                }
                "endpoint" => {
                    current_peer.as_mut().ok_or(no_peer_err)?.endpoint =
                        parse_endpoint(get_next_as_val()?)?;
                }
                "allowed-ips" => {
                    current_peer.as_mut().ok_or(no_peer_err)?.allowed_ips =
                        parse_allowed_ips(get_next_as_val()?)?;
                }
                "preshared-key" => {
                    let peer = current_peer.as_mut().ok_or(no_peer_err)?;
                    let lines = [
                        format!("Change preshared key for {}", peer.public_key),
                        "(or press <Enter> directly to remove the key from the peer).".to_string(),
                        "New key: ".to_string(),
                    ];
                    let prompt = lines.join("\n");
                    peer.preshared_key = Some(read_key(&prompt, &mut reader)?);
                }
                "persistent-keepalive" => {
                    current_peer
                        .as_mut()
                        .ok_or(no_peer_err)?
                        .persistent_keepalive = parse_persistent_keepalive(get_next_as_val()?)?;
                }
                _ => return Err(Error::InvalidArguments(format!("Unknown option `{}`", key))),
            }
        }

        Ok(())
    }

    fn print(&self) {
        // TODO(b/177877310): Print the connection state.
        println!("name: {}", self.name);
        // Always shows local ip since it's mandatory.
        println!("  local ip: {}", self.local_ips.join(", "));
        println!("  public key: {}", self.public_key);
        println!("  private key: (hidden)");
        if let Some(dns) = &self.name_servers {
            println!("  name servers: {}", dns.join(", "));
        }
        if let Some(mtu) = self.mtu {
            println!("  mtu: {}", mtu);
        }
        println!();
        for p in &self.peers {
            println!("  peer: {}", p.public_key);
            println!("    preshared key: (hidden or not set)");
            println!("    endpoint: {}", p.endpoint);
            println!("    allowed ips: {}", p.allowed_ips);
            println!("    persistent keepalive: {}", p.persistent_keepalive);
            println!();
        }
    }

    // Checks if every required field is filled. We do not check the service state here (i.e., if
    // the service is "Idle", "Connected", or in other states), since shill will return a failure
    // with a proper message immediately if the service is not connectable because of its state.
    fn check_connectability(&self) -> Result<(), Error> {
        for p in &self.peers {
            // `endpoint` is the only required field.
            if p.endpoint.is_empty() {
                return Err(Error::ServiceNotConnectable {
                    service_name: self.name.clone(),
                    reason: format!("Peer {} does not have a valid endpoint", p.public_key),
                });
            }
        }

        Ok(())
    }
}

mod option_util {
    use std::{
        io::{self, Write},
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
        ops::Range,
    };

    use super::Error;

    // Length of base64-encoded keys for WireGuard (Curve25519).
    pub const WG_BASE64_KEYLEN: usize = 44;

    fn is_valid_i32_in(val: &str, range: Range<i32>) -> bool {
        if let Ok(v) = val.parse::<i32>() {
            range.contains(&v)
        } else {
            false
        }
    }

    fn is_valid_hostname(val: &str) -> bool {
        // Some basic checks for a hostname, as per `man 7 hostname`.
        if !(1..254).contains(&val.len()) {
            return false;
        }
        for c in val.chars() {
            match c {
                'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '.' => {}
                _ => return false,
            }
        }
        true
    }

    fn is_valid_wg_key(val: &str) -> bool {
        if val.len() != WG_BASE64_KEYLEN {
            return false;
        }
        // The last character must be the padding character given the key length.
        if !val.ends_with('=') {
            return false;
        }
        // Some basic checks for a base64 string.
        for c in val[0..val.len() - 1].chars() {
            match c {
                'a'..='z' | 'A'..='Z' | '0'..='9' | '/' | '+' => {}
                _ => return false,
            }
        }
        true
    }

    // Prompts |prompt| to the user, and reads a base64-encoded WireGuard key from |reader|.
    pub(super) fn read_key<R: io::BufRead>(prompt: &str, reader: &mut R) -> Result<String, Error> {
        let internal_err = |e| Error::Internal(format!("Read error: {}", e));
        print!("{}", prompt);
        io::stdout().flush().map_err(internal_err)?;
        let mut buf = "".to_string();
        reader.read_line(&mut buf).map_err(internal_err)?;
        let buf = buf.trim().to_string();
        if buf.is_empty() || is_valid_wg_key(&buf) {
            Ok(buf)
        } else {
            Err(Error::InvalidArguments(
                "The input is not a valid WireGuard key".to_string(),
            ))
        }
    }

    fn parse_comma_split_ips(prop: &str, val: &str) -> Result<Vec<IpAddr>, Error> {
        val.split(',')
            .map(|x| x.parse::<IpAddr>())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| {
                Error::InvalidArguments(format!(
                    "'{}' should be a comma-separated list of valid IP addresses, but got '{}'",
                    prop, val
                ))
            })
    }

    pub(super) fn parse_local_ip(val: &str) -> Result<Vec<String>, Error> {
        match parse_comma_split_ips("local-ip", val) {
            Ok(v) if v.iter().filter(|x| x.is_ipv4()).count() > 1 => Err(Error::InvalidArguments(
                "Support at most one IPv4 local-ip".to_string(),
            )),
            Ok(v) if v.iter().filter(|x| x.is_ipv6()).count() > 1 => Err(Error::InvalidArguments(
                "Support at most one IPv6 local-ip".to_string(),
            )),
            Ok(v) => Ok(v.into_iter().map(|x| x.to_string()).collect()),
            Err(e) => Err(e),
        }
    }

    pub(super) fn parse_dns(val: &str) -> Result<Option<Vec<String>>, Error> {
        if val.is_empty() {
            return Ok(None);
        }

        parse_comma_split_ips("dns", val)
            .map(|v| Some(v.into_iter().map(|x| x.to_string()).collect()))
    }

    pub(super) fn parse_mtu(val: &str) -> Result<Option<i32>, Error> {
        if val.is_empty() {
            return Ok(None);
        }

        match val.parse::<i32>() {
            Ok(0) => Ok(None),
            // [576, 65536) as per wireguard-tools.
            Ok(x) if (576..65536).contains(&x) => Ok(Some(x)),
            _ => Err(Error::InvalidArguments(format!(
                "'mtu' should be in range from 576 to 65535, but got '{}'",
                val
            ))),
        }
    }

    pub(super) fn parse_peer(val: &str) -> Result<String, Error> {
        if is_valid_wg_key(val) {
            Ok(val.to_string())
        } else {
            Err(Error::InvalidArguments(
                "The given value after 'peer' is not a vaild public key".to_string(),
            ))
        }
    }

    pub(super) fn parse_endpoint(val: &str) -> Result<String, Error> {
        if let Ok(s) = val.parse::<SocketAddr>() {
            return Ok(s.to_string());
        }

        let segments: Vec<&str> = val.split(':').collect();
        match segments.as_slice() {
            [h, p] if is_valid_hostname(h) && is_valid_i32_in(p, 1..65536) => Ok(val.to_string()),
            _ => Err(Error::InvalidArguments(format!(
                "'endpoint' should be an IP or hostname, followed by a colon and then a port number, but got '{}'",
                val
            ))),
        }
    }

    pub(super) fn parse_allowed_ips(val: &str) -> Result<String, Error> {
        if val.is_empty() {
            return Ok("".to_string());
        }

        let err = || {
            Error::InvalidArguments(format!(
                "'allowed-ips' should be a common-separated list of \
                 IP addresses with CIDR notation, but got '{}'",
                val
            ))
        };

        // Clears the bits after netmask (e.g., "192.168.1.1/24" => "192.168.1.0/24")
        let formatter = |s: &str| -> Result<String, Error> {
            let segments: Vec<&str> = s.split('/').collect();
            if segments.len() != 2 {
                return Err(err());
            }
            let prefix = segments[1].parse::<i32>().map_err(|_| err())?;
            match segments[0].parse::<IpAddr>().map_err(|_| err())? {
                IpAddr::V4(addr) => {
                    let addr_u32 = addr
                        .octets()
                        .iter()
                        .fold(0u32, |acc, x| (acc << 8) + (*x as u32));
                    match prefix {
                        0..=31 => {
                            let base_addr = Ipv4Addr::from(addr_u32 & !(u32::MAX >> prefix));
                            Ok(format!("{}/{}", base_addr, prefix))
                        }
                        32 => Ok(s.to_string()),
                        _ => Err(err()),
                    }
                }
                IpAddr::V6(addr) => {
                    let addr_u128 = addr
                        .octets()
                        .iter()
                        .fold(0u128, |acc, x| (acc << 8) + (*x as u128));
                    match prefix {
                        0..=127 => {
                            let base_addr = Ipv6Addr::from(addr_u128 & !(u128::MAX >> prefix));
                            Ok(format!("{}/{}", base_addr, prefix))
                        }
                        128 => Ok(s.to_string()),
                        _ => Err(err()),
                    }
                }
            }
        };

        Ok(val
            .split(',')
            .map(formatter)
            .collect::<Result<Vec<_>, _>>()?
            .join(","))
    }

    pub(super) fn parse_persistent_keepalive(val: &str) -> Result<String, Error> {
        match val {
            "off" => Ok(val.to_string()),
            v if is_valid_i32_in(v, 0..65536) => Ok(val.to_string()),
            _ => Err(Error::InvalidArguments(format!(
                "'persistent-keepalive' should be in range from 0 to 65535, but got '{}'",
                val
            ))),
        }
    }
}

fn make_dbus_connection() -> Result<Connection, Error> {
    Connection::new_system()
        .map_err(|err| Error::Internal(format!("Failed to get D-Bus connection: {}", err)))
}

fn make_manager_proxy(connection: &Connection) -> dbus::blocking::Proxy<&Connection> {
    connection.with_proxy("org.chromium.flimflam", "/", DEFAULT_DBUS_TIMEOUT)
}

fn make_service_proxy<'a>(
    connection: &'a Connection,
    service_path: &'a str,
) -> dbus::blocking::Proxy<'a, &'a Connection> {
    connection.with_proxy("org.chromium.flimflam", service_path, DEFAULT_DBUS_TIMEOUT)
}

// Queries Shill to get all configured WireGuard services.
fn get_wireguard_services(connection: &Connection) -> Result<Vec<WireGuardService>, Error> {
    let manager_proxy = make_manager_proxy(connection);
    let manager_properties: InputPropMap =
        OrgChromiumFlimflamManager::get_properties(&manager_proxy)
            .map_err(|err| Error::Internal(format!("Failed to get Manager properties: {}", err)))?;

    let mut wg_services = Vec::new();

    // The "Services" property should contain a list of D-Bus paths.
    let services = manager_properties.get_strings(PROPERTY_SERVICES)?;
    for path in services {
        let proxy = make_service_proxy(connection, &path);
        let service_properties = OrgChromiumFlimflamService::get_properties(&proxy)
            .map_err(|err| Error::Internal(format!("Failed to get service properties: {}", err)))?;
        match WireGuardService::parse_from_prop_map(&service_properties) {
            Ok(mut service) => {
                service.path = Some(path.to_string());
                wg_services.push(service)
            }
            Err(Error::ServiceNotFound(_)) => continue,
            Err(other_err) => return Err(other_err),
        };
    }

    Ok(wg_services)
}

fn get_wireguard_service_by_name(
    connection: &Connection,
    service_name: &str,
) -> Result<WireGuardService, Error> {
    let services: Vec<WireGuardService> = get_wireguard_services(connection)?
        .into_iter()
        .filter(|x| x.name == service_name)
        .collect();

    match services.len() {
        0 => Err(Error::ServiceNotFound(service_name.to_string())),
        1 => Ok(services.into_iter().next().unwrap()),
        _ => Err(Error::Internal(
            "Found duplicated WireGuard services".to_string(),
        )),
    }
}

fn check_wireguard_support() -> Result<(), Error> {
    let connection = make_dbus_connection()?;
    let manager_proxy = make_manager_proxy(&connection);
    let manager_properties: InputPropMap =
        OrgChromiumFlimflamManager::get_properties(&manager_proxy)
            .map_err(|err| Error::Internal(format!("Failed to get Manager properties: {}", err)))?;

    let prohibited_techs = manager_properties.get_string(PROPERTY_PROHIBITED_TECHNOLOGIES)?;
    if prohibited_techs.split(',').any(|x| x == TYPE_VPN) {
        return Err(Error::VpnDisabled);
    }

    let supported_vpns = manager_properties.get_string(PROPERTY_SUPPORTED_VPN_TYPES)?;
    if !supported_vpns.split(',').any(|x| x == TYPE_WIREGUARD) {
        return Err(Error::WireGuardUnavailable);
    }

    Ok(())
}

fn wireguard_list() -> Result<(), Error> {
    let connection = make_dbus_connection()?;
    let mut services = get_wireguard_services(&connection)?;
    services.sort_by(|a, b| a.name.cmp(&b.name));
    for service in &services {
        service.print()
    }
    Ok(())
}

fn wireguard_show(service_name: &str) -> Result<(), Error> {
    let connection = make_dbus_connection()?;
    get_wireguard_service_by_name(&connection, service_name)?.print();
    Ok(())
}

fn wireguard_new(service_name: &str) -> Result<(), Error> {
    let connection = make_dbus_connection()?;

    // Checks if there is already a service with the given name.
    match get_wireguard_service_by_name(&connection, service_name) {
        Ok(_) => return Err(Error::ServiceAlreadyExists(service_name.to_string())),
        Err(Error::ServiceNotFound(_)) => {}
        Err(err) => return Err(err),
    };

    let manager_proxy = make_manager_proxy(&connection);
    let service = WireGuardService {
        path: None,
        name: service_name.to_string(),
        local_ips: Vec::new(),
        private_key: None,
        public_key: "".to_string(),
        name_servers: None,
        mtu: None,
        peers: Vec::new(),
    };
    manager_proxy
        .configure_service(service.encode_into_prop_map())
        .map_err(|err| Error::Internal(format!("Failed to configure service: {}", err)))?;

    println!("Service {} created", service_name);
    Ok(())
}

fn wireguard_set(service_name: &str, args: &[&str]) -> Result<(), Error> {
    let connection = make_dbus_connection()?;
    let mut wg_service = get_wireguard_service_by_name(&connection, service_name)?;
    wg_service.update_from_args(args, io::stdin().lock())?;
    let manager_proxy = make_manager_proxy(&connection);
    let properties = wg_service.encode_into_prop_map();
    manager_proxy.configure_service(properties).map_err(|err| {
        error!("ERROR: Failed to configure service: {}", err);
        Error::Internal("".to_string())
    })?;

    println!("Service {} updated", service_name);
    Ok(())
}

fn wireguard_connect(service_name: &str) -> Result<(), Error> {
    let connection = make_dbus_connection()?;
    let service = get_wireguard_service_by_name(&connection, service_name)?;
    service.check_connectability()?;
    make_service_proxy(&connection, &service.path.unwrap())
        .connect()
        .map_err(|err| Error::Internal(format!("Failed to connect service: {}", err)))?;

    println!("Connecting to {}..", service_name);
    Ok(())
}

fn wireguard_disconnect(service_name: &str) -> Result<(), Error> {
    let connection = make_dbus_connection()?;
    let service = get_wireguard_service_by_name(&connection, service_name)?;
    make_service_proxy(&connection, &service.path.unwrap())
        .disconnect()
        .map_err(|err| Error::Internal(format!("Failed to disconnect service: {}", err)))?;

    println!("Disconnecting from {}..", service_name);
    Ok(())
}

fn wireguard_del(service_name: &str) -> Result<(), Error> {
    let connection = make_dbus_connection()?;
    let service = get_wireguard_service_by_name(&connection, service_name)?;
    make_service_proxy(&connection, &service.path.unwrap())
        .remove()
        .map_err(|err| Error::Internal(format!("Failed to delete service: {}", err)))?;

    println!("Service {} was deleted", service_name);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Keys are generate randomly by `wireguard-tools`, only for test usages.
    const GOOD_KEYS: [&str; 7] = [
        "",
        "  ",
        "   \n",
        "yJtfKXN4bvw/Dlgp4uRUrbBJZDQGojDL7J5mbdh+x2k=",
        "yJtfKXN4bvw/Dlgp4uRUrbBJZDQGojDL7J5mbdh+x2k=  ",
        "  yJtfKXN4bvw/Dlgp4uRUrbBJZDQGojDL7J5mbdh+x2k=",
        "  yJtfKXN4bvw/Dlgp4uRUrbBJZDQGojDL7J5mbdh+x2k=\n",
    ];
    const BAD_KEYS: [&str; 4] = [
        "abc",
        "abc\n",
        "yJtfKXN4bvw/Dlgp4uRUrbB\nJZDQGojDL7J5mbdh+x2k=",
        "yJtfKXN4bvw/Dlgp4uRUrbBJZDQGojDL7J5mbdh+x2\n",
    ];

    struct TestVars {
        public_key_a: String,
        public_key_b: String,
        public_key_new: String,
        peer_a: WireGuardPeer,
        peer_b: WireGuardPeer,
        service: WireGuardService,
    }

    impl TestVars {
        fn new() -> Self {
            // Keys are generated randomly by `wireguard-tools`, only for test usages.
            let public_key_a: String = "JNy+A9BmLM3wAY/8JrL8KZ0pxIuwZ61FjsrK4DyNXgk=".to_string();
            let public_key_b: String = "IYo3i7xxgCKXEc6Nvawlmg2wO0Qf5ojqvLjz386RmB4=".to_string();
            let public_key_new: String = "LCDxqGY8J5+gXFGh1IqAsMC2CHF6w+oAuegB0nA8Ti4=".to_string();
            let peer_a = WireGuardPeer {
                public_key: public_key_a.clone(),
                endpoint: "10.0.8.1:13579".to_string(),
                allowed_ips: "0.0.0.0/0".to_string(),
                persistent_keepalive: "".to_string(),
                preshared_key: None,
            };
            let peer_b = WireGuardPeer {
                public_key: public_key_b.clone(),
                endpoint: "10.0.10.1:24680".to_string(),
                allowed_ips: "10.8.0.0/16,192.168.100.0/24".to_string(),
                persistent_keepalive: "3".to_string(),
                preshared_key: None,
            };
            let service = WireGuardService {
                path: None,
                name: "wg_test".to_string(),
                local_ips: vec![("192.168.1.2".to_string())],
                private_key: None,
                public_key: "".to_string(),
                name_servers: Some(vec!["4.3.2.1".to_string()]),
                mtu: Some(1234),
                peers: vec![peer_a.clone(), peer_b.clone()],
            };
            TestVars {
                public_key_a,
                public_key_b,
                public_key_new,
                peer_a,
                peer_b,
                service,
            }
        }
    }

    #[test]
    fn test_update_local_ip() {
        let vars = TestVars::new();
        // Input and the IPv4 addr in it.
        let cases = [
            ("192.168.1.1", Some("192.168.1.1".to_string())),
            ("fd01::1", None),
            ("192.168.1.1,fd01::1", Some("192.168.1.1".to_string())),
            ("fd01::1,192.168.1.1", Some("192.168.1.1".to_string())),
        ];
        for c in cases.iter() {
            let mut expected = vars.service.clone();
            expected.local_ips = c.0.split(',').map(|x| x.to_string()).collect();
            let mut actual = vars.service.clone();
            let args = ["local-ip", c.0];
            actual.update_from_args(&args, "".as_bytes()).unwrap();
            assert_eq!(expected, actual);
        }
    }

    #[test]
    fn test_update_local_ip_invalid() {
        let vars = TestVars::new();
        let cases = [
            "",
            "192.168.1",
            "abcdabcd",
            "1.2.3.4,1.2.3.5",
            "fd01::1,fd01::2",
            "1.2.3.4,1.2.3.5,fd01::1",
            "fd01::1,fd01::2,1.2.3.4",
        ];
        for c in cases.iter() {
            let mut actual = vars.service.clone();
            let args = ["local-ip", c];
            actual.update_from_args(&args, "".as_bytes()).unwrap_err();
        }
    }

    #[test]
    fn test_update_private_key() {
        let vars = TestVars::new();
        for c in GOOD_KEYS.iter() {
            let mut expected = vars.service.clone();
            expected.private_key = Some(c.trim().to_string());
            let mut actual = vars.service.clone();
            let args = ["private-key"];
            actual.update_from_args(&args, c.as_bytes()).unwrap();
            assert_eq!(expected, actual);
        }
    }

    #[test]
    fn test_update_private_key_invalid() {
        let vars = TestVars::new();
        for c in BAD_KEYS.iter() {
            let mut actual = vars.service.clone();
            let args = ["private-key"];
            actual.update_from_args(&args, c.as_bytes()).unwrap_err();
        }
    }

    #[test]
    fn test_update_dns() {
        let vars = TestVars::new();
        let cases = [
            "8.8.8.8,1.2.3.4",
            "8.8.8.8",
            "8.8.8.8,fd01::1",
            "fd01::1,8.8.8.8",
        ];
        for c in cases.iter() {
            let mut expected = vars.service.clone();
            expected.name_servers = Some(c.split(',').map(|x| x.to_string()).collect());
            let mut actual = vars.service.clone();
            actual.update_from_args(&["dns", c], "".as_bytes()).unwrap();
            assert_eq!(expected, actual);
        }
    }

    #[test]
    fn test_update_dns_default() {
        let vars = TestVars::new();
        let mut expected = vars.service.clone();
        expected.name_servers = None;
        let mut actual = vars.service;
        actual
            .update_from_args(&["dns", ""], "".as_bytes())
            .unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_update_dns_invalid() {
        let vars = TestVars::new();
        let cases = ["192.168.1", "abcdabcd", "8.8.8.8,abc", "fe80::1,abc"];
        for c in cases.iter() {
            let mut actual = vars.service.clone();
            let args = ["dns", c];
            actual.update_from_args(&args, "".as_bytes()).unwrap_err();
        }
    }

    #[test]
    fn test_update_mtu() {
        let vars = TestVars::new();
        let cases = ["576", "1000", "65535"];
        for c in cases.iter() {
            let mut expected = vars.service.clone();
            expected.mtu = Some(c.parse::<i32>().unwrap());
            let mut actual = vars.service.clone();
            actual.update_from_args(&["mtu", c], "".as_bytes()).unwrap();
            assert_eq!(expected, actual);
        }
    }

    #[test]
    fn test_update_mtu_default() {
        let vars = TestVars::new();
        let cases = ["0", ""];
        for c in cases.iter() {
            let mut expected = vars.service.clone();
            expected.mtu = None;
            let mut actual = vars.service.clone();
            actual.update_from_args(&["mtu", c], "".as_bytes()).unwrap();
            assert_eq!(expected, actual);
        }
    }

    #[test]
    fn test_update_mtu_invalid() {
        let vars = TestVars::new();
        let cases = ["-1", "575", "1000.0", "65536", "abcde"];
        for c in cases.iter() {
            let mut actual = vars.service.clone();
            let args = ["mtu", c];
            actual.update_from_args(&args, "".as_bytes()).unwrap_err();
        }
    }

    #[test]
    fn test_update_peer_endpoint() {
        let vars = TestVars::new();
        let cases = [
            "192.168.1.1:1234",
            "10.8.0.3:21",
            "[fe80::1]:12345",
            "www.example.com:65535",
            "a-z.A-Z01234.xyz:1111",
        ];

        for c in cases.iter() {
            let mut expected = vars.service.clone();
            let mut updated_peer_b = vars.peer_b.clone();
            updated_peer_b.endpoint = c.to_string();
            expected.peers = vec![vars.peer_a.clone(), updated_peer_b];
            let mut actual = vars.service.clone();
            let args = ["peer", &vars.public_key_b, "endpoint", c];
            actual.update_from_args(&args, "".as_bytes()).unwrap();
            assert_eq!(expected, actual);
        }
    }

    #[test]
    fn test_update_peer_endpoint_invalid() {
        let vars = TestVars::new();
        let cases = [
            "fe80::1:12345",  // invalid IPv6 addr with port
            "192.168.1.1:-1", // bad port
            "10.8.0.3:65536",
            "&example.com:1234", // bad hostname
            "example,com:1234",
            ":1234",
        ];
        for c in cases.iter() {
            let mut actual = vars.service.clone();
            let args = ["peer", &vars.public_key_b, "endpoint", c];
            actual.update_from_args(&args, "".as_bytes()).unwrap_err();
        }
    }

    #[test]
    fn test_update_peer_allowed_ips() {
        let vars = TestVars::new();

        // Inputs and expected outputs.
        let cases = [
            ("", ""),
            ("0.0.0.0/0", "0.0.0.0/0"),
            ("192.168.12.13/0", "0.0.0.0/0"),
            ("192.168.0.1/32", "192.168.0.1/32"),
            ("192.168.1.0/24", "192.168.1.0/24"),
            ("192.168.1.1/24", "192.168.1.0/24"),
            ("192.168.0.0/16", "192.168.0.0/16"),
            ("192.168.12.13/16", "192.168.0.0/16"),
            ("192.168.128.0/20,10.0.0.0/8", "192.168.128.0/20,10.0.0.0/8"),
            ("fd01::1/64", "fd01::/64"),
            ("fd01::1/8", "fd00::/8"),
            ("fd01::1/128", "fd01::1/128"),
        ];

        for c in cases.iter() {
            let mut expected = vars.service.clone();
            let mut updated_peer_b = vars.peer_b.clone();
            updated_peer_b.allowed_ips = c.1.to_string();
            expected.peers = vec![vars.peer_a.clone(), updated_peer_b];
            let mut actual = vars.service.clone();
            let args = ["peer", &vars.public_key_b, "allowed-ips", c.0];
            actual.update_from_args(&args, "".as_bytes()).unwrap();
            assert_eq!(expected, actual);
        }
    }

    #[test]
    fn test_update_peer_allowed_ips_invalid() {
        let vars = TestVars::new();
        let cases = [
            "192.168.1.0/-1", // bad CIDR
            "192.168.1.0/256",
            "192.168.128.0/20, 10.0.0.0/8", // additional space
            "192.168.128.0/20;10.0.0.0/8",  // bad separator
            "fd01::1/-1",
            "fd01::1",
            "fd01::/129",
        ];
        for c in cases.iter() {
            let mut actual = vars.service.clone();
            let args = ["peer", &vars.public_key_b, "allowed-ips", c];
            actual.update_from_args(&args, "".as_bytes()).unwrap_err();
        }
    }

    #[test]
    fn test_update_peer_persistent_keepalive() {
        let vars = TestVars::new();
        let cases = ["off", "0", "1", "300", "65535"];

        for c in cases.iter() {
            let mut expected = vars.service.clone();
            let mut updated_peer_b = vars.peer_b.clone();
            updated_peer_b.persistent_keepalive = c.to_string();
            expected.peers = vec![vars.peer_a.clone(), updated_peer_b];
            let mut actual = vars.service.clone();
            let args = ["peer", &vars.public_key_b, "persistent-keepalive", c];
            actual.update_from_args(&args, "".as_bytes()).unwrap();
            assert_eq!(expected, actual);
        }
    }

    #[test]
    fn test_update_peer_persistent_keepalive_invalid() {
        let vars = TestVars::new();
        let cases = ["-1", "1.0", "65536", "abcd", "192.168.1.1", "remove"];
        for c in cases.iter() {
            let mut actual = vars.service.clone();
            let args = ["peer", &vars.public_key_b, "persistent-keepalive", c];
            actual.update_from_args(&args, "".as_bytes()).unwrap_err();
        }
    }

    #[test]
    fn test_update_peer_preshared_key() {
        let vars = TestVars::new();
        for c in GOOD_KEYS.iter() {
            let mut expected = vars.service.clone();
            let mut updated_peer_b = vars.peer_b.clone();
            updated_peer_b.preshared_key = Some(c.trim().to_string());
            expected.peers = vec![vars.peer_a.clone(), updated_peer_b];
            let mut actual = vars.service.clone();
            let args = ["peer", &vars.public_key_b, "preshared-key"];
            actual.update_from_args(&args, c.as_bytes()).unwrap();
            assert_eq!(expected, actual);
        }
    }

    #[test]
    fn test_update_peer_preshared_key_invalid() {
        let vars = TestVars::new();
        for c in BAD_KEYS.iter() {
            let mut actual = vars.service.clone();
            let args = ["peer", &vars.public_key_b, "preshared-key"];
            actual.update_from_args(&args, c.as_bytes()).unwrap_err();
        }
    }

    #[test]
    fn test_update_add_peer() {
        let vars = TestVars::new();
        let endpoint_new = "34.56.78.90:45678";

        let mut expected = vars.service.clone();
        expected.peers.push(WireGuardPeer {
            public_key: vars.public_key_new.clone(),
            endpoint: endpoint_new.to_string(),
            allowed_ips: "".to_string(),
            persistent_keepalive: "".to_string(),
            preshared_key: None,
        });

        let mut actual = vars.service.clone();
        let args = ["peer", &vars.public_key_new, "endpoint", endpoint_new];
        actual.update_from_args(&args, "".as_bytes()).unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_update_remove_peer() {
        let vars = TestVars::new();
        let mut expected = vars.service.clone();
        expected.peers = vec![vars.peer_b.clone()];
        let mut actual = vars.service.clone();
        let args = ["peer", &vars.public_key_a, "remove"];
        actual.update_from_args(&args, "".as_bytes()).unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_update_remove_new_peer() {
        let vars = TestVars::new();
        let mut actual = vars.service.clone();
        let args = ["peer", &vars.public_key_new, "remove"];
        actual.update_from_args(&args, "".as_bytes()).unwrap_err();
    }

    #[test]
    fn test_update_all_in_one() {
        // Keys below generated randomly by `wireguard-tools`, only for test usages.
        let vars = TestVars::new();
        let local_ip = "192.168.99.2";
        let private_key = "yJtfKXN4bvw/Dlgp4uRUrbBJZDQGojDL7J5mbdh+x2k=";
        let endpoint_a = "34.56.78.90:45678";
        let allowed_ips_a = "192.168.101.0/24";
        let persistent_keepalive_a = "21";
        let preshared_key_a = "";
        let endpoint_new = "90.56.78.34:12345";
        let allowed_ips_new = "192.168.102.0/24";
        let persistent_keepalive_new = "off";
        let preshared_key_new = "xZkhH/yBfi3NtT1MzX0iszT03dr1g/0URWEgG5hwCrQ=";
        let updated_peer_a = WireGuardPeer {
            public_key: vars.public_key_a.clone(),
            endpoint: endpoint_a.to_string(),
            allowed_ips: allowed_ips_a.to_string(),
            persistent_keepalive: persistent_keepalive_a.to_string(),
            preshared_key: Some(preshared_key_a.to_string()),
        };
        let new_peer = WireGuardPeer {
            public_key: vars.public_key_new.clone(),
            endpoint: endpoint_new.to_string(),
            allowed_ips: allowed_ips_new.to_string(),
            persistent_keepalive: persistent_keepalive_new.to_string(),
            preshared_key: Some(preshared_key_new.to_string()),
        };

        let mut expected = vars.service.clone();
        expected.local_ips = vec![local_ip.to_string()];
        expected.private_key = Some(private_key.to_string());
        expected.name_servers = Some(vec!["8.8.8.8".to_string(), "1.2.3.4".to_string()]);
        expected.mtu = Some(1000);
        expected.peers = vec![updated_peer_a, new_peer];

        let mut cmd = vec!["local-ip", local_ip];
        cmd.extend_from_slice(&["private-key"]);
        cmd.extend_from_slice(&["dns", "8.8.8.8,1.2.3.4", "mtu", "1000"]);
        cmd.extend_from_slice(&["peer", &vars.public_key_b, "remove"]);
        cmd.extend_from_slice(&["peer", &vars.public_key_a, "endpoint", endpoint_a]);
        cmd.extend_from_slice(&["preshared-key"]);
        cmd.extend_from_slice(&["allowed-ips", allowed_ips_a]);
        cmd.extend_from_slice(&["persistent-keepalive", persistent_keepalive_a]);
        cmd.extend_from_slice(&["peer", &vars.public_key_new, "endpoint", endpoint_new]);
        cmd.extend_from_slice(&["allowed-ips", allowed_ips_new]);
        cmd.extend_from_slice(&["persistent-keepalive", persistent_keepalive_new]);
        cmd.extend_from_slice(&["preshared-key"]);

        let input = format!(
            "{}\n{}\n{}\n",
            private_key, preshared_key_a, preshared_key_new
        );

        let mut actual = vars.service;
        actual.update_from_args(&cmd, input.as_bytes()).unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_check_connectability() {
        let mut vars = TestVars::new();
        let service = &mut vars.service;
        service.check_connectability().unwrap();
        service.peers[0].endpoint = "".to_string();
        service.check_connectability().unwrap_err();
    }
}

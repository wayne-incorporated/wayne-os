// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::env;
use std::process::exit;
use std::str::FromStr;

use hwsec_utils::context::RealContext;
use hwsec_utils::cr50::cr50_set_factory_config;
use hwsec_utils::cr50::Cr50SetFactoryConfigVerdict;
use libchromeos::syslog;
use log::error;

fn parse_bool(s: &str) -> Option<bool> {
    match s {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

fn print_usage(arg0: &str) {
    error!("Usage: {} x_branded compliance_version", arg0);
}

fn main() {
    let ident = match syslog::get_ident_from_process() {
        Some(ident) => ident,
        None => std::process::exit(1),
    };

    if let Err(e) = syslog::init(ident, false /* Don't log to stderr */) {
        eprintln!("failed to initialize syslog: {}", e);
        std::process::exit(1)
    }

    let mut real_ctx = RealContext::new();
    let args_string: Vec<String> = env::args().collect();
    let args: Vec<&str> = args_string.iter().map(|s| s.as_str()).collect();
    if args.len() != 3 {
        print_usage(args[0]);
        exit(Cr50SetFactoryConfigVerdict::GeneralError as i32)
    }
    let Some(x_branded) = parse_bool(args[1]) else {
        print_usage(args[0]);
            exit(Cr50SetFactoryConfigVerdict::GeneralError as i32)
        };
    let Ok(ver) = u8::from_str(args[2]) else {
        print_usage(args[0]);
            exit(Cr50SetFactoryConfigVerdict::GeneralError as i32)
        };
    cr50_set_factory_config(&mut real_ctx, x_branded, ver)
        .map_err(|e| exit(e as i32))
        .unwrap();
}

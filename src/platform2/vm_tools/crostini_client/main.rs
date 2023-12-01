// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub mod disk;
pub mod frontends;
pub mod methods;
pub mod proto;
pub mod unsafe_misc;

use std::collections::BTreeMap;
use std::env;
use std::error::Error;

use getopts::Options;

use frontends::{EnvMap, FRONTENDS};
use libchromeos::panic_handler::install_memfd_handler;
use methods::Methods;

fn make_options() -> Options {
    let mut opts = Options::new();
    opts.optflag("h", "help", "print this help menu");

    opts
}

fn print_usage(program_name: &str, opts: &Options) {
    eprintln!("Crostini client\n");
    let brief = format!("USAGE: {} [SUBCOMMAND|FRONTEND]", program_name);
    eprintln!("{}", opts.usage(&brief));

    eprint!("Alternatively, invoke a supported FRONTEND: ");
    let mut first = true;
    for frontend in FRONTENDS {
        if !first {
            eprint!(", ");
        }
        eprint!("{}", frontend.name());
        first = false;
    }
    eprintln!("\n-----");

    for frontend in FRONTENDS {
        frontend.print_usage(frontend.name());
        eprintln!("-----");
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    install_memfd_handler();
    let args_string: Vec<String> = env::args().collect();
    let args: Vec<&str> = args_string.iter().map(|s| s.as_str()).collect();
    let vars_string: BTreeMap<String, String> = env::vars().collect();
    let vars: EnvMap = vars_string
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    if args.is_empty() {
        print_usage("crostini_client", &make_options());
        return Ok(());
    }

    // Match the program name against frontend names.
    for frontend in FRONTENDS {
        if args[0].ends_with(frontend.name()) {
            return frontend.run(&mut Methods::new()?, &args, &vars);
        }
    }

    if args.len() == 1 {
        print_usage(&args[0], &make_options());
        return Ok(());
    }

    // Next, match the subcommand against frontend names.
    for frontend in FRONTENDS {
        if args[1].ends_with(frontend.name()) {
            return frontend.run(&mut Methods::new()?, &args[1..], &vars);
        }
    }

    eprintln!("unrecognized frontend name: `{}`", args[0]);
    std::process::exit(1);
}

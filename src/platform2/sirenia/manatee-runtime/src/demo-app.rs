// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Demo application for use with the sirenia tast test.

#![deny(unsafe_op_in_unsafe_fn)]

// Needed for borrowing scoped data to use.
use std::borrow::Borrow;
use std::borrow::BorrowMut;
use std::io;

use log::info;
use manatee_runtime::storage::TrichechusStorage;
use manatee_runtime::ExclusiveScopedData;
use manatee_runtime::ScopedData;
use stderrlog::StdErrLog;

// Any creation of a scoped data requires that a callback is given which will
// be called if the id is not found in the backing store. In most circumstances,
// such as this one, simply returning an empty string is sufficient.

fn callback_id_not_found(_s: &str) -> String {
    "".to_string()
}

/// A test demo app that just stores a value that is written to stdin then
/// rereads it out of storage and prints back out to stdout.
fn main() {
    // Logger must be initialized in order to log to it.
    if let Err(e) = StdErrLog::new().verbosity(5).init() {
        eprintln!("failed to initialize syslog: {}", e);
        return;
    }

    // Creating a new TrichechusStorage allows the TEE app to access data stored
    // on the Chrome OS side.
    info!("Starting up storage");
    let mut store = TrichechusStorage::new();

    {
        let mut buffer = String::new();

        // Creating a scoped data retrieves the value associated with the given
        // id from the backing store. If the id is not found, the callback is
        // called instead. The data will be written back on `flush` or when the
        // variable goes out of scope.
        info!("Creating scoped data");
        let mut data: ExclusiveScopedData<String, TrichechusStorage> =
            ScopedData::new(&mut store, "Test id", callback_id_not_found).unwrap();
        // ScopedData must be borrowed to actually use and change.
        let s: &mut String = data.borrow_mut();
        info!("Reading data");
        match io::stdin().read_line(&mut buffer) {
            Ok(_) => {
                // Used for testing crash reporting
                if buffer == "please crash\n" {
                    panic!("bye bye!");
                }
                s.push_str(&buffer);
            }
            Err(error) => println!("error: {}", error),
        }
    }

    // This will retrieve the value assigned to the id "Test id" in the
    // previous block, because it was written back to the store when the
    // variable went out of scope.
    let data2: ExclusiveScopedData<String, TrichechusStorage> =
        ScopedData::new(&mut store, "Test id", callback_id_not_found).unwrap();
    let s2: &String = data2.borrow();
    print!("{}", s2);
}

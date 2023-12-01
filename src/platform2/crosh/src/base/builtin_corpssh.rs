// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Provides the command "builtin_corpssh" for crosh which enables/disables
// built-in gnubby's CorpSSH support.
// This command is deprecated and will be removed in M116.

use crate::dispatcher::{self, Arguments, Command, Dispatcher};

pub fn register(dispatcher: &mut Dispatcher) {
    dispatcher.register_command(
        Command::new(
            "builtin_corpssh".to_string(),
            "".to_string(),
            "[Deprecated] Enable or disable CorpSSH support for the \
             built-in gnubby.\n  This is now always enabled, and the \
             command will be removed soon."
                .to_string(),
        )
        .set_command_callback(Some(execute_builtin_corpssh)),
    );
}

fn execute_builtin_corpssh(_cmd: &Command, _args: &Arguments) -> Result<(), dispatcher::Error> {
    eprintln!(
        "This command is deprecated. CorpSSH support is now \
     always enabled,\nand the command will be removed soon."
    );
    Err(dispatcher::Error::CommandReturnedError)
}

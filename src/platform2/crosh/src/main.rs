// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![deny(unsafe_op_in_unsafe_fn)]

use std::env::var;
use std::io::{self, stdout, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicI32, Ordering};

use crosh::dispatcher::{CompletionResult, Dispatcher};
use crosh::{setup_dispatcher, util};
use libc::{
    c_int, c_void, fork, kill, pid_t, waitpid, SIGHUP, SIGINT, SIGKILL, STDERR_FILENO, WIFSTOPPED,
};
use libchromeos::chromeos::is_dev_mode;
use libchromeos::panic_handler::install_memfd_handler;
use libchromeos::sys::{block_signal, error, handle_eintr_errno, unblock_signal};
use libchromeos::syslog;
use rustyline::completion::Completer;
use rustyline::config::Configurer;
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{CompletionType, Config, Context, Editor, Helper};

const HISTORY_FILENAME: &str = ".crosh_history";

// Program name.
const IDENT: &str = "crosh";

fn usage(error: bool) {
    let usage_msg = r#"Usage: crosh [options] [-- [args]]

Options:
  --dev(=true|false) Force dev mode commands to be available or not. '--dev' is
                     the same as '--dev=true'.
  --removable        Force removable (boot from USB/SD/etc...) mode.
  --usb              Same as above.
  --help, -h         Show this help string.
  -- <all args after this are a command to run>
                Execute a single command and exit.
"#;
    if error {
        eprintln!("{}", usage_msg)
    } else {
        println!("{}", usage_msg);
    }
}

fn intro() {
    println!(
        r#"Welcome to crosh, the ChromeOS developer shell.

If you got here by mistake, don't panic!  Just close this tab and carry on.

Type 'help' for a list of commands.

If you want to customize the look/behavior, you can use the options page.
Load it by using the Ctrl-Shift-P keyboard shortcut.
"#
    );
}

static COMMAND_RUNNING_PID: AtomicI32 = AtomicI32::new(-1);

// Provides integration with rustyline.
struct ReadLineHelper {
    dispatcher: Dispatcher,
}

impl ReadLineHelper {
    fn dispatcher(&self) -> &Dispatcher {
        &self.dispatcher
    }
}

impl Helper for ReadLineHelper {}

impl Completer for ReadLineHelper {
    type Candidate = String;

    fn complete(
        &self,
        line: &str,
        _pos: usize,
        _ctx: &Context<'_>,
    ) -> Result<(usize, Vec<String>), ReadlineError> {
        let tokens: Vec<String> = match shell_words::split(line) {
            Ok(v) => v,
            Err(shell_words::ParseError) => {
                // Don't provide completion if the given line ends in the middle of a token.
                return Ok((0, vec![line.to_string(); 1]));
            }
        };
        match self.dispatcher.complete_command(tokens) {
            CompletionResult::NoMatches => Ok((0, vec![line.to_string(); 1])),
            CompletionResult::SingleDiff(diff) => Ok((line.len(), vec![diff; 1])),
            CompletionResult::WholeTokenList(matches) => Ok((0, matches)),
        }
    }
}

impl Hinter for ReadLineHelper {
    type Hint = String;
}

impl Highlighter for ReadLineHelper {}

impl Validator for ReadLineHelper {}

// Forks off a child process which executes the command handler and waits for it to return.
// COMMAND_RUNNING_PID is updated to have the child process id so SIGINT can be sent.
fn handle_cmd(dispatcher: &Dispatcher, args: Vec<String>) -> Result<(), ()> {
    let pid: pid_t;
    unsafe {
        pid = fork();
    }
    if pid < 0 {
        return Err(());
    }
    // Handle the child thread case.
    if pid == 0 {
        clear_signal_handlers();
        dispatch_cmd(dispatcher, args);
    }

    COMMAND_RUNNING_PID.store(pid, Ordering::Release);

    let mut status: c_int = 1;
    // Safe because status is owned.
    // EINTR can be triggered by signals such as SIGWINCH.
    let code: pid_t = handle_eintr_errno!(unsafe { waitpid(pid, &mut status, 0) });
    // Safe because references are not used and the return code is checked.
    // This should only happen if the child process is ptraced.
    if WIFSTOPPED(status) && unsafe { kill(-pid, SIGKILL) } != 0 {
        error!("kill failed: {}", io::Error::last_os_error());
    }
    COMMAND_RUNNING_PID.store(-1, Ordering::Release);
    if code != pid {
        error!("waitpid failed: {}", io::Error::last_os_error());
        return Err(());
    }
    match status {
        0 => Ok(()),
        _ => Err(()),
    }
}

// Execute the specific command. This should be called in a child process.
fn dispatch_cmd(dispatcher: &Dispatcher, args: Vec<String>) {
    std::process::exit(match args.get(0).map(|s| &**s) {
        Some("help") => {
            let mut ret: i32 = 0;
            if args.len() == 2 {
                let list: [&str; 1] = [&args[1]];
                if dispatcher.help_string(&mut stdout(), Some(&list)).is_err() {
                    eprintln!("help: unknown command '{}'", &args[1]);
                    ret = 1;
                }
            } else {
                if args.len() > 1 {
                    eprintln!("ERROR: too many arguments");
                    ret = 1;
                }
                let list = ["help", "help_advanced", "ping", "top"];
                if dispatcher.help_string(&mut stdout(), Some(&list)).is_err() {
                    panic!();
                }
            }
            ret
        }
        Some("help_advanced") => {
            if args.len() > 1 {
                eprintln!("ERROR: too many arguments");
                1
            } else {
                if dispatcher.help_string(&mut stdout(), None).is_err() {
                    panic!();
                }
                0
            }
        }
        _ => match dispatcher.handle_command(args) {
            Ok(_) => 0,
            Err(e) => {
                error!("ERROR: {}", e);
                1
            }
        },
    });
}

// Handle Ctrl-c/SIGINT by sending a SIGINT to any running child process.
extern "C" fn sigint_handler(_: c_int) {
    let mut command_pid: i32 = COMMAND_RUNNING_PID.load(Ordering::Acquire);
    if command_pid >= 0 {
        let _ = stdout().flush();
        // Safe because command_pid belongs to a child process.
        if unsafe { kill(command_pid, SIGINT) } != 0 {
            let bytes = "kill failed.".as_bytes();
            // Safe because the length is checked and it is ok if it fails.
            unsafe { libc::write(STDERR_FILENO, bytes.as_ptr() as *const c_void, bytes.len()) };
        } else {
            command_pid = -1;
        }
    }
    COMMAND_RUNNING_PID.store(command_pid, Ordering::Release);
}

fn register_signal_handlers() {
    // Safe because sigint_handler is async-signal-safe.
    unsafe { util::set_signal_handlers(&[SIGINT], sigint_handler) };
    if let Err(err) = block_signal(SIGHUP) {
        error!("Failed to block SIGHUP: {}", err);
    }
}

fn clear_signal_handlers() {
    util::clear_signal_handlers(&[SIGINT]);
    if let Err(err) = unblock_signal(SIGHUP) {
        error!("Failed to unblock SIGHUP: {}", err);
    }
}

// Loop for getting each command from the user and dispatching it to the handler.
fn input_loop(dispatcher: Dispatcher) {
    let history_path = match var("HOME") {
        Ok(h) => {
            if h.is_empty() {
                None
            } else {
                Some(PathBuf::from(h).join(HISTORY_FILENAME))
            }
        }
        _ => None,
    };

    let helper = ReadLineHelper { dispatcher };

    let mut builder = Config::builder()
        .auto_add_history(true)
        .history_ignore_dups(true)
        .history_ignore_space(true)
        .completion_type(CompletionType::List);
    builder.set_max_history_size(4096);

    let config = builder.build();
    let mut editor = Editor::<ReadLineHelper>::with_config(config);
    editor.set_helper(Some(helper));

    if let Some(h) = history_path.as_ref() {
        match editor.load_history(h) {
            Ok(()) => {}
            Err(ReadlineError::Io(e)) => {
                if e.kind() != io::ErrorKind::NotFound {
                    error!("Error loading history: {}", e);
                }
            }
            Err(e) => {
                error!("Error loading history: {}", e);
            }
        }
    }

    let mut buffer = Vec::new();
    loop {
        let prompt = if buffer.is_empty() { "crosh" } else { "" };
        match editor.readline(&format!("\x1b[1;33m{}>\x1b[0m ", prompt)) {
            Ok(line) => {
                if line.ends_with('\\') {
                    buffer.push(line);
                    continue;
                }

                buffer.push(line);
                let tokens = match shell_words::split(&buffer.join("\n")) {
                    Ok(v) => v,
                    Err(shell_words::ParseError) => {
                        continue;
                    }
                };
                buffer.clear();

                if tokens.is_empty() {
                    continue;
                }
                if tokens[0] == "exit" || tokens[0] == "quit" {
                    break;
                }
                let _ = handle_cmd(editor.helper().unwrap().dispatcher(), tokens);
                if let Some(h) = history_path.as_ref() {
                    if let Err(e) = editor.save_history(h) {
                        error!("Error persisting history: {}", e);
                    }
                }
            }
            Err(ReadlineError::Interrupted) => {
                buffer.clear();
            }
            Err(ReadlineError::Io(ioe)) if ioe.kind() == std::io::ErrorKind::Interrupted => {
                buffer.clear();
            }
            Err(ReadlineError::Eof) => {
                break;
            }
            Err(err) => {
                error!("ReadLine error: {}", err);
                break;
            }
        }
    }
}

fn main() -> Result<(), ()> {
    install_memfd_handler();
    let mut args = std::env::args();

    if let Err(e) = syslog::init(IDENT.to_string(), true /* log_to_stderr */) {
        eprintln!("failed to initialize syslog: {}", e);
        return Err(());
    }

    if args.next().is_none() {
        error!("expected executable name.");
        return Err(());
    }

    let mut args_as_command = false;

    let mut command_args: Vec<String> = Vec::new();

    util::set_dev_commands_included(is_dev_mode().unwrap_or_else(|_| {
        error!("Could not locate 'crossystem'; assuming devmode is off.");
        false
    }));

    util::set_usb_commands_included(util::is_removable().unwrap_or_else(|_| {
        error!("Could not query filesystem; assuming not removable.");
        false
    }));

    for arg in args {
        if args_as_command {
            command_args.push(arg)
        } else {
            match arg.as_ref() {
                "--help" | "-h" => {
                    usage(false);
                    return Ok(());
                }
                "--dev" | "--dev=true" => {
                    util::set_dev_commands_included(true);
                }
                "--dev=false" => {
                    util::set_dev_commands_included(false);
                }
                "--removable" | "--usb" => {
                    util::set_usb_commands_included(true);
                }
                "--" => {
                    args_as_command = true;
                }
                _ => {
                    usage(true);
                    return Err(());
                }
            }
        }
    }

    let dispatcher = setup_dispatcher();

    if args_as_command {
        dispatch_cmd(
            &dispatcher,
            command_args.iter().map(|a| a.to_string()).collect(),
        );
        Ok(())
    } else {
        register_signal_handlers();

        intro();

        input_loop(dispatcher);
        Ok(())
    }
}

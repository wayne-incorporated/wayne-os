# Crosh -- The ChromiumOS shell

[TOC]

This is the homepage/documentation for the crosh, the ChromiumOS shell.
If you're on a CrOS devices right now, you should be able to launch crosh
by hitting Ctrl+Alt+T.  If you aren't on CrOS, then most likely that won't
do anything useful :).

# For Users

Just run `help` to get info about available commands and discover more.

You can also use tab completion to quickly find existing commands.

It's an adventure!

# For ChromiumOS Developers

This section is meant for people hacking on ChromiumOS, especially when they
need to modify/extend crosh.

## Security Warning

Please do not install new modules without full security review.  Any insecure
code that crosh loads will be directly available to people in verified mode.
That's an easy attack vector to run arbitrary code and mess with the user's
state.  We don't want to undermine the security of CrOS!

If you are looking for reviewers, look at the [OWNERS](./OWNERS) file.

## Where Files Live

Crosh is being migrated from shell to Rust. Crosh starts executing from
[src/main.rs](src/main.rs) but many commands are implemented as their own
submodule of one of the high level modules (e.g. `base` or `dev`).

The old [`crosh`](./crosh) script contains the legacy implementations of
commands that haven't been ported to Rust yet.  It is installed on the device
as `crosh.sh`.

### Source Repos

Modules that are specific to a board, or heavily specific to a package, should
generally live with that board and/or package.  For functions that are always
available on all CrOS devices, that code should be kept in this repo.

If you're unsure, just ask on chromium-os-dev@chromium.org.

## Adding New Commands

> **Note**: All new commands must be implemented in Rust.  No new commands may
> be implemented in the legacy shell crosh code.

First determine what implementation strategy the new command will use. When
selecting a strategy, it helps to know what permissions and privileges are
needed. With the strategy in mind, check out the various examples below.

### Command Design

The crosh shell runs in the same environment as the browser (same user/group,
same Linux namespaces, etc...).  So any tools you run in crosh, or information
you try to acquire, must be accessible to the `chronos` user.

However, we rarely want crosh to actually execute tools directly.  Instead,
you should add D-Bus callbacks to the [debugd] daemon and send all requests to
it.  We can better control access in debugd and lock tools down.  Then the
only logic that exists in crosh is a D-Bus IPC call and then displays output
from those programs.  Discussion of debugd is out of scope here, so check out
the [debugd] directory instead.

### Examples

Example implementations:
*   D-Bus method wrapper (debugd): [base::verify_ro]\
    Use this when a D-Bus API is already planned or crosh lacks the needed
    permissions or capabilities.
*   External binary wrapper: [base::ccd_pass]\
    Use this when there is already a command line tool that implements the
    command that works when run as chronos with the capabilities of crosh.
*   Command written in Rust: [base::arc]\
    This is best suited for cases where extra capabilities are not needed and
    having a separate command line tool is not justified.

A sample workflow is included below for writing a new command.

#### Module Setup

Pick an appropriate module for the command to belong to. For dev mode commands
this will be `dev`, most other commands will belong in `base`. This example will
use `base` as the module, but the same steps should still apply in other cases.

Then pick a command name, create a sub module with that name, and register it
with the parent module. For this example the command is `verify_ro`, so the new
source file is `src/base/verify_ro.rs` and two lines need to be added to
`src/base/mod.rs`:

First, the submodule needs to be imported:

```rust
mod verify_ro;
```

Second the register function (to be created below) needs to be called by the
register function in the parent module `src/base/mod.rs`:

```rust
pub fn register(dispatcher: &mut Dispatcher) {
    ...
    verify_ro::register(dispatcher);
    ...
}
```

Now the `src/base/verify_ro.rs` source file is ready to be written. Start with
this minimal source file and verify that crosh compiles with `cargo build`:

```rust
use crate::dispatcher::{self, Arguments, Command, Dispatcher};

pub fn register(dispatcher: &mut Dispatcher) {
    dispatcher.register_command(
        Command::new(
            "verify_ro".to_string(),
            "TODO put usage here".to_string(),
            "TODO put description here".to_string(),
        )
        .set_command_callback(Some(execute_verify_ro)),
    );
}

fn execute_verify_ro(_cmd: &Command, _args: &Arguments) -> Result<(), dispatcher::Error> {
    unimplemented!();
}
```

#### Command Implementation

This assumes the above instructions are already complete.

Since privileged operations cannot be executed by Crosh (but should be
implemented in [debugd] or wherever else), the example below focuses on D-Bus
in particular and assumes there is an existing D-Bus method that needs to be
called from a new Crosh command.

Note that
[debugd's D-Bus interface](/debugd/dbus_bindings/org.chromium.debugd.xml)
already has Rust bindings generated through dev-rust/system_api, so the
bindings and D-Bus connection can be imported with:

```rust
use dbus::blocking::Connection;
use system_api::client::OrgChromiumDebugd;
```

If you want to browse the source code of the generated bindings, after running
build_packages, take a look at the following path:

```sh
/build/${BOARD}/usr/lib/cros_rust_registry/registry/system_api-*/src/bindings/client/
```

Inside the command implementation a D-Bus connection needs to be initialized.
A blocking connection is used in this example.

```rust
let connection = Connection::new_system().map_err(|err| {
    error!("ERROR: Failed to get D-Bus connection: {}", err);
    dispatcher::Error::CommandReturnedError
})?;
```

The bus connection can then be used to get an interface to the desired service,
which is debugd in this case:

```rust
let conn_path = connection.with_proxy(
    "org.chromium.debugd",
    "/org/chromium/debugd",
    DEFAULT_DBUS_TIMEOUT,
);
```

The rest of the method call uses the fact that the imported trait
`system_api::client::OrgChromiumDebugd` is implemented for `conn_path` so the
member functions that map to D-Bus methods can be called from `conn_path`. For
example:


```rust
conn_path
    .update_and_verify_fwon_usb_stop(handle)
    .map_err(|err| {
        println!("ERROR: Got unexpected result: {}", err);
        dispatcher::Error::CommandReturnedError
    })?;
```

This covers the basics. If you look at the actual source code for
[base::verify_ro], it provides a more complicated example with a start method
call, a watcher, and a stop method call.

### Command Help

The default help strings are populated using the command name, usage string,
description string, and any options or flags that are registered through the
dispatcher API.

Alternatively, a help callback can be set when registering the command to
perform custom logic like invoking the help option of a binary. For example:

```rust
const EXECUTABLE: &str = "/usr/bin/vmc";

pub fn register(dispatcher: &mut Dispatcher) {
    dispatcher.register_command(
        Command::new("vmc".to_string(), "".to_string(), "".to_string())
            .set_command_callback(Some(execute_vmc))
            .set_help_callback(vmc_help),
    );
}

fn vmc_help(_cmd: &Command, w: &mut dyn Write, _level: usize) {
    let mut sub = process::Command::new(EXECUTABLE)
        .arg("--help")
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    if copy(&mut sub.stdout.take().unwrap(), w).is_err() {
        panic!();
    }

    if sub.wait().is_err() {
        panic!();
    }
}
```

## Deprecating Commands

If you want to replace a crosh command with some other UI (like a chrome://
page), and you want to deprecate the command gracefully by leaving behind a
friendly note if people try to use it, here's the form.

```sh
# Set the vars to pass the unittests ...
USAGE_storage_status=''
HELP_storage_status=''
# ... then unset them to hide the command from "help" output.
unset USAGE_storage_status HELP_storage_status
cmd_storage_status() (
  # TODO: Delete this after the R## release branch.
  echo "Removed. See storage_info section in chrome://system"
)
```

Make sure you add the TODO comment so people know in the future when it's OK
to clean it up.

## Testing

### Iterative Development

You can run `./crosh` on your desktop system to get a sample shell.  You can
quickly test basic interactions (like argument parsing) here, or check the
help output.  You won't have access to the CrOS services that many crosh
commands expect to talk to (via D-Bus), so those commands will fail.

If you want to load dev mode modules, you can use `./crosh --dev`.  It will
only load local modules ([`./dev.d/`](./dev.d/)), so if your module lives
elsewhere, you can copy it here temporarily.

Similarly, if you want to load removable device modules, you can use
`./crosh --removable`.

### Unittests

To run the unit tests either call `cargo test --workspace` in the crosh folder
or run `emege-${BOARD} crosh && FEATURES=test emerge-${BOARD}`

The [`./run_tests.sh`](./run_tests.sh) legacy unittest runner performs a bunch
of basic style and soundness checks.  Run it against any changes to the shell
code!

# Future Work

Anyone should feel free to pick up these ideas and try to implement them :).

* Move any remaining commands that are implemented in place to debugd calls
  so they can be done over D-Bus.
* Run crosh itself in a restricted sandbox (namespaces/seccomp/etc...).
  Once all commands are done via IPC, there's no need to keep privs.
  Might make it dependent upon dev mode though so we don't break `shell`.
* Migrate additional legacy shell commands over to Rust. This can also be done
  at the same time as migrating a command over to debugd.

# Legacy Crosh Documentation

> **Note**: All new commands must be implemented in Rust.  No new commands may
> be implemented in the legacy shell crosh code.

Crosh was originally written in shell. At the time of writing many of the
commands are still remain in shell and have yet to be ported over to the Rust
crosh. This documentation is kept here for the maintenance of these commands.

## Command API

For every command, you define two variables and one function.  There is no
need to register the new commands anywhere as crosh will inspect its own
runtime environment to discover them.

Here's how you would register a new `foo` command.
```sh
# A short description of arguments that this command accepts.
USAGE_foo='<some args>'
HELP_foo='
  Extended description of this command.
'
# Not required, but lets crosh detect if the foo program is available in the
# current system (e.g. the package is not installed on all devices).  If it
# isn't available, crosh will automatically display an error message and never
# call cmd_foo.
EXEC_foo='/full/path/to/program'
cmd_foo() (
  # Implementation for the foo command.
  # You should validate $# and "$@" and process them first.
  # For invalid args, call the help function with an error message
  # before returning non-zero.
  ...foo code goes here!...
)
```

See the design section below for more details on what and how to structure
the new command.

### Command Help

If your crosh command simply calls out to an external program to do the
processing, and that program already offers usage details, you probably
don't want to have to duplicate things.  You can handle this scenario by
defining a `help_foo` function that makes the respective call.

```sh
# Set the help string so crosh can discover us automatically.
HELP_foo=''
cmd_foo() (
  ...
)
help_foo() (
  /some/command --help
)
```

Take note that we still set `HELP_foo`.  This is needed so crosh can discover
us automatically and display us in the relevant user facing lists (like the
`help_advanced` command).  We don't need to set `USAGE_foo` though since the
`help_foo` function does that for us.

## Hiding Commands

If a command is not yet ready for "prime time", you might want to have it in
crosh for early testing, but not have it show up in the `help` output where
users can easily discover it (of course, the code is all public, so anyone
reading the actual source can find it).  Here's how you do it.

```sh
# Set the vars to pass the unittests ...
USAGE_vmc=''
HELP_vmc=''
# ... then unset them to hide the command from "help" output.
unset USAGE_vmc HELP_vmc
cmd_vmc() (
  ...
)
```

[base::verify_ro]: src/base/verify_ro.rs
[base::arc]: src/base/arc.rs
[base::ccd_pass]: src/base/ccd_pass.rs
[debugd]: /debugd/

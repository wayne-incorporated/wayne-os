// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Provides support for registering and handling commands as well as displaying the command line
// help.

use std::collections::HashMap;
use std::fmt::{self, Display};
use std::io::{stdout, Write};
use std::process::Child;

use remain::sorted;

const INDENT: &str = "  ";

#[derive(Debug)]
#[sorted]
pub enum Error {
    CommandInvalidArguments(String),
    CommandNotFound(String),
    CommandNotImplemented(String),
    CommandReturnedError,
    DuplicateCommand(Vec<String>),
    FlagFilter,
}

impl Display for Error {
    #[remain::check]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        #[sorted]
        match self {
            CommandInvalidArguments(msg) => write!(f, "invalid arguments: {}", msg),
            CommandNotFound(command) => write!(f, "unknown command: {}", command),
            CommandNotImplemented(command) => write!(f, "command not implemented: {}", command),
            CommandReturnedError => write!(f, "command failed"),
            DuplicateCommand(dups) => write!(f, "duplicate commands: {}", dups.join(", ")),
            FlagFilter => write!(f, "error filtering flags"),
        }
    }
}

pub fn wait_for_result(mut child: Child) -> Result<(), Error> {
    match child.wait() {
        Ok(status) => {
            if status.success() {
                Ok(())
            } else {
                Err(Error::CommandReturnedError)
            }
        }
        Err(_) => Err(Error::CommandReturnedError),
    }
}

// Keeps all the state required to interpret a dispatched command, and provides interfaces for:
// * Registering commands (along with strings required to generate help text).
// * Dispatching an issued command.
// * Providing token completion given partial input.
pub struct Dispatcher {
    registered_commands: Vec<Command>,
}

impl Dispatcher {
    pub fn new() -> Dispatcher {
        Dispatcher {
            registered_commands: Vec::new(),
        }
    }

    // Register a command description that can be handled by the dispatcher.
    pub fn register_command(&mut self, cmd: Command) -> &mut Dispatcher {
        self.registered_commands.push(cmd);
        self
    }

    // Lookup a command by name.
    pub fn find_by_name(&self, name: &str) -> Option<&Command> {
        find_by_name(name, &self.registered_commands)
    }

    // Return a CompletionResult that represents auto-completion suggestions for |tokens|.
    pub fn complete_command(&self, tokens: Vec<String>) -> CompletionResult {
        if tokens.is_empty() {
            return complete_by_name("", &self.registered_commands);
        }

        let (commands, entry) = self.get_command_list(tokens);

        if commands.is_empty() {
            if entry.tokens.len() == 1 {
                return complete_by_name(&entry.tokens[0], &self.registered_commands);
            }
            return CompletionResult::NoMatches;
        }

        let command: &Command = commands.last().unwrap();
        if let Some(cb) = command.completion_callback {
            return (cb)(&entry);
        }

        CompletionResult::NoMatches
    }

    // Execute the command handler represented by |tokens|. Flags will be parsed and flag handling
    // callbacks will be invoked.
    pub fn handle_command(&self, tokens: Vec<String>) -> Result<(), Error> {
        if tokens.is_empty() {
            return Err(Error::CommandNotFound(tokens.join(" ")));
        }

        let mut command: &Command = self
            .find_by_name(&tokens[0])
            .ok_or_else(|| Error::CommandNotFound(tokens[0].to_string()))?;

        let mut flag_callbacks: Vec<CommandCallback> = Vec::new();
        let entry = &mut Arguments {
            tokens,
            position: 1,
            flags: HashMap::new(),
        };

        if let Some(cb) = command.flag_callback {
            flag_callbacks.push(cb);
        }
        while entry.position < entry.tokens.len() {
            let sub: Option<&Command> = command.handle_tokens(entry);

            if sub.is_none() {
                break;
            }
            entry.position += 1;
            command = sub.unwrap();
            if let Some(cb) = command.flag_callback {
                flag_callbacks.push(cb);
            }
        }
        if command.command_callback.is_none() {
            return Err(Error::CommandNotImplemented(entry.get_command().join(" ")));
        }

        for cb in flag_callbacks {
            (cb)(command, entry)?;
        }
        (command.command_callback.unwrap())(command, entry)
    }

    pub fn validate(&mut self) -> Result<(), Error> {
        self.registered_commands
            .sort_unstable_by(|a: &Command, b: &Command| a.name.cmp(&b.name));

        let mut duplicates: Vec<String> = Vec::new();
        for i in 1..self.registered_commands.len() {
            let name = &self.registered_commands[i - 1].name;
            if name == &self.registered_commands[i].name {
                duplicates.push(name.to_string());
            }
        }

        if !duplicates.is_empty() {
            return Err(Error::DuplicateCommand(duplicates));
        }
        Ok(())
    }

    // Generate and return the help string.
    pub fn help_string(&self, w: &mut dyn Write, opt_cmds: Option<&[&str]>) -> Result<(), Error> {
        match opt_cmds {
            Some(cmds) => {
                for name in cmds {
                    if let Some(cmd) = self.find_by_name(name) {
                        cmd.append_help_string(w, 0);
                    } else {
                        return Err(Error::CommandNotFound(name.to_string()));
                    }
                }
            }
            None => {
                for c in &self.registered_commands {
                    c.append_help_string(w, 0);
                }
            }
        }
        Ok(())
    }

    fn get_command_list(&self, tokens: Vec<String>) -> (Vec<&Command>, Arguments) {
        let mut list: Vec<&Command> = Vec::new();
        let mut entry = Arguments::new();
        if tokens.is_empty() {
            return (list, entry);
        }
        entry.tokens = tokens;

        let c = self.find_by_name(&entry.tokens[0]);
        if c.is_none() {
            return (list, entry);
        }

        entry.position = 1;
        let mut command: &Command = c.unwrap();
        list.push(command);
        while entry.position < entry.tokens.len() {
            let sub: Option<&Command> = command.handle_tokens(&mut entry);

            if sub.is_none() {
                break;
            }
            entry.position += 1;
            command = sub.unwrap();
            list.push(command);
        }
        (list, entry)
    }
}

impl Default for Dispatcher {
    fn default() -> Self {
        Dispatcher::new()
    }
}

// Owns the data required to identify the command, and serves as a node in a tree. Sub commands can
// be registered. It contains callbacks for the following:
// * flag/switch processing
// * executing the command
// * providing command completion suggestions.
pub struct Command {
    name: String,
    usage: String,
    description: String,
    sub_commands: Vec<Command>,
    flags: Vec<Flag>,
    flag_callback: Option<CommandCallback>,
    command_callback: Option<CommandCallback>,
    completion_callback: Option<CompletionCallback>,
    help_callback: HelpCallback,
}

impl Command {
    pub fn new(name: String, usage: String, description: String) -> Command {
        Command {
            name,
            usage,
            description,
            sub_commands: Vec::new(),
            flags: Vec::new(),
            flag_callback: None,
            command_callback: None,
            completion_callback: None,
            help_callback: default_help_callback,
        }
    }

    pub fn new_disabled_command(name: String, message: String) -> Command {
        Command::new(name, message, "".to_string())
            .set_command_callback(Some(print_help_command_callback))
            .set_help_callback(disabled_command_help_callback)
    }

    // Set the callback that is executed when this command or a sub command is invoked primarily for
    // the purpose of filtering or handling flags.
    pub fn set_flag_callback(mut self, replacement: Option<CommandCallback>) -> Command {
        self.flag_callback = replacement;
        self
    }

    // Set the callback that is executed when this command invoked directly.
    pub fn set_command_callback(mut self, replacement: Option<CommandCallback>) -> Command {
        self.command_callback = replacement;
        self
    }

    // Set the callback to handle command completion for arguments of this command.
    pub fn set_completion_callback(mut self, replacement: Option<CompletionCallback>) -> Command {
        self.completion_callback = replacement;
        self
    }

    // Set the callback to handle command completion for arguments of this command.
    pub fn set_help_callback(mut self, replacement: HelpCallback) -> Command {
        self.help_callback = replacement;
        self
    }

    pub fn register_subcommand(mut self, cmd: Command) -> Command {
        self.sub_commands.push(cmd);
        self
    }

    pub fn register_flag(mut self, flag: Flag) -> Command {
        self.flags.push(flag);
        self
    }

    pub fn get_name(&self) -> &str {
        &self.name
    }

    pub fn append_help_string(&self, w: &mut dyn Write, level: usize) {
        (self.help_callback)(self, w, level);
    }

    fn find_flag(&self, flag: &str) -> Option<&Flag> {
        self.flags.iter().find(|&f| f.name == flag)
    }

    fn find_subcommand(&self, name: &str) -> Option<&Command> {
        find_by_name(name, &self.sub_commands)
    }

    fn handle_tokens(&self, entry: &mut Arguments) -> Option<&Command> {
        while entry.position < entry.tokens.len() {
            let token = &entry.tokens[entry.position];

            let result = self.find_subcommand(token);
            if result.is_some() {
                return result;
            }

            let mut parts = token.splitn(2, '=');
            let name = parts.next().unwrap().to_string();
            let flag = self.find_flag(&name)?;

            let value = flag.get_default_value().parse(parts.next().unwrap_or(""));
            if value.is_none() {
                panic!();
            }
            entry.flags.insert(name, value.unwrap());

            entry.position += 1;
        }
        None
    }
}

pub fn default_help_callback(cmd: &Command, w: &mut dyn Write, level: usize) {
    let mut prefix = INDENT.repeat(level);
    write!(w, "{}{}", &prefix, &cmd.name).unwrap();
    prefix.push_str(INDENT);
    if !cmd.usage.is_empty() {
        write!(w, " {}", &cmd.usage).unwrap();
    }
    writeln!(w).unwrap();

    if !cmd.description.is_empty() {
        writeln!(w, "{}{}", &prefix, &cmd.description).unwrap();
    }

    if !cmd.flags.is_empty() {
        if !cmd.description.is_empty() {
            writeln!(w).unwrap();
        }
        write!(w, "{}Options:", &prefix).unwrap();
        for flag in &cmd.flags {
            writeln!(w).unwrap();
            flag.append_help_string(w, level + 2);
        }
    }

    if !cmd.sub_commands.is_empty() {
        if !cmd.description.is_empty() || !cmd.flags.is_empty() {
            writeln!(w).unwrap();
        }
        writeln!(w, "{}Subcommands:", &prefix).unwrap();
        for sub in &cmd.sub_commands {
            sub.append_help_string(w, level + 2);
        }
    } else {
        writeln!(w).unwrap();
    }
}

fn disabled_command_help_callback(cmd: &Command, w: &mut dyn Write, level: usize) {
    writeln!(w, "{}{}: {}\n", INDENT.repeat(level), cmd.name, cmd.usage).unwrap();
}

pub fn print_help_command_callback(cmd: &Command, _: &Arguments) -> Result<(), Error> {
    let mut buffer = Vec::<u8>::new();
    (cmd.help_callback)(cmd, &mut buffer, 0);
    stdout().write(&buffer).map(drop).map_err(|err| {
        eprintln!("cmd '{}' help failed with: {}", cmd.name, err);
        Error::CommandReturnedError
    })
}

impl HasName for Command {
    fn get_name(&self) -> &str {
        &self.name
    }
}

pub struct Arguments {
    tokens: Vec<String>,
    position: usize,
    flags: HashMap<String, FlagType>,
}

impl Arguments {
    fn new() -> Arguments {
        Arguments {
            tokens: Vec::new(),
            position: 0,
            flags: HashMap::new(),
        }
    }

    pub fn get_command(&self) -> &[String] {
        &self.tokens[0..self.position]
    }

    pub fn get_tokens(&self) -> &[String] {
        &self.tokens
    }

    pub fn get_flag(&self, flag: &str) -> Option<&FlagType> {
        self.flags.get(flag)
    }

    pub fn get_args(&self) -> &[String] {
        &self.tokens[self.position..]
    }
}

pub enum CompletionResult {
    NoMatches,
    SingleDiff(String),
    WholeTokenList(Vec<String>),
}

type CommandCallback = fn(cmd: &Command, args: &Arguments) -> Result<(), Error>;
type CompletionCallback = fn(args: &Arguments) -> CompletionResult;
type HelpCallback = fn(cmd: &Command, w: &mut dyn Write, level: usize);

pub enum FlagType {
    NoValue,
    Boolean(bool),
    Integer(i64),
    Float(f64),
    String(String),
}

impl FlagType {
    pub fn parse(&self, s: &str) -> Option<FlagType> {
        match self {
            FlagType::NoValue => Some(FlagType::NoValue),
            FlagType::Boolean(_) => match s.parse::<bool>() {
                Ok(b) => Some(FlagType::Boolean(b)),
                Err(_) => None,
            },
            FlagType::Integer(_) => match s.parse::<i64>() {
                Ok(i) => Some(FlagType::Integer(i)),
                Err(_) => None,
            },
            FlagType::Float(_) => match s.parse::<f64>() {
                Ok(f) => Some(FlagType::Float(f)),
                Err(_) => None,
            },
            FlagType::String(_) => Some(FlagType::String(s.to_string())),
        }
    }
}

pub struct Flag {
    name: String,
    description: String,
    default_value: FlagType,
}

impl HasName for Flag {
    fn get_name(&self) -> &str {
        &self.name
    }
}

impl Flag {
    pub fn new(name: String, description: String, default_value: FlagType) -> Flag {
        Flag {
            name,
            description,
            default_value,
        }
    }

    pub fn append_help_string(&self, w: &mut dyn Write, level: usize) {
        let prefix = INDENT.repeat(level);
        write!(w, "{}{}", &prefix, &self.name).unwrap();
        let value_cb = |w: &mut dyn Write, value: String| {
            write!(w, "{}{}{}", &value, &prefix, INDENT).unwrap();
        };
        match &self.default_value {
            FlagType::NoValue => {
                write!(w, " ").unwrap();
            }
            FlagType::Boolean(default) => {
                value_cb(w, format!("=[true|false]  default: {}\n", default));
            }
            FlagType::Integer(default) => {
                value_cb(w, format!("=<int>  default: {}\n", default));
            }
            FlagType::Float(default) => {
                value_cb(w, format!("=<float>  default: {}\n", default));
            }
            FlagType::String(default) => {
                value_cb(w, format!("=<value>  default: {}\n", default));
            }
        }
        writeln!(w, "{}", &self.description).unwrap();
    }

    pub fn get_default_value(&self) -> &FlagType {
        &self.default_value
    }
}

// Internal trait used to share logic used to walk lists of Commands and Flags.
trait HasName {
    fn get_name(&self) -> &str;
}

// Fetch a reference to an entry in a list by matching against get_name().
fn find_by_name<'a, T: HasName>(name: &str, list: &'a [T]) -> Option<&'a T> {
    list.iter().find(|&c| *c.get_name() == *name)
}

// Provide a CompletionResult after prefix matching against get_name().
fn complete_by_name<T: HasName>(name: &str, list: &[T]) -> CompletionResult {
    let mut suggestions: Vec<String> = Vec::new();
    for c in list {
        if c.get_name().starts_with(name) {
            suggestions.push(c.get_name().to_string());
        }
    }
    if suggestions.is_empty() {
        CompletionResult::NoMatches
    } else if suggestions.len() == 1 {
        CompletionResult::SingleDiff(suggestions[0][name.len()..].to_string())
    } else {
        CompletionResult::WholeTokenList(suggestions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::str;

    static PARENT_COMMAND_NAME: &str = "test";
    static CHILD_COMMAND_NAME: &str = "subtest";

    fn flag_callback(_cmd: &Command, _args: &Arguments) -> Result<(), Error> {
        Ok(())
    }

    fn false_flag_callback(_cmd: &Command, _args: &Arguments) -> Result<(), Error> {
        Err(Error::FlagFilter)
    }

    fn panic_flag_callback(_cmd: &Command, _args: &Arguments) -> Result<(), Error> {
        panic!()
    }

    fn command_callback(_cmd: &Command, _args: &Arguments) -> Result<(), Error> {
        Ok(())
    }

    fn panic_command_callback(_cmd: &Command, _args: &Arguments) -> Result<(), Error> {
        panic!()
    }

    fn panic_completion_callback(_args: &Arguments) -> CompletionResult {
        panic!()
    }

    fn default_dispatcher(parent: Command) -> Dispatcher {
        let mut dispatcher = Dispatcher::new();
        dispatcher.register_command(parent);
        dispatcher
    }

    fn default_command(name: String, usage: String, description: String) -> Command {
        Command::new(name, usage, description)
            .set_flag_callback(Some(panic_flag_callback))
            .set_command_callback(Some(panic_command_callback))
            .set_completion_callback(Some(panic_completion_callback))
    }

    fn default_parent_command(child: Command) -> Command {
        default_command(
            PARENT_COMMAND_NAME.to_string(),
            format!("[{}]", CHILD_COMMAND_NAME),
            "parent test command.".to_string(),
        )
        .register_subcommand(child)
    }

    fn default_child_command() -> Command {
        default_command(
            CHILD_COMMAND_NAME.to_string(),
            "".to_string(),
            "parent test command.".to_string(),
        )
    }

    #[test]
    fn test_handle_command_empty() {
        let dispatcher = default_dispatcher(default_parent_command(default_child_command()));

        assert!(dispatcher.handle_command(Vec::new()).is_err());
    }

    #[test]
    fn test_handle_command_parent() {
        let dispatcher = default_dispatcher(
            default_parent_command(default_child_command().set_flag_callback(Some(flag_callback)))
                .set_flag_callback(Some(flag_callback))
                .set_command_callback(Some(command_callback)),
        );

        let tokens: Vec<String> = vec![PARENT_COMMAND_NAME.to_string()];

        assert!(dispatcher.handle_command(tokens).is_ok());
    }

    #[test]
    fn test_handle_command_child() {
        let dispatcher = default_dispatcher(
            default_parent_command(
                default_child_command()
                    .set_flag_callback(Some(flag_callback))
                    .set_command_callback(Some(command_callback)),
            )
            .set_flag_callback(Some(flag_callback)),
        );

        let tokens: Vec<String> = vec![
            PARENT_COMMAND_NAME.to_string(),
            CHILD_COMMAND_NAME.to_string(),
        ];

        assert!(dispatcher.handle_command(tokens).is_ok());
    }

    #[test]
    fn test_handle_command_false_flag_callback() {
        let dispatcher = default_dispatcher(
            default_parent_command(default_child_command())
                .set_flag_callback(Some(false_flag_callback)),
        );

        let tokens: Vec<String> = vec![
            PARENT_COMMAND_NAME.to_string(),
            CHILD_COMMAND_NAME.to_string(),
        ];

        assert!(dispatcher.handle_command(tokens).is_err());
    }

    #[test]
    fn test_help_string() {
        let dispatcher = default_dispatcher(
            default_command("1".to_string(), "2".to_string(), "3".to_string())
                .register_subcommand(default_command(
                    "4".to_string(),
                    "5".to_string(),
                    "6".to_string(),
                ))
                .register_subcommand(
                    default_command("7".to_string(), "".to_string(), "".to_string())
                        .register_subcommand(
                            default_command("8".to_string(), "9".to_string(), "10".to_string())
                                .register_flag(Flag::new(
                                    "11".to_string(),
                                    "12".to_string(),
                                    FlagType::Integer(0),
                                )),
                        ),
                ),
        );

        let mut result: Vec<u8> = Vec::new();
        assert!(dispatcher
            .help_string(&mut result, Some(&["not a command"]))
            .is_err());
        assert!(dispatcher.help_string(&mut result, None).is_ok());
        assert_eq!(
            str::from_utf8(&result).unwrap(),
            r#"1 2
  3

  Subcommands:
    4 5
      6

    7
      Subcommands:
        8 9
          10

          Options:
            11=<int>  default: 0
              12

"#
        );
    }
}

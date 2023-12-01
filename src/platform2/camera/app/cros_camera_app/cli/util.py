# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""The utilities for parsing command line arguments"""

import argparse
import collections
import enum
import inspect
from typing import (
    Any,
    Callable,
    DefaultDict,
    Dict,
    List,
    NamedTuple,
    Optional,
    Tuple,
    Type,
)


class CLIError(Exception):
    """Failed when processing CLI commands."""


class EnumAction(argparse.Action):
    """Action that converts between the string choices and Enum for argparse."""

    def __init__(
        self,
        option_strings: str,
        dest: str,
        enum_type: Type[enum.Enum],
        **kwargs,
    ):
        """Initializes the instance.

        Args:
            option_strings: The option strings that trigger this action.
            dest: The name of the attribute to hold the selected enum value.
            enum_type: The enum class to use for argument choices.
            **kwargs: Additional keyword arguments to pass to argparse.Action.
        """
        self._enum_type = enum_type
        kwargs["choices"] = [e.name.lower() for e in enum_type]
        super().__init__(option_strings, dest, **kwargs)

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: str,
        option_string=None,
    ):
        """Converts the selected value to an enum and updates the namespace.

        Args:
            parser: The argument parser instance.
            namespace: The namespace to hold the selected enum value.
            values: The selected value as a string.
            option_string: The option string that triggered this action.
        """
        del parser  # unused
        del option_string  # unused
        enum_value = self._enum_type[values.upper()]
        setattr(namespace, self.dest, enum_value)


class Option(NamedTuple):
    """Parameters to build a command line option with add_argument()."""

    args: Tuple[Any, ...]
    kwargs: Dict[str, Any]


class Command(NamedTuple):
    """Parameters to build a command with add_parser()."""

    name: str
    parent: Optional[Callable]
    kwargs: Dict[str, Any]
    children: List[Callable]


Decorator = Callable[[Callable], Callable]


class CLIRunner:
    """Runner to parse command line arguments and dispatch commands."""

    def __init__(self, parser: argparse.ArgumentParser):
        """Initializes the instance.

        Args:
            parser: The main parser to build commands on.
        """
        self._root_parser = parser
        self._root_func: Optional[Callable] = None
        self._parents: Dict[Callable, Optional[Callable]] = {}
        self._commands: Dict[Callable, Command] = {}
        self._options: DefaultDict[
            Callable, List[Option]
        ] = collections.defaultdict(list)
        self._parsers: Dict[Callable, argparse.ArgumentParser] = {}

    def command(
        self, name: str, *, parent: Optional[Callable], **kwargs
    ) -> Decorator:
        """Decorator to register a new command.

        Args:
            name: The command name.
            parent: The parent command group of this command, or None if this
                is the root entry command.
            **kwargs: The keyword arguments to be forwarded to add_parser().
        """

        def decorator(func: Callable):
            self._parents[func] = parent
            self._commands[func] = Command(name, parent, kwargs, [])
            if parent is None:
                if self._root_func is not None:
                    raise CLIError("Duplicated root command")
                self._root_func = func
            else:
                self._commands[parent].children.append(func)
            return func

        return decorator

    def option(self, *args, **kwargs) -> Decorator:
        """Decorator to register an option for the current command.

        Args:
            *args: The arguments to be forwarded to add_argument().
            **kwargs: The keyword arguments to be forwarded to add_parser().
        """

        def decorator(func: Callable):
            self._options[func].append(Option(args, kwargs))
            return func

        return decorator

    def build_parsers(self, parser: argparse.ArgumentParser, func: Callable):
        """Builds parsers by traversing the command tree.

        The built parsers are stored in self._parsers.

        Args:
            parser: The parser of the current command node.
            func: The handler function of the current command node.
        """
        self._parsers[func] = parser

        for opt in self._options[func]:
            parser.add_argument(*opt.args, **opt.kwargs)
        parser.set_defaults(func=func)

        cmd = self._commands[func]
        if cmd.children:
            subparsers = parser.add_subparsers(title="commands")
            for child in cmd.children:
                subcmd = self._commands[child]
                subparser = subparsers.add_parser(subcmd.name, **subcmd.kwargs)
                self.build_parsers(subparser, child)

    def run(self, argv: Optional[List[str]] = None) -> Optional[int]:
        """Parses the arguments and runs the target commands.

        Args:
            argv: The command line arguments.

        Returns:
            An optional return code for sys.exit().
        """
        if self._root_func is None:
            raise CLIError("There should be exactly one root command")
        self.build_parsers(self._root_parser, self._root_func)

        args = self._root_parser.parse_args(argv)

        func = args.func
        cmd = self._commands[func]
        if cmd.children:
            # Print help if it has deeper subcommands not specified by the
            # command line arguments yet.
            self._parsers[func].print_help()
            return

        funcs = []
        while func is not None:
            funcs.append(func)
            func = self._parents[func]

        # Process the command handlers from root to leaf.
        for func in reversed(funcs):
            # Extract the function parameters from parsed arguments.
            params = inspect.signature(func).parameters
            unwrapped_args = {k: getattr(args, k) for k in params}

            # Invoke the handler and return early if there is an error
            # indicated by return code.
            ret = func(**unwrapped_args)
            if ret is not None and ret != 0:
                return ret

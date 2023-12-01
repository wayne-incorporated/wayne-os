# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""This module interacts with Chrome via DevTools Protocol.

It exposes two classes, Chrome and Page, which allow clients to control the
browser and webpage respectively.
"""

import collections
import json
import logging
import queue
from typing import Any, Callable, Dict, List, Optional, Set
import urllib.request

# pylint: disable=import-error
import ws4py.client.threadedclient
import ws4py.messaging


class RPCError(Exception):
    """Chrome DevTools rejected the JSON-RPC call."""


EventHandler = Callable[[Dict[str, Any]], None]


class _JSONWebSocketClient(ws4py.client.threadedclient.WebSocketClient):
    """Exchanges JSON-RPC messages with a Chrome DevTools WebSocket endpoint.

    By inheriting the threaded client from ws4py, the received_message()
    functions would operates on its own thread.
    """

    def __init__(self, *args, **kwargs):
        """Initializes the instance."""
        super().__init__(*args, **kwargs)
        self._pending_results: Dict[int, queue.Queue] = {}
        self._event_handlers: Dict[
            str, List[EventHandler]
        ] = collections.defaultdict(list)

    def on(self, event: str, handler: EventHandler):
        """Registers an event handler.

        Args:
            event: The name of target event.
            handler: The handler function to run when the event occurs.
        """
        self._event_handlers[event].append(handler)

    def received_message(self, msg: ws4py.messaging.Message):
        """Processes a received message from DevTools.

        Args:
            msg: A message in JSON format. It could be either a result of the
                previous issued commands, or an event dispatched from the Chrome
                side.
        """
        res = json.loads(msg.data)

        # TODO(shik): Shorten the log message if the data is very long, such as
        # a base64 encoded blob for screenshot.
        logging.debug(res)

        if "id" not in res:
            # If there is no id field, it should be an event from Chrome side
            # with "method" and "params" field.
            for handler in self._event_handlers.get(res["method"], []):
                handler(res["params"])

            # TODO(shik): Listen to consoleAPICalled events so we can see the
            # logging messages from the JS side.
            return

        self._pending_results[res["id"]].put(res)

    # TODO(shik): Migrate cmd to TypedDict after ChromeOS supports Python 3.8.
    def rpc(self, cmd: Dict[str, Any]) -> Dict[str, Any]:
        """Runs a RPC to DevTools.

        Args:
            cmd: A dict with JSON-RPC payload with id, method, params, and
                optionally sessionId if it's for a specific page.

        Returns:
            The result of the command.

        Raises:
            RPCError: Chrome returns an error response for the command.
        """

        pending_result = queue.Queue(maxsize=1)
        self._pending_results[cmd["id"]] = pending_result
        logging.debug(cmd)
        super().send(json.dumps(cmd))

        # Wait for the result being set in received_message().
        res = pending_result.get()
        self._pending_results.pop(cmd["id"])

        # As standard JSON-RPC, the result should have either `error` or
        # `result` field.
        if "error" in res:
            raise RPCError("code %(code)s: %(message)s" % res["error"])

        return res["result"]


class Chrome:
    """A connection to a running instance of Chrome via the DevTools API.

    This is used to control Chrome remotely using Chrome DevTools Protocol.
    See https://chromedevtools.github.io/devtools-protocol/ for more details.
    """

    @staticmethod
    def _get_json(url: str) -> Any:
        """Gets and deserializes a JSON from the given URL.

        Args:
            url: A string representing the target url.

        Returns:
            The deserialized JSON value.
        """
        with urllib.request.urlopen(url) as res:
            return json.load(res)

    @staticmethod
    def _get_debugging_port() -> int:
        """Gets the remote debugging port for Chrome.

        Returns:
            The remote debugging port.
        """
        # TODO(shik): Add a `setup` subcommand to help setup the required
        # command line flags of Chrome.
        # TODO(shik): Check the command line arguments of Chrome process as
        # well, since the port might be specified directly.
        with open("/home/chronos/DevToolsActivePort", encoding="utf-8") as f:
            return int(f.readline())

    def __init__(self):
        """Initializes the instance and connect to Chrome."""
        port = self._get_debugging_port()
        version = self._get_json(f"http://127.0.0.1:{port}/json/version")
        url = version["webSocketDebuggerUrl"]
        self._alive_sessions: Set[str] = set()
        self._ws = _JSONWebSocketClient(url, exclude_headers=["origin"])
        self._ws.on("Target.attachedToTarget", self.on_attached_to_target)
        self._ws.on("Target.detachedFromTarget", self.on_detached_from_target)
        self._ws.connect()
        self._next_cmd_id = 0

    def on_attached_to_target(self, params: Dict):
        """Handler for Target.attachToTarget event.

        Args:
            params: A dictionary with sessionId and targetInfo.
        """
        self._alive_sessions.add(params["sessionId"])

    def on_detached_from_target(self, params: Dict):
        """Handler for Target.detachedFromTarget event.

        Args:
            params: A dictionary with sessionId.
        """
        self._alive_sessions.remove(params["sessionId"])

    def is_session_alive(self, session_id: str) -> bool:
        """Checks whether a session is still alive.

        Args:
            session_id: The id of the session.

        Returns:
            Whether the session is alive.
        """
        return session_id in self._alive_sessions

    def rpc(
        self,
        method: str,
        params: Dict[str, Any],
        *,
        session_id: Optional[str] = None,
    ) -> Any:
        """Invokes a RPC to Chrome.

        Args:
            method: A string representing the name of the method to be invoked.
            params: A dict to be passed as parameters to the defined method.
            session_id: An optional string representing the session id of a
            specific target. If it's None, the RPC is targeting the main
            browser session.

        Returns:
            The result of the RPC got from the Chrome side.
        """
        cmd_id = self._next_cmd_id
        self._next_cmd_id += 1

        payload = {"id": cmd_id, "method": method, "params": params}
        if session_id is not None:
            payload["sessionId"] = session_id
        return self._ws.rpc(payload)

    def find_target(self, url_prefix: str) -> Optional[str]:
        """Finds a target with the given URL prefix.

        Args:
            url_prefix: A string representing the target URL prefix.

        Returns:
            The target id, or None if there is no matching target. If there are
            multiple matches, the returned id could be anyone of them.
        """
        res = self.rpc("Target.getTargets", {})
        for t in res["targetInfos"]:
            if t["url"].startswith(url_prefix):
                return t["targetId"]
        return None

    def close_targets(self, url_prefix: str) -> int:
        """Closes all targets with the given URL prefix.

        Args:
            url_prefix: A string representing the target URL prefix.

        Returns:
            The number of closed targets.
        """
        res = self.rpc("Target.getTargets", {})
        to_close_ids = [
            t["targetId"]
            for t in res["targetInfos"]
            if t["url"].startswith(url_prefix)
        ]
        for target_id in to_close_ids:
            self.rpc("Target.closeTarget", {"targetId": target_id})
        return len(to_close_ids)

    def _attach_to_target(self, target_id: str) -> "Page":
        """Attaches to the page with the given target id.

        Args:
            target_id: The id of target to be attached.

        Returns:
            A Page instance that can be used to control the page remotely.
        """
        res = self.rpc(
            "Target.attachToTarget",
            {
                "targetId": target_id,
                "flatten": True,
            },
        )
        return Page(chrome=self, session_id=res["sessionId"])

    def try_attach(self, url: str) -> Optional["Page"]:
        """Tries to attach to the page with the given URL if it exists.

        Attaches to any page that matches the given url by prefix. If there are
        multiple matches, attach to one of them. If there is no match, returns
        None.

        Args:
            url: A string representing the target page url.

        Returns:
            A Page instance that can be used to control the page remotely, or
            None if there is no page matches the given url.
        """
        target_id = self.find_target(url)
        if target_id is None:
            return None

        return self._attach_to_target(target_id)

    def attach(self, url: str) -> "Page":
        """Attaches to the page with the given URL.

        Attaches to any page that matches the given url by prefix. If there are
        multiple matches, attach to one of them. If there is no match, this
        function will automatically create a new page.

        Args:
            url: A string representing the target page url.

        Returns:
            A Page instance that can be used to control the page remotely.
        """
        target_id = self.find_target(url)
        if target_id is None:
            res = self.rpc("Target.createTarget", {"url": url})
            target_id = res["targetId"]

        return self._attach_to_target(target_id)


class JSError(Exception):
    """A error occurred when evaluating JavaScript code in Chrome."""

    @staticmethod
    def _get_exception_message(ex: Dict[str, Any]) -> str:
        """Builds a human-friendly message from the given JavaScript exception.

        The exception might have different shapes for different kinds of
        exceptions. The imeplmentation is largely based on the
        getExceptionMessage() in Puppeteer library from Chrome team:
        https://github.com/puppeteer/puppeteer/blob/2922611f5e6a3b2eab2981a5bb6608e7f4610d9f/packages/puppeteer-core/src/common/util.ts#L43

        Args:
            ex: A dict representing a JavaScript exception. See
                https://chromedevtools.github.io/devtools-protocol/1-2/Runtime/#type-ExceptionDetails
                for the definition.

        Returns:
            A human-friendly message built from the exception.
        """
        desc = ex.get("exception", {}).get("description")
        if desc is not None:
            return desc

        value = ex.get("exception", {}).get("value")
        if value is not None:
            return value

        lines = [ex["text"]]
        stack_trace = ex.get("stackTrace")
        if stack_trace is not None:
            for frame in stack_trace["callFrames"]:
                location = "%(url)s:%(lineNumber)d:%(columnNumber)d" % frame
                line = f"    at {frame.functionName} ({location})"
                lines.append(line)
        return "\n".join(lines)

    def __init__(self, ex):
        """Initializes an instance."""
        msg = self._get_exception_message(ex)
        super().__init__(msg)


class Page:
    """A connection to a page attached by DevTools."""

    def __init__(self, *, chrome: Chrome, session_id: str):
        """Initializes a instance and makes it ready to be controlled.

        Args:
            chrome: The Chrome instance that is running this page.
            session_id: The session id for controlling this page.
        """
        self.chrome = chrome
        self.session_id = session_id

        # Make the page less restrictive to run arbitrary JS code.
        self.rpc("Page.setBypassCSP", {"enabled": True})
        self.rpc("Runtime.enable", {})

    @property
    def is_alive(self) -> bool:
        """Whether the attached page session is alive."""
        return self.chrome.is_session_alive(self.session_id)

    def rpc(self, method: str, params: Dict[str, Any]) -> Any:
        """Invokes a RPC to Chrome on this page.

        Args:
            method: A string representing the name of the method to be invoked.
            params: A dict to be passed as parameters to the defined method.

        Returns:
            The result of the RPC got from the Chrome side.
        """
        return self.chrome.rpc(method, params, session_id=self.session_id)

    def eval(self, expr: str) -> Any:
        """Evaluates the JavaScript expression on this page.

        Args:
            expr: A JavaScript expression.

        Returns:
            The evaluated result. If it's a promise, the result would be
            automatically awaited.
        """
        res = self.rpc(
            "Runtime.evaluate",
            {
                "expression": expr,
                "returnByValue": True,
                "awaitPromise": True,
                "allowUnsafeEvalBlockedByCSP": True,
            },
        )
        ex = res.get("exceptionDetails")
        if ex is not None:
            raise JSError(ex)

        return res["result"].get("value")

    def call(self, fn_expr: str, *args) -> Any:
        """Calls the JavaScript function with provided arguments.

        Args:
            fn_expr: A function expression that to be called on.
            *args: The arguments to be passed to the function. All values
                should be JSON-serializable.

        Returns:
            The evaluated function call result. If it's a promise, the result
            would be automatically awaited.
        """

        # Technically, this could be implemented by Runtime.callFunctionOn RPC
        # method to be more semantically correct without the string
        # concatenation here, but Runtime.callFunctionOn requires passing the
        # receiver explicitly, which is a less user-friendly API.

        args_expr = ", ".join(json.dumps(a) for a in args)

        # Note that the parentheses will NOT change the value of "this" for
        # function invocation, because group operator will not apply GetValue
        # operation to the result of evaluating expression. See
        # https://262.ecma-international.org/13.0/#sec-function-calls and
        # https://262.ecma-international.org/13.0/#sec-grouping-operator for
        # more details.
        full_expr = f"({fn_expr})({args_expr})"

        return self.eval(full_expr)

"""Asynchronous helpers for managing a long-lived GDB process.

The :class:`GDBSession` class hides the messy parts of spawning GDB, feeding
commands through its machine interface (MI2), and collecting console output or
structured results.  It is intentionally conservative: commands are executed
serially, timeouts are enforced, and all subprocess interaction happens via
``asyncio`` primitives so the server can stay responsive.

Only a – very small – subset of the MI grammar is required for the current MCP
server use-cases, but the parser below is able to handle nested dictionaries
and lists which is enough for most common GDB commands (breakpoints, register
inspection, stepping, etc.).  Whenever the parser encounters constructs it does
not fully understand it gracefully falls back to returning the raw text.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import shlex
from asyncio.subprocess import Process
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, MutableMapping, Optional

_LOGGER = logging.getLogger(__name__)

_PROMPT = b"(gdb) "
_DEFAULT_TIMEOUT = 15.0
_SUCCESS_RESULT_CLASSES = {"done", "running", "connected", "exit"}
_ERROR_RESULT_CLASSES = {"error"}


class GDBSessionError(RuntimeError):
    """Base error for the GDB session wrapper."""


class GDBSessionNotRunning(GDBSessionError):
    """Raised when an operation requires a running session but none exists."""


class GDBSessionAlreadyRunning(GDBSessionError):
    """Raised when attempting to start a session while one is already running."""


class GDBCommandTimeout(GDBSessionError):
    """Raised when GDB takes too long to respond."""


class GDBTerminatedUnexpectedly(GDBSessionError):
    """Raised when the underlying GDB process exits mid-command."""


@dataclass(slots=True)
class GDBCommandResult:
    """Structured response for a single GDB command execution."""

    command: str
    success: bool
    result_class: Optional[str]
    console_output: str
    result_payload: Optional[Dict[str, Any]] = None
    async_records: List[str] = field(default_factory=list)
    stderr_output: str = ""
    raw_response: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable dictionary representation."""

        return {
            "command": self.command,
            "success": self.success,
            "result_class": self.result_class,
            "console_output": self.console_output,
            "result_payload": self.result_payload,
            "async_records": list(self.async_records),
            "stderr_output": self.stderr_output,
            "raw_response": self.raw_response,
        }


class GDBSession:
    """Manage a single background GDB process through its MI interface."""

    def __init__(
        self,
        gdb_path: str = "gdb",
        *,
        default_cwd: Optional[str] = None,
        startup_commands: Optional[List[str]] = None,
    ) -> None:
        self._gdb_path = gdb_path
        self._default_cwd = default_cwd
        self._startup_commands = list(startup_commands or [
            "set confirm off",
            "set pagination off",
        ])
        self._process: Optional[Process] = None
        self._stderr_task: Optional[asyncio.Task[None]] = None
        self._stderr_queue: asyncio.Queue[str] = asyncio.Queue()
        self._command_lock = asyncio.Lock()
        self._last_command: Optional[str] = None

    # ------------------------------------------------------------------
    # lifecycle helpers
    # ------------------------------------------------------------------
    @property
    def last_command(self) -> Optional[str]:
        """Return the last command issued to GDB (if any)."""

        return self._last_command

    def is_running(self) -> bool:
        return self._process is not None and self._process.returncode is None

    async def start(
        self,
        *,
        cwd: Optional[str] = None,
        gdb_args: Optional[List[str]] = None,
        env: Optional[Mapping[str, str]] = None,
        executable: Optional[str] = None,
    ) -> str:
        """Launch a new GDB process (if not already running).

        Args:
            cwd: Working directory for GDB.  Defaults to ``default_cwd``.
            gdb_args: Extra command-line arguments.
            env: Environment overrides.
            executable: Optional path to load immediately via ``file``.
        Returns:
            Initial banner text emitted by GDB (with the prompt stripped).
        """

        if self.is_running():
            raise GDBSessionAlreadyRunning("GDB session is already active")

        cmd = [self._gdb_path, "-q", "--nx", "--interpreter=mi2"]
        if gdb_args:
            cmd.extend(gdb_args)

        resolved_env: Optional[MutableMapping[str, str]] = None
        if env is not None:
            resolved_env = os.environ.copy()
            resolved_env.update(env)

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd or self._default_cwd,
            env=resolved_env,
        )

        self._process = process
        self._stderr_task = asyncio.create_task(self._collect_stderr(process))

        banner = await self._read_until_prompt()
        _LOGGER.debug("GDB banner: %s", banner.strip())

        if executable:
            await self.execute_console(f"file {shlex.quote(executable)}")

        for command in self._startup_commands:
            await self.execute_console(command, timeout=5.0)

        return banner.strip()

    async def stop(self, *, force: bool = False) -> None:
        """Terminate the running GDB process (if any)."""

        if not self.is_running():
            return

        assert self._process is not None

        try:
            if self._process.stdin and not force:
                self._process.stdin.write(b"quit\n")
                await self._process.stdin.drain()
                try:
                    await asyncio.wait_for(self._process.wait(), timeout=3.0)
                except asyncio.TimeoutError:
                    force = True
        finally:
            if force and self._process.returncode is None:
                self._process.kill()
                await self._process.wait()

        if self._stderr_task:
            self._stderr_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._stderr_task

        self._process = None
        self._stderr_task = None

    # ------------------------------------------------------------------
    # command execution helpers
    # ------------------------------------------------------------------
    async def execute_console(
        self,
        command: str,
        *,
        timeout: float = _DEFAULT_TIMEOUT,
    ) -> GDBCommandResult:
        """Execute a regular console command (e.g. ``break main``)."""

        escaped = command.replace("\\", "\\\\").replace("\"", "\\\"")
        mi_command = f'-interpreter-exec console "{escaped}"'
        return await self._execute(mi_command, original=command, timeout=timeout)

    async def execute_mi(
        self,
        command: str,
        *,
        timeout: float = _DEFAULT_TIMEOUT,
    ) -> GDBCommandResult:
        """Execute a raw MI command (must include the leading dash)."""

        return await self._execute(command, original=command, timeout=timeout)

    async def interrupt(self) -> None:
        """Send a Ctrl-C to the running GDB process."""

        if not self.is_running():
            raise GDBSessionNotRunning("Cannot interrupt; no active session")

        assert self._process is not None
        if self._process.stdin is None:
            raise GDBSessionError("GDB stdin is not available")
        self._process.stdin.write(b"\x03")
        await self._process.stdin.drain()

    # ------------------------------------------------------------------
    # private helpers
    # ------------------------------------------------------------------
    async def _execute(
        self,
        mi_command: str,
        *,
        original: str,
        timeout: float,
    ) -> GDBCommandResult:
        if not self.is_running():
            raise GDBSessionNotRunning("Start the session before executing commands")

        assert self._process is not None and self._process.stdin is not None

        async with self._command_lock:
            self._last_command = original
            _LOGGER.debug("Executing command: %s", mi_command)
            self._process.stdin.write(mi_command.encode("utf-8") + b"\n")
            await self._process.stdin.drain()

            try:
                raw = await asyncio.wait_for(self._read_until_prompt(), timeout=timeout)
            except asyncio.TimeoutError as exc:  # pragma: no cover - best effort
                raise GDBCommandTimeout(
                    f"Timed out waiting for GDB to finish command: {original}"
                ) from exc
            except asyncio.IncompleteReadError as exc:  # pragma: no cover - rare
                raise GDBTerminatedUnexpectedly(
                    "GDB exited while processing the command"
                ) from exc

            stderr_output = await self._drain_stderr()

        parsed = _parse_mi_response(raw)
        result_record = parsed.get("result_record")
        console_text = "".join(parsed.get("console", []))
        async_lines = parsed.get("async_records", [])

        result_class = None
        result_payload = None
        success = True
        if result_record is not None:
            result_class = result_record.get("class")
            result_payload = result_record.get("payload")
            if result_class is None:
                success = True
            elif result_class in _SUCCESS_RESULT_CLASSES:
                success = True
            elif result_class in _ERROR_RESULT_CLASSES:
                success = False
            else:
                success = result_class not in _ERROR_RESULT_CLASSES

        return GDBCommandResult(
            command=original,
            success=success,
            result_class=result_class,
            console_output=console_text,
            result_payload=result_payload,
            async_records=async_lines,
            stderr_output=stderr_output,
            raw_response=raw,
        )

    async def _read_until_prompt(self) -> str:
        assert self._process is not None and self._process.stdout is not None
        data = await self._process.stdout.readuntil(_PROMPT)
        text = data.decode("utf-8", errors="replace")
        if text.endswith(_PROMPT.decode("ascii")):
            text = text[: -len(_PROMPT)]
        return text

    async def _collect_stderr(self, process: Process) -> None:
        assert process.stderr is not None
        while True:
            line = await process.stderr.readline()
            if not line:
                break
            await self._stderr_queue.put(line.decode("utf-8", errors="replace"))

    async def _drain_stderr(self) -> str:
        items: List[str] = []
        while not self._stderr_queue.empty():
            try:
                items.append(self._stderr_queue.get_nowait())
            except asyncio.QueueEmpty:  # pragma: no cover - loop guard
                break
        return "".join(items)


# ---------------------------------------------------------------------------
# MI response parsing helpers
# ---------------------------------------------------------------------------

import string

_IDENTIFIER_CHARS = set(string.ascii_letters + string.digits + "_-.")


def _parse_mi_response(raw: str) -> Dict[str, Any]:
    """Lightweight parser for a block of MI output.

    The return value has the following (narrow) structure::

        {
            "result_record": {"class": str, "payload": dict | None} | None,
            "console": [str, ...],
            "log": [str, ...],
            "target": [str, ...],
            "async_records": [str, ...],
            "other": [str, ...],
        }
    """

    parsed: Dict[str, Any] = {
        "result_record": None,
        "console": [],
        "log": [],
        "target": [],
        "async_records": [],
        "other": [],
    }

    for raw_line in raw.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        prefix = line[0]
        payload = line[1:]

        if prefix == "^":
            parsed["result_record"] = _parse_result_record(payload)
        elif prefix == "~":
            parsed["console"].append(_decode_mi_string(payload))
        elif prefix == "&":
            parsed["log"].append(_decode_mi_string(payload))
        elif prefix == "@":
            parsed["target"].append(_decode_mi_string(payload))
        elif prefix in {"*", "="}:
            parsed["async_records"].append(line)
        else:
            parsed["other"].append(line)

    return parsed


def _parse_result_record(payload: str) -> Dict[str, Any]:
    if not payload:
        return {"class": None, "payload": None}

    if "," not in payload:
        return {"class": payload, "payload": None}

    result_class, data = payload.split(",", 1)
    try:
        parsed_payload = _parse_tuple(data)
    except ValueError:
        _LOGGER.debug("Could not fully parse MI payload: %s", data)
        parsed_payload = {"__raw__": data}
    return {"class": result_class, "payload": parsed_payload}


def _parse_tuple(text: str) -> Dict[str, Any]:
    items: Dict[str, Any] = {}
    pos = 0
    length = len(text)

    while pos < length:
        pos = _skip_ws(text, pos)
        if pos >= length:
            break

        key, pos = _parse_identifier(text, pos)
        pos = _skip_ws(text, pos)
        if pos >= length or text[pos] != "=":
            raise ValueError(f"Malformed MI pair in: {text!r}")
        pos += 1
        value, pos = _parse_value(text, pos)
        items[key] = value
        pos = _skip_ws(text, pos)
        if pos < length and text[pos] == ",":
            pos += 1

    return items


def _parse_value(text: str, pos: int) -> tuple[Any, int]:
    pos = _skip_ws(text, pos)
    if pos >= len(text):
        return "", pos

    ch = text[pos]
    if ch == '"':
        return _parse_string(text, pos)
    if ch == "{":
        return _parse_dict(text, pos)
    if ch == "[":
        return _parse_list(text, pos)
    if ch in "-0123456789":
        return _parse_number(text, pos)
    if ch in _IDENTIFIER_CHARS:
        start = pos
        while pos < len(text) and text[pos] in _IDENTIFIER_CHARS:
            pos += 1
        ident = text[start:pos]
        pos = _skip_ws(text, pos)
        if pos < len(text) and text[pos] == "=":
            pos += 1
            value, pos = _parse_value(text, pos)
            return {ident: value}, pos
        return ident, pos

    return ch, pos + 1


def _parse_string(text: str, pos: int) -> tuple[str, int]:
    assert text[pos] == '"'
    pos += 1
    buf: List[str] = []
    while pos < len(text):
        ch = text[pos]
        if ch == "\\":
            pos += 1
            if pos >= len(text):
                break
            buf.append(_UNESCAPE_MAP.get(text[pos], text[pos]))
        elif ch == '"':
            pos += 1
            return "".join(buf), pos
        else:
            buf.append(ch)
        pos += 1
    return "".join(buf), pos


_UNESCAPE_MAP = {
    '"': '"',
    "\\": "\\",
    "n": "\n",
    "r": "\r",
    "t": "\t",
    "0": "\0",
}


def _parse_dict(text: str, pos: int) -> tuple[Any, int]:
    assert text[pos] == "{"
    pos += 1
    result: Dict[str, Any] = {}
    while pos < len(text):
        pos = _skip_ws(text, pos)
        if pos < len(text) and text[pos] == "}":
            return result, pos + 1
        key, pos = _parse_identifier(text, pos)
        pos = _skip_ws(text, pos)
        if pos >= len(text) or text[pos] != "=":
            raise ValueError(f"Malformed dict entry near {text[pos:]} in {text!r}")
        pos += 1
        value, pos = _parse_value(text, pos)
        result[key] = value
        pos = _skip_ws(text, pos)
        if pos < len(text) and text[pos] == ",":
            pos += 1
    return result, pos


def _parse_list(text: str, pos: int) -> tuple[Any, int]:
    assert text[pos] == "["
    pos += 1
    items: List[Any] = []
    while pos < len(text):
        pos = _skip_ws(text, pos)
        if pos < len(text) and text[pos] == "]":
            return items, pos + 1
        value, pos = _parse_value(text, pos)
        items.append(value)
        pos = _skip_ws(text, pos)
        if pos < len(text) and text[pos] == ",":
            pos += 1
    return items, pos


def _parse_number(text: str, pos: int) -> tuple[Any, int]:
    start = pos
    pos += 1
    while pos < len(text) and text[pos] in "0123456789":
        pos += 1
    substr = text[start:pos]
    try:
        return int(substr), pos
    except ValueError:
        return substr, pos


def _parse_identifier(text: str, pos: int) -> tuple[str, int]:
    start = pos
    while pos < len(text) and text[pos] in _IDENTIFIER_CHARS:
        pos += 1
    return text[start:pos], pos


def _skip_ws(text: str, pos: int) -> int:
    while pos < len(text) and text[pos] in " \t\n\r":
        pos += 1
    return pos


def _decode_mi_string(payload: str) -> str:
    if not payload or payload[0] != '"' or not payload.endswith('"'):
        return payload
    content = payload[1:-1]
    result_chars: List[str] = []
    idx = 0
    while idx < len(content):
        ch = content[idx]
        if ch == "\\" and idx + 1 < len(content):
            idx += 1
            result_chars.append(_UNESCAPE_MAP.get(content[idx], content[idx]))
        else:
            result_chars.append(ch)
        idx += 1
    return "".join(result_chars)


__all__ = [
    "GDBSession",
    "GDBSessionError",
    "GDBSessionNotRunning",
    "GDBSessionAlreadyRunning",
    "GDBCommandTimeout",
    "GDBTerminatedUnexpectedly",
    "GDBCommandResult",
]

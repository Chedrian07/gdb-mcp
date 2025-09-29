"""Model Context Protocol (MCP) server that exposes a GDB debugging session."""

from __future__ import annotations

import asyncio
import logging
import os
import shlex
import time
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from typing_extensions import Literal

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:  # pragma: no cover - import guard
    try:
        from fastmcp import FastMCP  # type: ignore
    except ImportError as exc:
        raise SystemExit(
            "Could not import FastMCP. Install it with 'pip install mcp' or 'pip install fastmcp'."
        ) from exc

from gdb_session import (
    GDBCommandResult,
    GDBCommandTimeout,
    GDBSession,
    GDBSessionAlreadyRunning,
    GDBSessionError,
)

_LOGGER = logging.getLogger(__name__)
logging.basicConfig(level=os.environ.get("GDB_MCP_LOGLEVEL", "INFO"))

server = FastMCP(
    name="gdb-mcp",
    instructions="Interact with a live GDB session via the Model Context Protocol.",
    dependencies=["gdb"],
)

_SESSION = GDBSession()

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_DOC_PATHS: Dict[str, Path] = {
    "eng": _REPO_ROOT / "docs" / "eng" / "gdb-feature-list.md",
    "kor": _REPO_ROOT / "docs" / "kor" / "gdb-feature-list.md",
}
_DOC_CACHE: Dict[str, str] = {}

_DEFAULT_COMMAND_TIMEOUT = 15.0
_SESSION_IDLE_TIMEOUT = float(os.environ.get("GDB_MCP_IDLE_TIMEOUT", "90"))
_IDLE_CHECK_INTERVAL = 5.0

_last_activity = time.monotonic()
_idle_monitor_task: Optional[asyncio.Task[None]] = None


def _format_args(args: Optional[List[str]]) -> str:
    if not args:
        return ""
    return " ".join(shlex.quote(item) for item in args)


async def _ensure_running() -> None:
    if not _SESSION.is_running():
        raise RuntimeError("GDB session is not running. Call start_session first.")


def _result_to_payload(result: GDBCommandResult) -> Dict[str, object]:
    payload = result.to_dict()
    # Convert lists to plain Python primitives for JSON friendliness
    payload["async_records"] = list(payload.get("async_records") or [])
    return payload


async def _exec_console_command(command: str, *, timeout: float = _DEFAULT_COMMAND_TIMEOUT) -> Dict[str, object]:
    _touch_activity()
    await _ensure_running()
    result = await _SESSION.execute_console(command, timeout=timeout)
    return _result_to_payload(result)


def _join_command(parts: Sequence[str]) -> str:
    return " ".join(part for part in parts if part)


def _touch_activity() -> None:
    global _last_activity
    _last_activity = time.monotonic()
    if _SESSION.is_running():
        _ensure_idle_monitor()


def _ensure_idle_monitor() -> None:
    if _SESSION_IDLE_TIMEOUT <= 0:
        return

    global _idle_monitor_task
    if _idle_monitor_task is None or _idle_monitor_task.done():
        _idle_monitor_task = asyncio.create_task(_idle_monitor_loop())


async def _idle_monitor_loop() -> None:
    if _SESSION_IDLE_TIMEOUT <= 0:
        return

    global _idle_monitor_task

    try:
        while True:
            interval = max(1.0, min(_IDLE_CHECK_INTERVAL, _SESSION_IDLE_TIMEOUT / 3))
            await asyncio.sleep(interval)

            if not _SESSION.is_running():
                continue

            idle_duration = time.monotonic() - _last_activity
            if idle_duration >= _SESSION_IDLE_TIMEOUT:
                _LOGGER.info(
                    "GDB session idle for %.1fs (threshold %.1fs); stopping session",
                    idle_duration,
                    _SESSION_IDLE_TIMEOUT,
                )
                try:
                    await _SESSION.stop(force=False)
                except Exception as exc:  # pragma: no cover - defensive
                    _LOGGER.warning("Failed to stop idle GDB session: %s", exc)
    except asyncio.CancelledError:  # pragma: no cover - task cancelled on shutdown
        pass
    finally:
        _idle_monitor_task = None


@server.tool()
async def start_session(
    executable: Optional[str] = None,
    args: Optional[List[str]] = None,
    cwd: Optional[str] = None,
    gdb_args: Optional[List[str]] = None,
    env: Optional[Dict[str, str]] = None,
) -> Dict[str, object]:
    """Start a new GDB session (if one is not already running)."""

    safe_env = dict(env) if env else None
    safe_args = list(gdb_args) if gdb_args else None

    try:
        banner = await _SESSION.start(
            cwd=cwd,
            gdb_args=safe_args,
            env=safe_env,
            executable=executable,
        )
    except (GDBSessionAlreadyRunning, GDBSessionError, FileNotFoundError) as exc:
        raise RuntimeError(str(exc))

    _touch_activity()

    result: Dict[str, object] = {"banner": banner, "started": True}

    if args:
        cmd = f"set args {_format_args(args)}"
        set_args_result = await _exec_console_command(cmd, timeout=5.0)
        result["set_args"] = set_args_result

    return result


@server.tool()
async def stop_session(force: bool = False) -> Dict[str, object]:
    """Terminate the active GDB session (if running)."""

    _touch_activity()
    if not _SESSION.is_running():
        return {"stopped": False, "reason": "session-not-running"}

    await _SESSION.stop(force=force)
    return {"stopped": True}


@server.tool()
async def session_status() -> Dict[str, object]:
    """Return high-level information about the current session."""

    _touch_activity()
    status: Dict[str, object] = {"running": _SESSION.is_running()}
    if _SESSION.is_running():
        status["last_command"] = _SESSION.last_command
    return status


@server.tool()
async def run_gdb_command(
    command: str,
    *,
    use_mi: bool = False,
    timeout: float = 15.0,
) -> Dict[str, object]:
    """Execute a single GDB command and return its structured output."""

    _touch_activity()
    await _ensure_running()

    try:
        if use_mi:
            result = await _SESSION.execute_mi(command, timeout=timeout)
        else:
            result = await _SESSION.execute_console(command, timeout=timeout)
    except (GDBCommandTimeout, GDBSessionError) as exc:
        raise RuntimeError(str(exc))

    return _result_to_payload(result)


@server.tool()
async def run_gdb_commands(
    commands: List[str],
    *,
    use_mi: bool = False,
    timeout: float = 15.0,
) -> List[Dict[str, object]]:
    """Execute multiple commands sequentially."""

    await _ensure_running()

    results: List[Dict[str, object]] = []
    for command in commands:
        if not command.strip():
            continue
        _touch_activity()
        try:
            if use_mi:
                res = await _SESSION.execute_mi(command, timeout=timeout)
                results.append(_result_to_payload(res))
            else:
                res = await _SESSION.execute_console(command, timeout=timeout)
                results.append(_result_to_payload(res))
        except (GDBCommandTimeout, GDBSessionError) as exc:
            results.append(
                {
                    "command": command,
                    "success": False,
                    "error": str(exc),
                }
            )
            continue
    return results


@server.tool()
async def interrupt_program() -> Dict[str, object]:
    """Send Ctrl-C to the inferior (useful while it is running)."""

    await _ensure_running()
    _touch_activity()
    try:
        await _SESSION.interrupt()
    except GDBSessionError as exc:
        raise RuntimeError(str(exc))
    return {"interrupted": True}


# ---------------------------------------------------------------------------
# Files / Symbols / Core loading
# ---------------------------------------------------------------------------


@server.tool()
async def load_executable(executable: str) -> Dict[str, object]:
    """Load or replace the current executable under debug."""

    command = _join_command(["file", shlex.quote(executable)])
    return await _exec_console_command(command)


@server.tool()
async def load_symbol_file(symbol_file: str) -> Dict[str, object]:
    """Replace the current symbol table with the provided file."""

    command = _join_command(["symbol-file", shlex.quote(symbol_file)])
    return await _exec_console_command(command)


@server.tool()
async def add_symbol_file(symbol_file: str, load_address: str) -> Dict[str, object]:
    """Add an additional symbol file at the provided load address."""

    command = _join_command([
        "add-symbol-file",
        shlex.quote(symbol_file),
        load_address,
    ])
    return await _exec_console_command(command)


@server.tool()
async def load_core_file(core_path: str) -> Dict[str, object]:
    """Load a core dump for post-mortem analysis."""

    command = _join_command(["core-file", shlex.quote(core_path)])
    return await _exec_console_command(command)


@server.tool()
async def info_files() -> Dict[str, object]:
    """Return GDB's view of loaded files and sections."""

    return await _exec_console_command("info files")


@server.tool()
async def info_shared_libraries(filter_regex: Optional[str] = None) -> Dict[str, object]:
    """List shared libraries currently known to GDB."""

    command = "info sharedlibrary"
    if filter_regex:
        command = _join_command([command, filter_regex])
    return await _exec_console_command(command)


# ---------------------------------------------------------------------------
# Program execution control
# ---------------------------------------------------------------------------


@server.tool()
async def set_program_arguments(args: Optional[List[str]] = None) -> Dict[str, object]:
    """Configure the arguments used by the next ``run``."""

    formatted = _format_args(args)
    command = "set args" if not formatted else _join_command(["set args", formatted])
    return await _exec_console_command(command)


@server.tool()
async def run_program(args: Optional[List[str]] = None) -> Dict[str, object]:
    """Run the inferior, optionally overriding arguments for this invocation."""

    parts = ["run"]
    if args:
        parts.append(_format_args(args))
    return await _exec_console_command(_join_command(parts))


@server.tool()
async def start_program(args: Optional[List[str]] = None) -> Dict[str, object]:
    """Start the program and stop at ``main`` (alias of ``start``)."""

    parts = ["start"]
    if args:
        parts.append(_format_args(args))
    return await _exec_console_command(_join_command(parts))


@server.tool()
async def restart_program() -> Dict[str, object]:
    """Restart the program using the last ``run`` arguments."""

    return await _exec_console_command("run")


@server.tool()
async def continue_execution() -> Dict[str, object]:
    """Continue program execution until the next breakpoint or event."""

    return await _exec_console_command("continue")


@server.tool()
async def step_into(count: int = 1) -> Dict[str, object]:
    """Execute ``step`` count times."""

    command = "step" if count == 1 else _join_command(["step", str(count)])
    return await _exec_console_command(command)


@server.tool()
async def step_over(count: int = 1) -> Dict[str, object]:
    """Execute ``next`` count times."""

    command = "next" if count == 1 else _join_command(["next", str(count)])
    return await _exec_console_command(command)


@server.tool()
async def step_instruction(count: int = 1) -> Dict[str, object]:
    """Execute ``stepi`` (step instruction) count times."""

    command = "stepi" if count == 1 else _join_command(["stepi", str(count)])
    return await _exec_console_command(command)


@server.tool()
async def next_instruction(count: int = 1) -> Dict[str, object]:
    """Execute ``nexti`` (next instruction) count times."""

    command = "nexti" if count == 1 else _join_command(["nexti", str(count)])
    return await _exec_console_command(command)


@server.tool()
async def finish_function() -> Dict[str, object]:
    """Run until the current function finishes (``finish``)."""

    return await _exec_console_command("finish")


@server.tool()
async def run_until(location: Optional[str] = None) -> Dict[str, object]:
    """Run until the next line or specified location (``until``)."""

    command = "until" if not location else _join_command(["until", location])
    return await _exec_console_command(command)


@server.tool()
async def reverse_continue() -> Dict[str, object]:
    """Reverse-continue execution (requires record/replay)."""

    return await _exec_console_command("reverse-continue")


@server.tool()
async def reverse_step() -> Dict[str, object]:
    """Reverse-step to the previous instruction."""

    return await _exec_console_command("reverse-step")


@server.tool()
async def reverse_next() -> Dict[str, object]:
    """Reverse-next (step backwards over)."""

    return await _exec_console_command("reverse-next")


# ---------------------------------------------------------------------------
# Breakpoints and watchpoints
# ---------------------------------------------------------------------------


def _build_breakpoint_command(keyword: str, location: str, condition: Optional[str]) -> str:
    parts = [keyword, location]
    if condition:
        parts.extend(["if", condition])
    return _join_command(parts)


@server.tool()
async def set_breakpoint(location: str, condition: Optional[str] = None) -> Dict[str, object]:
    """Set a breakpoint at the specified location."""

    command = _build_breakpoint_command("break", location, condition)
    return await _exec_console_command(command)


@server.tool()
async def set_temporary_breakpoint(location: str, condition: Optional[str] = None) -> Dict[str, object]:
    """Set a temporary breakpoint (auto-deletes when hit)."""

    command = _build_breakpoint_command("tbreak", location, condition)
    return await _exec_console_command(command)


@server.tool()
async def set_hardware_breakpoint(location: str, condition: Optional[str] = None) -> Dict[str, object]:
    """Set a hardware breakpoint (requires target support)."""

    command = _build_breakpoint_command("hbreak", location, condition)
    return await _exec_console_command(command)


@server.tool()
async def delete_breakpoint(number: Optional[int] = None) -> Dict[str, object]:
    """Delete a breakpoint/watchpoint by number or all if omitted."""

    command = "delete" if number is None else _join_command(["delete", str(number)])
    return await _exec_console_command(command)


@server.tool()
async def disable_breakpoints(numbers: Optional[List[int]] = None) -> Dict[str, object]:
    """Disable one or more breakpoints without removing them."""

    if numbers:
        arguments = " ".join(str(num) for num in numbers)
        command = _join_command(["disable", arguments])
    else:
        command = "disable"
    return await _exec_console_command(command)


@server.tool()
async def enable_breakpoints(numbers: Optional[List[int]] = None) -> Dict[str, object]:
    """Enable previously disabled breakpoints."""

    if numbers:
        arguments = " ".join(str(num) for num in numbers)
        command = _join_command(["enable", arguments])
    else:
        command = "enable"
    return await _exec_console_command(command)


@server.tool()
async def set_breakpoint_condition(breakpoint_number: int, condition: Optional[str] = None) -> Dict[str, object]:
    """Apply or clear a condition on an existing breakpoint."""

    if condition:
        command = _join_command(["condition", str(breakpoint_number), condition])
    else:
        command = _join_command(["condition", str(breakpoint_number)])
    return await _exec_console_command(command)


@server.tool()
async def set_ignore_count(breakpoint_number: int, count: int) -> Dict[str, object]:
    """Ignore the next *count* hits of a breakpoint."""

    command = _join_command(["ignore", str(breakpoint_number), str(count)])
    return await _exec_console_command(command)


@server.tool()
async def list_breakpoints() -> Dict[str, object]:
    """Return the ``info break`` listing."""

    return await _exec_console_command("info break")


@server.tool()
async def set_watchpoint(
    expression: str,
    *,
    watch_type: Literal["write", "read", "access"] = "write",
    condition: Optional[str] = None,
) -> Dict[str, object]:
    """Create a watchpoint for the given expression."""

    keyword = {
        "write": "watch",
        "read": "rwatch",
        "access": "awatch",
    }[watch_type]
    command = _build_breakpoint_command(keyword, expression, condition)
    return await _exec_console_command(command)


@server.tool()
async def list_watchpoints() -> Dict[str, object]:
    """Return ``info watch`` output."""

    return await _exec_console_command("info watch")


# ---------------------------------------------------------------------------
# Stack / frames utilities
# ---------------------------------------------------------------------------


@server.tool()
async def backtrace(limit: Optional[int] = None) -> Dict[str, object]:
    """Return a backtrace up to the optional depth."""

    command = "backtrace" if limit is None else _join_command(["backtrace", str(limit)])
    return await _exec_console_command(command)


@server.tool()
async def frame_info(frame: Optional[int] = None) -> Dict[str, object]:
    """Display detailed information about a frame."""

    command = "info frame" if frame is None else _join_command(["info frame", str(frame)])
    return await _exec_console_command(command)


@server.tool()
async def select_frame(frame: int) -> Dict[str, object]:
    """Select a specific frame number."""

    command = _join_command(["frame", str(frame)])
    return await _exec_console_command(command)


@server.tool()
async def frame_up(count: int = 1) -> Dict[str, object]:
    """Move up the call stack."""

    command = "up" if count == 1 else _join_command(["up", str(count)])
    return await _exec_console_command(command)


@server.tool()
async def frame_down(count: int = 1) -> Dict[str, object]:
    """Move down the call stack."""

    command = "down" if count == 1 else _join_command(["down", str(count)])
    return await _exec_console_command(command)


@server.tool()
async def list_locals() -> Dict[str, object]:
    """Show local variables for the selected frame."""

    return await _exec_console_command("info locals")


@server.tool()
async def list_arguments() -> Dict[str, object]:
    """Show arguments for the selected frame."""

    return await _exec_console_command("info args")


# ---------------------------------------------------------------------------
# Data / memory inspection
# ---------------------------------------------------------------------------


@server.tool()
async def evaluate_expression(expression: str, format: Optional[str] = None) -> Dict[str, object]:
    """Evaluate an expression via ``print`` with optional format (e.g., ``x``)."""

    command = "print" if not format else f"print/{format}"
    command = _join_command([command, expression])
    return await _exec_console_command(command)


@server.tool()
async def set_variable(lvalue: str, value: str) -> Dict[str, object]:
    """Assign a new value to a variable or memory location."""

    command = _join_command(["set", "var", f"{lvalue} = {value}"])
    return await _exec_console_command(command)


@server.tool()
async def examine_memory(
    address: str,
    *,
    count: int = 4,
    unit: Literal["b", "h", "w", "g", "i"] = "w",
    format: Literal["x", "d", "u", "o", "t", "a", "c", "f", "s", "i"] = "x",
) -> Dict[str, object]:
    """Examine memory using ``x`` with the requested layout."""

    spec = f"{count}{unit}{format}"
    command = _join_command([f"x/{spec}", address])
    return await _exec_console_command(command)


@server.tool()
async def display_expression(expression: str, format: Optional[str] = None) -> Dict[str, object]:
    """Add an expression to the ``display`` list."""

    command = "display" if not format else f"display/{format}"
    command = _join_command([command, expression])
    return await _exec_console_command(command)


@server.tool()
async def undisplay(display_number: Optional[int] = None) -> Dict[str, object]:
    """Remove one or all auto-displays."""

    command = "undisplay" if display_number is None else _join_command(["undisplay", str(display_number)])
    return await _exec_console_command(command)


@server.tool()
async def list_displays() -> Dict[str, object]:
    """Return ``info display`` output."""

    return await _exec_console_command("info display")


# ---------------------------------------------------------------------------
# Thread / process management
# ---------------------------------------------------------------------------


@server.tool()
async def list_threads() -> Dict[str, object]:
    """List all threads known to GDB."""

    return await _exec_console_command("info threads")


@server.tool()
async def select_thread(thread_id: int) -> Dict[str, object]:
    """Switch to the given thread id."""

    command = _join_command(["thread", str(thread_id)])
    return await _exec_console_command(command)


@server.tool()
async def thread_backtrace(thread_id: Optional[str] = "all", depth: Optional[int] = None) -> Dict[str, object]:
    """Run ``thread apply`` with ``backtrace`` on a thread or all threads."""

    target = thread_id or "all"
    command_parts = ["thread", "apply", target, "bt"]
    if depth is not None:
        command_parts.append(str(depth))
    return await _exec_console_command(_join_command(command_parts))


@server.tool()
async def thread_apply(thread_selector: str, command: str) -> Dict[str, object]:
    """Apply an arbitrary command to the specified thread(s)."""

    full_command = _join_command(["thread", "apply", thread_selector, command])
    return await _exec_console_command(full_command)


# ---------------------------------------------------------------------------
# Remote / target management
# ---------------------------------------------------------------------------


@server.tool()
async def connect_remote(target: str, *, extended: bool = False) -> Dict[str, object]:
    """Connect to a remote GDB server (target remote/extended-remote)."""

    keyword = "target extended-remote" if extended else "target remote"
    command = _join_command([keyword, target])
    return await _exec_console_command(command)


@server.tool()
async def disconnect_remote() -> Dict[str, object]:
    """Disconnect from the remote target."""

    return await _exec_console_command("disconnect")


@server.tool()
async def monitor_command(command: str) -> Dict[str, object]:
    """Send a ``monitor`` command to the remote stub."""

    full_command = _join_command(["monitor", command])
    return await _exec_console_command(full_command)


@server.tool()
async def set_architecture(architecture: str) -> Dict[str, object]:
    """Set the architecture for the target."""

    command = _join_command(["set architecture", architecture])
    return await _exec_console_command(command)


# ---------------------------------------------------------------------------
# Settings / info helpers
# ---------------------------------------------------------------------------


@server.tool()
async def set_pagination(enabled: bool) -> Dict[str, object]:
    """Enable or disable GDB pagination."""

    value = "on" if enabled else "off"
    command = _join_command(["set pagination", value])
    return await _exec_console_command(command)


@server.tool()
async def set_pretty_print(enabled: bool) -> Dict[str, object]:
    """Toggle ``set print pretty``."""

    value = "on" if enabled else "off"
    command = _join_command(["set print pretty", value])
    return await _exec_console_command(command)


@server.tool()
async def info_registers(register: Optional[str] = None) -> Dict[str, object]:
    """Return register contents (optionally a single register)."""

    command = "info registers" if register is None else _join_command(["info registers", register])
    return await _exec_console_command(command)


@server.tool()
async def info_program() -> Dict[str, object]:
    """Return ``info program`` output."""

    return await _exec_console_command("info program")


@server.tool()
async def info_functions(regex: Optional[str] = None) -> Dict[str, object]:
    """Return ``info functions`` (optionally filtered)."""

    command = "info functions" if regex is None else _join_command(["info functions", regex])
    return await _exec_console_command(command)


@server.tool()
async def info_variables(regex: Optional[str] = None) -> Dict[str, object]:
    """Return ``info variables`` (optionally filtered)."""

    command = "info variables" if regex is None else _join_command(["info variables", regex])
    return await _exec_console_command(command)


@server.tool()
async def get_feature_reference(
    topic: Optional[str] = None,
    language: str = "eng",
) -> Dict[str, object]:
    """Return the embedded, concise GDB reference from the docs directory."""

    document = _load_document(language)
    if topic:
        section = _extract_markdown_section(document, topic)
        if section:
            return {"language": language, "topic": topic, "content": section}
        return {
            "language": language,
            "topic": topic,
            "content": document,
            "message": "Topic not found; returning full document",
        }
    return {"language": language, "content": document}


@server.tool()
async def list_reference_topics(language: str = "eng") -> Dict[str, object]:
    """List all markdown headings in the reference document."""

    document = _load_document(language)
    headings = [
        line.strip()
        for line in document.splitlines()
        if line.startswith("## ") or line.startswith("### ")
    ]
    return {"language": language, "topics": headings}


def _load_document(language: str) -> str:
    lang_key = language.lower()
    path = _DOC_PATHS.get(lang_key)
    if path is None:
        raise RuntimeError(f"Unsupported language: {language}")
    if lang_key not in _DOC_CACHE:
        if not path.exists():
            raise RuntimeError(f"Reference document not found: {path}")
        _DOC_CACHE[lang_key] = path.read_text(encoding="utf-8")
    return _DOC_CACHE[lang_key]


def _extract_markdown_section(document: str, topic: str) -> str:
    lowered = topic.lower()
    lines = document.splitlines()
    start_index: Optional[int] = None
    start_level: Optional[int] = None

    for idx, line in enumerate(lines):
        if line.startswith("#"):
            stripped = line.lstrip("#")
            level = len(line) - len(stripped)
            title = stripped.strip().lower()
            if lowered in title:
                start_index = idx
                start_level = level
                break

    if start_index is None:
        matches = [line for line in lines if lowered in line.lower()]
        return "\n".join(matches[:40]).strip()

    collected: List[str] = [lines[start_index]]
    idx = start_index + 1
    while idx < len(lines):
        line = lines[idx]
        if line.startswith("#"):
            level = len(line) - len(line.lstrip("#"))
            if start_level is not None and level <= start_level:
                break
        collected.append(line)
        idx += 1

    return "\n".join(collected).strip()


def main() -> None:
    """CLI entrypoint when launched as ``python -m src.mcp-gdb.server``."""

    server.run()


if __name__ == "__main__":  # pragma: no cover - module entrypoint
    main()

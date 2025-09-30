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


def _exception_payload(command: str, *, error_type: str, message: str) -> Dict[str, object]:
    return {
        "command": command,
        "success": False,
        "result_class": None,
        "console_output": "",
        "result_payload": None,
        "async_records": [],
        "stderr_output": "",
        "raw_response": "",
        "error_type": error_type,
        "error_message": message,
    }


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
    except GDBCommandTimeout as exc:
        return _exception_payload(command, error_type="timeout", message=str(exc))
    except GDBSessionError as exc:
        return _exception_payload(command, error_type="session-error", message=str(exc))
    except Exception as exc:  # pragma: no cover - defensive
        _LOGGER.exception("Unexpected error while executing GDB command %s", command)
        return _exception_payload(command, error_type="unexpected", message=str(exc))

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
        except GDBCommandTimeout as exc:
            results.append(_exception_payload(command, error_type="timeout", message=str(exc)))
            continue
        except GDBSessionError as exc:
            results.append(_exception_payload(command, error_type="session-error", message=str(exc)))
            continue
        except Exception as exc:  # pragma: no cover - defensive
            _LOGGER.exception("Unexpected error while executing GDB command %s", command)
            results.append(_exception_payload(command, error_type="unexpected", message=str(exc)))
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
# Files / Symbols / Core loading (CONSOLIDATED)
# ---------------------------------------------------------------------------


@server.tool()
async def file_control(
    action: Literal["load_executable", "load_symbol", "add_symbol", "load_core"],
    path: str,
    load_address: Optional[str] = None,
) -> Dict[str, object]:
    """Unified file/symbol management: load executable, symbols, or core files.
    
    Args:
        action: Type of operation to perform
        path: Path to the file
        load_address: Required for 'add_symbol' action
    """
    
    if action == "load_executable":
        command = _join_command(["file", shlex.quote(path)])
    elif action == "load_symbol":
        command = _join_command(["symbol-file", shlex.quote(path)])
    elif action == "add_symbol":
        if not load_address:
            raise ValueError("load_address is required for add_symbol action")
        command = _join_command(["add-symbol-file", shlex.quote(path), load_address])
    elif action == "load_core":
        command = _join_command(["core-file", shlex.quote(path)])
    else:
        raise ValueError(f"Unknown action: {action}")
    
    return await _exec_console_command(command)


@server.tool()
async def info_files_symbols(
    what: Literal["files", "shared_libraries"],
    filter_regex: Optional[str] = None,
) -> Dict[str, object]:
    """Query file and symbol information.
    
    Args:
        what: Type of information to retrieve
        filter_regex: Optional filter for shared_libraries
    """
    
    if what == "files":
        return await _exec_console_command("info files")
    elif what == "shared_libraries":
        command = "info sharedlibrary"
        if filter_regex:
            command = _join_command([command, filter_regex])
        return await _exec_console_command(command)
    else:
        raise ValueError(f"Unknown query type: {what}")


# ---------------------------------------------------------------------------
# Program execution control (CONSOLIDATED)
# ---------------------------------------------------------------------------


@server.tool()
async def set_program_arguments(args: Optional[List[str]] = None) -> Dict[str, object]:
    """Configure the arguments used by the next ``run``."""

    formatted = _format_args(args)
    command = "set args" if not formatted else _join_command(["set args", formatted])
    return await _exec_console_command(command)


@server.tool()
async def program_control(
    action: Literal["run", "start", "restart"],
    args: Optional[List[str]] = None,
) -> Dict[str, object]:
    """Unified program start control.
    
    Args:
        action: run (start and continue), start (break at main), or restart
        args: Optional arguments (ignored for restart)
    """
    
    if action == "run":
        parts = ["run"]
        if args:
            parts.append(_format_args(args))
        command = _join_command(parts)
    elif action == "start":
        parts = ["start"]
        if args:
            parts.append(_format_args(args))
        command = _join_command(parts)
    elif action == "restart":
        command = "run"
    else:
        raise ValueError(f"Unknown action: {action}")
    
    return await _exec_console_command(command)


@server.tool()
async def execution_step(
    step_type: Literal["into", "over", "instruction", "next_instruction"],
    count: int = 1,
    reverse: bool = False,
) -> Dict[str, object]:
    """Unified stepping control for source and instruction level.
    
    Args:
        step_type: Type of step operation
        count: Number of steps to execute
        reverse: Execute in reverse (requires record/replay)
    """
    
    if step_type == "into":
        base_cmd = "reverse-step" if reverse else "step"
    elif step_type == "over":
        base_cmd = "reverse-next" if reverse else "next"
    elif step_type == "instruction":
        base_cmd = "stepi"  # no reverse variant commonly used
    elif step_type == "next_instruction":
        base_cmd = "nexti"  # no reverse variant commonly used
    else:
        raise ValueError(f"Unknown step_type: {step_type}")
    
    if reverse and step_type in ["instruction", "next_instruction"]:
        raise ValueError(f"Reverse stepping not supported for {step_type}")
    
    command = base_cmd if count == 1 else _join_command([base_cmd, str(count)])
    return await _exec_console_command(command)


@server.tool()
async def execution_flow(
    action: Literal["continue", "finish", "until", "reverse_continue"],
    location: Optional[str] = None,
) -> Dict[str, object]:
    """Unified execution flow control.
    
    Args:
        action: Type of flow control
        location: Required for 'until' action
    """
    
    if action == "continue":
        command = "continue"
    elif action == "finish":
        command = "finish"
    elif action == "until":
        if not location:
            command = "until"
        else:
            command = _join_command(["until", location])
    elif action == "reverse_continue":
        command = "reverse-continue"
    else:
        raise ValueError(f"Unknown action: {action}")
    
    return await _exec_console_command(command)


# ---------------------------------------------------------------------------
# Breakpoints and watchpoints (CONSOLIDATED)
# ---------------------------------------------------------------------------


def _build_breakpoint_command(keyword: str, location: str, condition: Optional[str]) -> str:
    parts = [keyword, location]
    if condition:
        parts.extend(["if", condition])
    return _join_command(parts)


@server.tool()
async def breakpoint_control(
    action: Literal["set", "set_temporary", "set_hardware", "delete",
                    "enable", "disable", "condition", "ignore", "list"],
    location: Optional[str] = None,
    number: Optional[int] = None,
    numbers: Optional[List[int]] = None,
    condition: Optional[str] = None,
    count: Optional[int] = None,
) -> Dict[str, object]:
    """Unified breakpoint management.
    
    Args:
        action: Type of breakpoint operation
        location: Required for set actions (e.g., "main", "file.c:42", "*0x400812")
        number: Breakpoint number for delete/condition/ignore
        numbers: List of breakpoint numbers for enable/disable
        condition: Condition expression for set/condition actions
        count: Ignore count for ignore action
    """
    
    if action == "set":
        if not location:
            raise ValueError("location is required for set action")
        command = _build_breakpoint_command("break", location, condition)
    elif action == "set_temporary":
        if not location:
            raise ValueError("location is required for set_temporary action")
        command = _build_breakpoint_command("tbreak", location, condition)
    elif action == "set_hardware":
        if not location:
            raise ValueError("location is required for set_hardware action")
        command = _build_breakpoint_command("hbreak", location, condition)
    elif action == "delete":
        command = "delete" if number is None else _join_command(["delete", str(number)])
    elif action == "enable":
        if numbers:
            arguments = " ".join(str(num) for num in numbers)
            command = _join_command(["enable", arguments])
        else:
            command = "enable"
    elif action == "disable":
        if numbers:
            arguments = " ".join(str(num) for num in numbers)
            command = _join_command(["disable", arguments])
        else:
            command = "disable"
    elif action == "condition":
        if number is None:
            raise ValueError("number is required for condition action")
        if condition:
            command = _join_command(["condition", str(number), condition])
        else:
            command = _join_command(["condition", str(number)])
    elif action == "ignore":
        if number is None or count is None:
            raise ValueError("number and count are required for ignore action")
        command = _join_command(["ignore", str(number), str(count)])
    elif action == "list":
        command = "info break"
    else:
        raise ValueError(f"Unknown action: {action}")
    
    return await _exec_console_command(command)


@server.tool()
async def watchpoint_control(
    action: Literal["set", "list"],
    expression: Optional[str] = None,
    watch_type: Literal["write", "read", "access"] = "write",
    condition: Optional[str] = None,
) -> Dict[str, object]:
    """Unified watchpoint management.
    
    Args:
        action: set or list
        expression: Expression to watch (required for set)
        watch_type: Type of watch (write/read/access)
        condition: Optional condition for the watchpoint
    """
    
    if action == "set":
        if not expression:
            raise ValueError("expression is required for set action")
        keyword = {
            "write": "watch",
            "read": "rwatch",
            "access": "awatch",
        }[watch_type]
        command = _build_breakpoint_command(keyword, expression, condition)
    elif action == "list":
        command = "info watch"
    else:
        raise ValueError(f"Unknown action: {action}")
    
    return await _exec_console_command(command)


# ---------------------------------------------------------------------------
# Stack / frames utilities (CONSOLIDATED)
# ---------------------------------------------------------------------------


@server.tool()
async def stack_control(
    action: Literal["backtrace", "select_frame", "up", "down",
                    "info_frame", "info_locals", "info_args"],
    frame_number: Optional[int] = None,
    count: int = 1,
    limit: Optional[int] = None,
) -> Dict[str, object]:
    """Unified stack and frame management.
    
    Args:
        action: Type of stack operation
        frame_number: Frame number for select_frame/info_frame
        count: Number of frames to move for up/down
        limit: Limit for backtrace depth
    """
    
    if action == "backtrace":
        command = "backtrace" if limit is None else _join_command(["backtrace", str(limit)])
    elif action == "select_frame":
        if frame_number is None:
            raise ValueError("frame_number is required for select_frame action")
        command = _join_command(["frame", str(frame_number)])
    elif action == "up":
        command = "up" if count == 1 else _join_command(["up", str(count)])
    elif action == "down":
        command = "down" if count == 1 else _join_command(["down", str(count)])
    elif action == "info_frame":
        command = "info frame" if frame_number is None else _join_command(["info frame", str(frame_number)])
    elif action == "info_locals":
        command = "info locals"
    elif action == "info_args":
        command = "info args"
    else:
        raise ValueError(f"Unknown action: {action}")
    
    return await _exec_console_command(command)


# ---------------------------------------------------------------------------
# Data / memory inspection (CONSOLIDATED)
# ---------------------------------------------------------------------------


@server.tool()
async def data_control(
    action: Literal["evaluate", "set_variable", "examine_memory",
                    "display_add", "display_remove", "display_list"],
    expression: Optional[str] = None,
    lvalue: Optional[str] = None,
    value: Optional[str] = None,
    address: Optional[str] = None,
    display_number: Optional[int] = None,
    format: Optional[str] = None,
    count: int = 4,
    unit: Literal["b", "h", "w", "g", "i"] = "w",
) -> Dict[str, object]:
    """Unified data inspection and modification.
    
    Args:
        action: Type of data operation
        expression: Expression for evaluate/display_add
        lvalue: Left-hand side for set_variable
        value: Right-hand side for set_variable
        address: Memory address for examine_memory
        display_number: Display number for display_remove
        format: Output format (e.g., 'x' for hex, 'd' for decimal)
        count: Number of units for examine_memory
        unit: Unit size for examine_memory (b/h/w/g/i)
    """
    
    if action == "evaluate":
        if not expression:
            raise ValueError("expression is required for evaluate action")
        command = "print" if not format else f"print/{format}"
        command = _join_command([command, expression])
    elif action == "set_variable":
        if not lvalue or not value:
            raise ValueError("lvalue and value are required for set_variable action")
        command = _join_command(["set", "var", f"{lvalue} = {value}"])
    elif action == "examine_memory":
        if not address:
            raise ValueError("address is required for examine_memory action")
        fmt = format or "x"
        spec = f"{count}{unit}{fmt}"
        command = _join_command([f"x/{spec}", address])
    elif action == "display_add":
        if not expression:
            raise ValueError("expression is required for display_add action")
        command = "display" if not format else f"display/{format}"
        command = _join_command([command, expression])
    elif action == "display_remove":
        command = "undisplay" if display_number is None else _join_command(["undisplay", str(display_number)])
    elif action == "display_list":
        command = "info display"
    else:
        raise ValueError(f"Unknown action: {action}")
    
    return await _exec_console_command(command)


# ---------------------------------------------------------------------------
# Thread / process management (CONSOLIDATED)
# ---------------------------------------------------------------------------


@server.tool()
async def thread_control(
    action: Literal["list", "select", "backtrace", "apply"],
    thread_id: Optional[int] = None,
    thread_selector: Optional[str] = None,
    command: Optional[str] = None,
    depth: Optional[int] = None,
) -> Dict[str, object]:
    """Unified thread management.
    
    Args:
        action: Type of thread operation
        thread_id: Thread ID for select action
        thread_selector: Thread selector for backtrace/apply (e.g., "all", "1.2")
        command: Command to apply for apply action
        depth: Backtrace depth for backtrace action
    """
    
    if action == "list":
        cmd = "info threads"
    elif action == "select":
        if thread_id is None:
            raise ValueError("thread_id is required for select action")
        cmd = _join_command(["thread", str(thread_id)])
    elif action == "backtrace":
        target = thread_selector or "all"
        command_parts = ["thread", "apply", target, "bt"]
        if depth is not None:
            command_parts.append(str(depth))
        cmd = _join_command(command_parts)
    elif action == "apply":
        if not thread_selector or not command:
            raise ValueError("thread_selector and command are required for apply action")
        cmd = _join_command(["thread", "apply", thread_selector, command])
    else:
        raise ValueError(f"Unknown action: {action}")
    
    return await _exec_console_command(cmd)


# ---------------------------------------------------------------------------
# Remote / target management (CONSOLIDATED)
# ---------------------------------------------------------------------------


@server.tool()
async def remote_control(
    action: Literal["connect", "disconnect", "monitor", "set_architecture"],
    target: Optional[str] = None,
    extended: bool = False,
    command: Optional[str] = None,
    architecture: Optional[str] = None,
) -> Dict[str, object]:
    """Unified remote debugging control.
    
    Args:
        action: Type of remote operation
        target: Remote target address for connect (e.g., "localhost:1234")
        extended: Use extended-remote for connect
        command: Monitor command to send
        architecture: Architecture name for set_architecture
    """
    
    if action == "connect":
        if not target:
            raise ValueError("target is required for connect action")
        keyword = "target extended-remote" if extended else "target remote"
        cmd = _join_command([keyword, target])
    elif action == "disconnect":
        cmd = "disconnect"
    elif action == "monitor":
        if not command:
            raise ValueError("command is required for monitor action")
        cmd = _join_command(["monitor", command])
    elif action == "set_architecture":
        if not architecture:
            raise ValueError("architecture is required for set_architecture action")
        cmd = _join_command(["set architecture", architecture])
    else:
        raise ValueError(f"Unknown action: {action}")
    
    return await _exec_console_command(cmd)


# ---------------------------------------------------------------------------
# Settings and info queries (CONSOLIDATED)
# ---------------------------------------------------------------------------


@server.tool()
async def gdb_setting(
    setting: Literal["pagination", "pretty_print"],
    enabled: bool,
) -> Dict[str, object]:
    """Configure GDB settings.
    
    Args:
        setting: Setting name to modify
        enabled: True to enable, False to disable
    """
    
    value = "on" if enabled else "off"
    
    if setting == "pagination":
        cmd = _join_command(["set pagination", value])
    elif setting == "pretty_print":
        cmd = _join_command(["set print pretty", value])
    else:
        raise ValueError(f"Unknown setting: {setting}")
    
    return await _exec_console_command(cmd)


@server.tool()
async def info_control(
    what: Literal["registers", "program", "functions", "variables"],
    register_name: Optional[str] = None,
    filter_regex: Optional[str] = None,
) -> Dict[str, object]:
    """Query various GDB information.
    
    Args:
        what: Type of information to query
        register_name: Specific register name for registers query
        filter_regex: Optional regex filter for functions/variables
    """
    
    if what == "registers":
        cmd = "info registers" if register_name is None else _join_command(["info registers", register_name])
    elif what == "program":
        cmd = "info program"
    elif what == "functions":
        cmd = "info functions" if filter_regex is None else _join_command(["info functions", filter_regex])
    elif what == "variables":
        cmd = "info variables" if filter_regex is None else _join_command(["info variables", filter_regex])
    else:
        raise ValueError(f"Unknown query type: {what}")
    
    return await _exec_console_command(cmd)


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

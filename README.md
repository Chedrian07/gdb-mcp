# gdb-mcp Server

![MCP server running](images/running_screen.png?raw=1)

## English

### Overview
The **gdb-mcp** project implements a Model Context Protocol (MCP) server that exposes a rich set of GDB 15.x capabilities to LLM-based clients. It launches an interactive `gdb` process, forwards commands through the MI2 interface, and returns structured responses, enabling step-by-step debugging, breakpoint management, memory inspection, and remote-target control from automated agents.

Key capabilities include:
- Asynchronous GDB session management with automatic idle shutdown (default 90 s, configurable via `GDB_MCP_IDLE_TIMEOUT`).
- High-level MCP tools mapped to common GDB workflows (execution control, break/watchpoints, stack & thread inspection, memory/data evaluation, remote debugging, documentation lookup).
- Robust MI output parsing, error propagation, and command batching for multi-step operations.
- Containerised distribution using Python 3.12, UV-based dependency management, and bundled `gdb` for reproducible environments.

### Repository Layout
- `src/mcp-gdb/gdb_session.py` – Async wrapper around the GDB MI interpreter, featuring result parsing and timeout handling.
- `src/mcp-gdb/server.py` – MCP server definition with dozens of tools mirroring the GDB cheat sheet in `docs/`.
- `docs/eng`, `docs/kor` – Concise GDB feature reference used by documentation tools.
- `Dockerfile` – Production image build with `python:3.12-slim`, UV package management, and pre-installed `gdb`.
- `images/running_screen.png` – Example screenshot of the server running inside Docker.

### Quick Start
```bash
# Build the container image
$ docker build -t gdb-mcp:latest .

# Run the MCP server (stdio transport)
$ docker run --rm -i \
    --cap-add=SYS_PTRACE \
    --security-opt seccomp=unconfined \
    -v "$PWD":/workspace \
    gdb-mcp:latest
```

The server waits for an MCP-compatible client (e.g., a desktop LLM application) to connect over stdio. Once connected, you can:

1. Call `start_session` to launch GDB, optionally specifying the target binary or arguments.
2. Use tools such as `set_breakpoint`, `run_program`, `backtrace`, `evaluate_expression`, or `connect_remote` to drive debugging.
3. Rely on `get_feature_reference` / `list_reference_topics` for quick GDB documentation lookup.
4. Allow the auto-idle monitor to shut down the session when inactive.

### Configuration
- `GDB_MCP_IDLE_TIMEOUT` – Seconds of inactivity before the session stops (default `90`).
- `GDB_MCP_LOGLEVEL` – Python logging level (`INFO`, `DEBUG`, etc.).

### Development Notes
- Install dependencies locally (optional): `uv pip install --system -r <generated requirements>` or work inside the Docker container.
- Run `python -m compileall src` to perform a lightweight syntax check.
- Refer to `docs/eng/gdb-feature-list.md` (English) or `docs/kor/gdb-feature-list.md` (Korean) for tool coverage when extending the server.

---

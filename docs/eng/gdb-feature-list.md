## GDB Features/Commands Reference (Concise)

This document summarizes core features and commonly used commands of GDB 15.x. Each section explains purpose, key subcommands/arguments, and short examples. Applicable to aarch64-linux-gnu builds as well.

Tip: Inside GDB, use `help`, `help <class>`, `help <command>`, and `apropos <word>` for detailed docs or related commands.

---

### Quick start
- Load executable: start with `file <path/to/binary>` or `gdb <binary>`
- Connect to remote target: `target remote <host:port>`
- Start/stop/quit: `run [args...]` / Ctrl-C / `quit`
- Common abbrevs: `bt`(backtrace), `ni`(nexti), `si`(stepi), `b`(break), `c`(continue), `n`(next), `s`(step), `fin`(finish)

---

## 1) Files / Symbols
Purpose: Specify and inspect executable/core/symbols for debugging

Key commands
- `file <exe>`: Set the current executable to debug
- `symbol-file <symfile>`: Load/replace a separate symbol file (e.g., .debug)
- `add-symbol-file <file> <addr> [sec addr ...]`: Load additional symbols at given addr
- `core-file <core>`: Load a core dump
- `exec-file <exe>`: Replace only the executable (symbol handling may vary)
- `sharedlibrary [regex]`: Load/rescan shared-library symbols
- `info files` / `info sharedlibrary`: Inspect loaded state

Examples
- `file ./a.out`
- `core-file core.1234`
- `add-symbol-file vmlinux 0xffff800010000000`

Caveats
- With PIE/ASLR, ensure correct base address for `add-symbol-file`
- Symbol version mismatches may produce warnings

---

## 2) Program execution
Purpose: Start/stop/restart and step through program execution

Key commands
- `run [args...]` / `start`: Run program (to main)
- `continue`/`c`: Continue until next breakpoint
- `next`/`n`: Step over (line)
- `step`/`s`: Step into (line)
- `finish`: Run until current function returns
- `until [loc]`: Run until given location/next line
- `reverse-continue|reverse-next|reverse-step`: Reverse debug (requires recording/build support)
- `interrupt`: Interrupt a running target (similar to Ctrl-C)

Examples
- `run --flag 1`
- `n` / `s` / `finish`
- `until 123` or `until func_name`

Caveats
- Reverse debug typically requires `record` (e.g., `record full`)

---

## 3) Breakpoints / Watchpoints
Purpose: Stop on code locations, conditions, or data accesses

Key commands
- `break|b <loc>`: Set breakpoint
  - loc formats: `file:line`, `func`, `*addr`
- `tbreak <loc>`: Temporary breakpoint
- `hbreak`/`thbreak`: Hardware breakpoint (target-dependent)
- `watch <expr>`: Watch data writes
- `rwatch <expr>`: Watch data reads
- `awatch <expr>`: Watch both reads/writes
- `condition <bnum> <expr>`: Conditional breakpoint
- `commands <bnum> ... end`: Auto-run commands when hit
- `ignore <bnum> <count>`: Ignore first N hits
- `enable|disable [bnum]`
- `delete [bnum]`
- `info break` / `info watch`

Examples
- `b main` / `b file.c:42` / `b *0x400812`
- `condition 1 i>10` / `ignore 1 3`
- `commands 1` → `silent` → `bt 3` → `continue` → `end`

Caveats
- Hardware watchpoints are limited in number (arch constraints)

---

## 4) Data / Memory inspection
Purpose: Evaluate expressions, dump/modify memory

Key commands
- `print|p <expr>`: Evaluate/print expression
- `set var <lvalue> = <expr>`: Modify variable/memory
- `x/<fmt> <addr|expr>`: Examine memory
  - fmt examples: `10x` (10 words, hex), `8gx` (8 8-byte units), `20i` (instructions)
- `ptype <symbol|expr>`: Show type info
- `display/undisplay <expr>`: Auto print per step
- `set print <option>`: Output formatting (e.g., `pretty on`)

Examples
- `p myvec.size()` / `p/x var` / `set var buf[0]=0`
- `x/16bx 0x7ffff7dd0000` / `x/20i $pc`
- `display/x $x0` (AArch64 register)

Caveats
- In multithreaded scenarios values may change due to races

---

## 5) Stack / Frames
Purpose: Inspect call stack, switch frames, inspect locals/args

Key commands
- `backtrace|bt [N]`
- `frame <N>` / `select-frame <N>`
- `up` / `down [COUNT]`
- `info frame` / `info args` / `info locals`
- `return [expr]`

Examples
- `bt 20` / `frame 3` / `info locals`

---

## 6) Disassembly / Registers
Purpose: Low-level analysis

Key commands
- `disassemble [/m|/s] [start, end]` (`/m` mixes source)
- `x/ni $pc`: Show n instructions at current PC
- `info registers [name]`
- `set $reg = <expr>`

Examples
- `disassemble /m main`
- `info registers` / `set $x0=0` (AArch64)

---

## 7) Source navigation / TUI
Purpose: Navigate source and use text UI

Key commands
- `list [loc]`
- `layout <split>`: TUI layout
  - split: `src`, `asm`, `regs`, `split`
- `tui enable|disable` or toggle `tui`
- `refresh`
- `winheight|winwidth`

Examples
- `layout split` / ``tui enable`` / `list main`

Caveats
- `text-user-interface` is a class name; actual command is `tui`/`layout`. Typing `text-user-interface` results in “Undefined command”.

---

## 8) Threads / Processes / Inferiors
Purpose: Control multi-process/multi-thread targets

Key commands
- `info threads` / `thread <ID>`
- `thread apply <ID|all> <cmd>`
- `add-inferior` / `remove-inferiors` / `inferior <ID>`
- `attach <pid>` / `detach`

Examples
- `info threads` → `thread 3` → `bt`
- `thread apply all bt 5`

---

## 9) Remote debugging / Targets
Purpose: Connect to gdbserver/emulator/hardware targets

Key commands
- `target remote <host:port>`
- `target extended-remote <host:port>`
- `monitor <cmd>` (e.g., QEMU)
- `set architecture <arch>`
- `remote`-related `set|show` options (timeouts, transfer, etc.)

Examples
- `target remote 127.0.0.1:1234`
- `monitor reset halt`

---

## 10) Tracepoints
Purpose: Collect trace data without stopping (useful for embedded/remote)

Key commands
- `trace <loc>` (like `tbreak` but non-stopping)
- `actions <tpoint>`: Define data to collect (e.g., `collect var, $regs`)
- `tstart` / `tstop` / `tstatus`
- `tsave <file>` / `tdump`

Examples
- `trace func` → `actions $tp` → `collect $pc, $sp, var` → `tstart`

Caveats
- Requires target/transport support; limited locally

---

## 11) Recording / Reverse debugging
Purpose: Record execution to move backward and reverse-execute

Key commands
- `record full|btrace|...`
- `tfind <start|end|range|pc>`
- `reverse-continue|reverse-step|reverse-next`
- `tstop`

Caveats
- Overheads can be high; target-dependent

---

## 12) Search / Find
Purpose: Search memory/assembly/source

Key commands
- `search <pattern>`: Search byte sequence
- `find [/size] <start>, <end>, <val1> [<val2> ...]`
- `forward-search` / `reverse-search`

Examples
- `find 0x400000, 0x410000, 0x90`

---

## 13) Info / Show / Status
Purpose: Inspect various states and settings

Key commands
- `info functions|variables|types`
- `info registers|args|locals|frame|files|sharedlibrary`
- `info break|watch|threads|inferiors|target`
- `show <setting>` (e.g., `show architecture`)

---

## 14) Settings (set/unset)
Purpose: Control runtime behavior/format/target params

Common ones
- `set disassemble-next-line on`
- `set pagination off`
- `set print pretty on`
- `set follow-fork-mode child|parent`
- `set detach-on-fork on|off`
- `set {type}addr = value`

Verify via `show <same-setting>`

---

## 15) Scripting / Extensibility (python, guile, define)
Purpose: Automation, user commands, pretty-printers

Key commands
- `python` / `python-interactive`
- `define <name> ... end`
- `alias <new> = <existing>`
- `document <name> ... end`
- `source <file>`

Examples
- `define pbt` → `bt 20` → `end` → then use `pbt`

---

## 16) On-the-fly compilation (compile)
Purpose: Compile small C snippets at runtime (Clang/LLVM integration)

Key commands
- `compile code <c-snippet>`
- `compile print <expr>` / `compile file <c-file>`

Caveats
- Consider security/stability; match optimization/ABI

---

## 17) Utilities / Misc
- `shell <cmd>`
- `save gdb-index|breakpoints|tracepoints <file>`
- `generate-core-file [file]`
- `dump memory|value|binary ...`
- `whatis <expr>`
- `demangle <name>`

---

## 18) Abbrevs / Common combos
- bt/fin/n/s/c, step with `display`, `info regs` + `x/10i $pc`, `layout split` then `tui`

---

## 19) Troubleshooting tips
- “Undefined command: text-user-interface”: Use `tui`/`layout` instead.
- Missing symbols: try `set substitute-path`, `directory <src_dir>`, rerun `sharedlibrary`
- Optimized binaries: `set disassemble-next-line on`, `set print pretty on`, mix `ni/si`
- ASLR/PIE: Use actual load address (`info proc mappings` or `info files`) for extra symbols

---

## 20) References
- GDB Docs: https://www.gnu.org/software/gdb/documentation/
- In-GDB help: `help`, `apropos`, `help all`

# Ariadne

In the myth, Ariadne’s thread is what lets Theseus walk the labyrinth and return.
This is that thread for a binary: a localhost XML-RPC bridge between **Binary Ninja**,
**GDB/pwndbg**, and a **Julia REPL**.

Ariadne is a lightweight alternative to tools like BinSync (collaborative database) and Binjatron (IDA-style XML-RPC). The Binary Ninja UI thread never waits on a sync: analysis is served from caches, and PC / breakpoint highlights are posted asynchronously and coalesced so a fast step loop cannot flood the GUI.

```
                     XML-RPC 127.0.0.1:9337
  Binary Ninja  <-------------------------------->  pwndbg client
  (plugin server)                                   (GDB events)
        ^                                               |
        |                                               | XML-RPC 127.0.0.1:9338
        |                                               v
        +----------------- Julia REPL ------------------+
           analysis queries          memory / registers
```

Both servers bind **localhost only**. Remote binds are rejected.

## What syncs

| Direction | Data |
| --- | --- |
| Binary Ninja → GDB | Renamed functions (GDB convenience vars `$ari_<name>`), function type strings, structs as a C header, stack-variable layouts |
| GDB → Binary Ninja | Current PC (highlighted + navigated in HLIL), enabled breakpoint locations |
| Julia → Binary Ninja | `func`, `blocks`, `il`, `types`, `stackvars` |
| Julia → GDB | `mem` / `mem!`, `regs`, `pc`, `breakpoints`, `gdb_eval` |

Addresses on the wire are **hex strings** (`"0x401000"`). XML-RPC `<int>` is 32-bit; hex strings keep 64-bit PCs intact.

GDB runtime addresses and Binary Ninja image addresses are converted with an explicit ASLR slide (`ariadne-base`).

## Requirements

- Binary Ninja with the Python API (tested against the 4.x / 5.x plugin metadata)
- GDB 12+ with Python 3, and [pwndbg](https://github.com/pwndbg/pwndbg)
- Julia 1.6+ (stdlib only: `Downloads`, `Base64`, `Sockets`)
- No extra Python packages at runtime (`xmlrpc` is in the stdlib)

## Setup

### 1. Binary Ninja plugin

Symlink the `plugin` directory into Binary Ninja's user plugin folder:

```bash
# Linux
ln -s "$(pwd)/plugin" ~/.binaryninja/plugins/ariadne

# macOS
ln -s "$(pwd)/plugin" "$HOME/Library/Application Support/Binary Ninja/plugins/ariadne"

# Windows (Admin PowerShell)
New-Item -ItemType SymbolicLink -Path "$env:APPDATA\Binary Ninja\plugins\ariadne" -Target (Resolve-Path .\plugin)
```

The plugin adds the repo's `shared/` directory to `sys.path` so `ariadne_protocol` imports resolve. If you copy the plugin without the rest of the repo, also copy `shared/ariadne_protocol` next to it or onto `PYTHONPATH`.

In Binary Ninja: **Plugins → Ariadne → Start server**. The log should show `Ariadne XML-RPC server on http://127.0.0.1:9337/RPC2`.

Override the bind with `ARIADNE_BN_HOST` / `ARIADNE_BN_PORT` if needed (host must stay loopback).

### 2. pwndbg client

After pwndbg has loaded:

```
(gdb) source /absolute/path/to/ariadne/pwndbg/ariadne.py
(gdb) ariadne-connect
(gdb) ariadne-base 0x555555554000          # GDB module base
# or, if you know the analysis address of the current PC:
(gdb) ariadne-base pc 0x401000
```

Commands:

| Command | Purpose |
| --- | --- |
| `ariadne` | Status (slide, cache hits, endpoints) |
| `ariadne-connect [host] [port]` | Attach to the Binary Ninja server and start the GDB RPC |
| `ariadne-sync` | Push PC/breakpoints and pull pending BN edits now |
| `ariadne-base <addr>` | Set the GDB module base (computes the slide) |
| `ariadne-base pc <analysis-addr>` | Infer the base from the current PC |
| `ariadne-stack` | Print cached notes for the current function |
| `ariadne-enable [off]` | Pause or resume automatic stop-sync |

Wait I should not introduce a typo. Use the exact local README.

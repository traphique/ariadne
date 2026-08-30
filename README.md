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
| `ariadne-stack` | Print cached stack variables for the current function |
| `ariadne-enable [off]` | Pause or resume automatic stop-sync |

The client hooks `gdb.events.stop` / breakpoint changes (and pwndbg `EventType.STOP` when present). The stop handler only starts a background thread — it does **not** call `gdb.execute`, which is a known GDB/pwndbg deadlock.

On stop it:

1. Pushes `$pc` and breakpoint addresses to Binary Ninja (`set_pc`, `set_breakpoints`).
2. Pulls `get_updates(since)` and applies new function names / types.

Stack-variable offsets are cached per function start on both sides. Renames in Binary Ninja bump a revision and invalidate that function's cache.

The GDB-side XML-RPC server (port **9338**) is what Julia uses for memory and registers. Incoming calls are `gdb.post_event`'d onto GDB's thread.

### 3. Julia REPL

```julia
julia> include("/absolute/path/to/ariadne/julia/Ariadne.jl")
julia> using .Ariadne
julia> connect!()   # talks to 127.0.0.1:9337 and :9338

# Binary Ninja analysis (image / analysis addresses)
julia> fn = func(0x401000)
julia> fn["header"]["name"]
julia> stackvars(0x401000)
julia> blocks(0x401000)
julia> il(0x401000, :hlil)          # also :mlil, :llil
julia> types()
julia> types("node")

# Live GDB session (runtime addresses)
julia> pc()
julia> regs()
julia> mem(0x7fffffffde00, 16)      # Vector{UInt8}
julia> mem!(0x7fffffffde00, UInt8[0x00, 0x01])
julia> breakpoints()
julia> gdb_eval("sizeof(void*)")
```

`examples.jl` is a scripted version of the same session. Change `0x401000` to a function that exists in your BinaryView.

Memory writes go through GDB's inferior API and are capped at 1 MiB. They are ordinary debugger writes, not a substitute for a process-control protocol — do not expose port 9338 off localhost.

## Architecture notes

**Why XML-RPC instead of gRPC.** The Python stdlib already has `xmlrpc.server` / `xmlrpc.client`, so the Binary Ninja plugin has zero pip dependencies. Julia talks to the same wire format with a small stdlib client (the older XMLRPC.jl package is unmaintained and does not handle faults). If you later want gRPC, keep the handler methods; only the transport changes.

**UI thread.** RPC runs on a `ThreadingMixIn` daemon thread.

- Analysis reads (`get_function`, `get_il`, …) never call `execute_on_main_thread_and_wait`.
- Highlights and HLIL navigation are `execute_on_main_thread` (fire-and-forget).
- Rapid `set_pc` calls publish to a `LatestValue` slot; a queued UI job that is no longer current is dropped.

**Caching.** `StackVarCache` is an LRU keyed by function start, with a monotonic revision per function. `BinaryDataNotification` (`function_updated`, type/symbol changes) invalidates the matching entries and appends to an incremental update log that GDB polls on stop.

**Rebase.** `AddressMapper` stores `analysis_base` (from `bv.start`) and `runtime_base` (from `ariadne-base`). `set_pc` / `set_breakpoints` treat incoming addresses as runtime by default; Julia analysis queries use analysis addresses (`as_runtime=false`).

## Tests

The protocol, cache, rebase math, C-header emitter, handlers (mock BinaryView), and XML-RPC round-trip run without Binary Ninja or GDB:

```bash
python3 -m pip install -r requirements-dev.txt
python3 -m pytest
```

## Layout

```
shared/ariadne_protocol/   wire types, stack cache, rebase, XML-RPC helpers
plugin/                     Binary Ninja plugin (plugin.json + ariadne/)
pwndbg/                     source-able GDB client + GDB XML-RPC server
julia/                      Ariadne.jl + examples
tests/                      headless unit tests
```

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `ARIADNE_BN_HOST` | `127.0.0.1` | Binary Ninja XML-RPC bind / connect host |
| `ARIADNE_BN_PORT` | `9337` | Binary Ninja XML-RPC port |
| `ARIADNE_GDB_HOST` | `127.0.0.1` | GDB XML-RPC bind / connect host |
| `ARIADNE_GDB_PORT` | `9338` | GDB XML-RPC port |
| `ARIADNE_CC` | `cc` | Optional compiler used to give GDB debug info for structs |

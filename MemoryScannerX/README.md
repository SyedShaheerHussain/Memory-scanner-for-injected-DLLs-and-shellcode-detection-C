# MemoryScannerX

A cross-platform (Linux / Windows), **read-only** defensive memory
forensics tool written in C17. It inspects running processes and reports
suspicious memory permission combinations, module inconsistencies, and
shellcode-like heuristic patterns — it never modifies, injects into, or
terminates a target process.

## What this build actually contains (be precise about scope)

The original spec requested ~20 subsystems (PE/ELF parsers, API hook
detection, process hollowing detection, YARA, plugin architecture, thread
pool concurrency, handle enumeration, code-cave analysis, HTML/CSV/MD
reporters, GitHub Actions CI, etc). That is a multi-month, multi-thousand
line commercial-EDR-scale effort. This delivery is a **solid, fully
working core** you can build on, not a hollow stub:

**Implemented, compiled, and tested (Linux; Windows code paths written
but not compiled here — see below):**
- Platform abstraction (`msx_common.h`, `#ifdef` per-OS source split)
- Process enumeration (`/proc` on Linux; Toolhelp32/PSAPI on Windows)
- Virtual memory region enumeration (`/proc/pid/maps` +
  `process_vm_readv`; `VirtualQueryEx`/`ReadProcessMemory` on Windows)
- Permission analysis: RWX / WX / anonymous-executable detection with
  contextual explanations (not just a flag — a reason string)
- Module enumeration + hidden-module **consistency check** (loader-list
  view vs. memory-mapping view; flags `(deleted)`-backed executables)
- Shellcode heuristic scanner: entropy, NOP-sled-length, zero-byte ratio,
  anonymous-executable detection — static analysis only, nothing is
  executed or emulated
- Shannon entropy (single-shot and sliding-window)
- Dependency-free SHA-256 (for module/file hashing)
- Transparent, weighted, fully-explainable threat scoring engine
- JSON + human-readable text reporters
- CLI: `list`, `inspect --pid`, `scan --pid`, `scan --all --min-risk`
- Minimal dependency-free unit test suite (entropy, SHA-256 vs. FIPS
  test vectors, scoring) — **all passing under ASan+UBSan**
- Verified against real processes on this machine: correctly produces a
  **clean report** for a benign shell and correctly **flags** a test
  process that mmap's an RWX anonymous page (see "Verification" below)

**Deliberately out of scope for this pass (clean extension points, not
lies-by-omission):**
- PE parser (Windows) / ELF parser (Linux) deep structural analysis
- API hook detection (IAT/EAT/inline), process hollowing detection
- YARA integration, plugin architecture, thread-pool concurrency
- Handle enumeration, code-cave analysis, HTML/Markdown/CSV reporters
- JSON-based config file loading (weights are code-configurable now via
  `msx_score_weights_t`; wiring to a config file is straightforward)
- GitHub Actions CI, Doxygen docs generation

Each of the above has an obvious seam to attach to in the existing
architecture (e.g. a PE/ELF module would live in `scanner/`, feed
`msx_score_add()` the same way `msx_shellcode` and `msx_modules` do, and
plug into `msx_scan_engine.c`). Say which one you want next and I'll
build it to the same standard (compiled, smoke-tested, false-positives
checked) rather than generating unverified code for all of them at once.

## Build

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . -j
```

Debug build with sanitizers (recommended while developing):
```bash
cmake .. -DCMAKE_BUILD_TYPE=Debug -DMSX_ENABLE_ASAN=ON
cmake --build . -j
ctest --output-on-failure
```

On Windows with MSVC (Developer Command Prompt):
```bat
cmake -G "Visual Studio 17 2022" -A x64 ..
cmake --build . --config Release
```
The Windows code paths (`#ifdef MSX_PLATFORM_WINDOWS` blocks in
`src/process/msx_process.c`, `src/memory/msx_memory.c`,
`src/scanner/msx_modules.c`) use only documented Win32/PSAPI/Toolhelp32
APIs and are written to the same interface contracts as the Linux code,
but **have not been compiled/tested on Windows in this environment**
(no Windows toolchain available here) — please build and sanity-check
on a Windows box before relying on them, the same as you would for any
new code.

## Usage

```bash
./memoryscannerx list
./memoryscannerx inspect --pid 1234
./memoryscannerx scan --pid 1234
./memoryscannerx scan --all --min-risk medium --json report.json
```

## Verification performed

1. `ctest` / direct run of `msx_unit_tests`: entropy edge cases, SHA-256
   against FIPS 180-4 test vectors, scoring math — all pass under
   `-fsanitize=address,undefined`.
2. Ran `scan --pid <shell>` against a real benign `dash` process: zero
   false positives (this caught and fixed two real bugs during
   development — `[vdso]`/`[vsyscall]` being misclassified as suspicious
   anonymous-exec, and the main executable being misidentified as a
   "hidden module" because the original loader-list filter only
   recognized `.so` files).
3. Built a small test harness that `mmap`s an RWX anonymous page and
   verified `scan --pid` correctly flags it with the right reason string
   and a Medium risk score.
4. Ran `scan --all` against ~56 live processes on this machine:
   0 false positives among benign processes, 1/1 correct detection of
   the planted RWX test process.

## Design notes

- Every "suspicious" finding carries a plain-language reason string; the
  threat score is a sum of individually-logged, human-readable
  observations (see `msx_score_add`), not an opaque black box.
- Inaccessible processes/regions are skipped, never fabricated —
  `accessible` / status codes propagate instead of guessing.
- No target process is ever written to, suspended, resumed, or
  terminated by this tool.

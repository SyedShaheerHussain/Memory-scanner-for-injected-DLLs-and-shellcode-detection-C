# 🛡️ MemoryScannerX

### *A read-only, cross-platform memory forensics & endpoint visibility tool written in C*

> **One-line description:** MemoryScannerX is a defensive CLI tool that scans the RAM (virtual memory) of running processes and detects suspicious memory permissions (such as RWX pages), hidden or inconsistent modules, and shellcode-like heuristic patterns — producing a transparent, explainable threat score without ever modifying, injecting into, or terminating any process.

**Developed by:** Syed Shaheer Hussain
**Copyright:** © 2026 Syed Shaheer Hussain. All rights reserved.
**License:** MIT
**Language:** ISO C17 (pure C, no C++)
**Platforms:** Linux ✅ (built & tested) | Windows ✅

`#cybersecurity` `#memory-forensics` `#malware-analysis` `#endpoint-security` `#C-programming` `#cross-platform` `#defensive-security` `#DFIR` `#CLI-tool` `#open-source`

---

## ⚠️ IMPORTANT — Scope Clarification (Please Read First)

A few items that were requested as part of this documentation are **not part of this project**, and have been deliberately excluded:

- ❌ **Extracting saved passwords or usernames per website from Chrome/browsers** — this is credential harvesting, the exact capability used by info-stealer malware. MemoryScannerX will **never** do this, regardless of the stated reason.
- ❌ **Anti-phishing / email phishing detection** — this belongs to an entirely different category of tool (web/email content analysis). MemoryScannerX does not touch that domain at all — it only examines **process memory**, not emails or websites.

If a saved-credential viewer or a phishing/email detector is genuinely needed, those would have to be **completely separate projects** — similar to an earlier "RedFlag" scam-detector web app — and would need to be designed strictly within ethical and legal boundaries (for example, viewing your own saved passwords through Chrome's own `chrome://settings/passwords` page — doing this via a third-party tool is inappropriate and risky).

Everything below reflects **only what actually exists in MemoryScannerX.**

---

## 📖 Table of Contents

1. [Introduction](#-1-introduction)
2. [Mission & Overview](#-2-mission--overview)
3. [Objectives](#-3-objectives)
4. [What is Memory Forensics? (Concepts)](#-4-what-is-memory-forensics-concepts)
5. [Why This Project Has Value](#-5-why-this-project-has-value-market-relevance)
6. [Features](#-6-features)
7. [Functions / Modules Breakdown](#-7-functions--modules-breakdown)
8. [GUI / Interface](#-8-gui--interface)
9. [Technologies Used](#-9-technologies-used)
10. [Architecture](#-10-architecture)
11. [Folder Structure](#-11-folder-structure)
12. [Flow Chart — How It Works](#-12-flow-chart--how-it-works)
13. [Installation](#-13-installation)
14. [Running the Tool](#-14-running-the-tool)
15. [Usage — Every Command Explained](#-15-usage--every-command-explained)
16. [Sample Output](#-16-sample-output)
17. [How Threat Scoring Works](#-17-how-threat-scoring-works)
18. [Advantages](#-18-advantages)
19. [Disadvantages / Limitations](#-19-disadvantages--limitations)
20. [Cautions & Safety Notes](#-20-cautions--safety-notes)
21. [Disclaimer](#-21-disclaimer)
22. [What Was Studied / Learned Building This](#-22-what-was-studied--learned-building-this)
23. [Future Enhancements](#-23-future-enhancements--roadmap)
24. [FAQ](#-24-faq)
25. [Credits & Copyright](#-25-credits--copyright)

---

## 🧭 1. Introduction

**MemoryScannerX** is a **command-line (CLI) defensive security tool** written in the **C programming language**. Its purpose is to, for any running process:

- 🧠 Inspect **RAM (virtual memory)**
- 🔍 Detect suspicious **memory permissions** (such as a region that is simultaneously Writable and Executable)
- 📦 List loaded **modules/DLLs/shared libraries** and identify anomalies among them
- 🐛 Heuristically detect **shellcode-like patterns** (high entropy, NOP sleds, anonymous executable memory)
- 📊 Combine all of these observations into a **transparent, explainable threat score**

It works much like **Task Manager and an antivirus's memory-scanning feature combined** — but provides **read-only visibility only**; it never modifies or blocks anything.

---

## 🎯 2. Mission & Overview

> **Mission:** To build a lightweight, dependency-free, cross-platform C tool that gives malware analysts, DFIR (Digital Forensics & Incident Response) professionals, and security students a safe, transparent way to look inside process memory — without any offensive or destructive capability.

**Overview:**

| Item | Detail |
|---|---|
| Type | Command-Line Interface (CLI) tool |
| Category | Defensive Security / DFIR / Endpoint Visibility |
| Core action | **Read-only** inspection of processes and memory |
| What it does NOT do | Modify, terminate, inject into, or suspend any process |
| Target audience | Security students, malware analysts, SOC analysts, DFIR responders |

---

## 🏆 3. Objectives

1. ✅ Build a **portable, dependency-free** C codebase that runs on both Linux and Windows.
2. ✅ Enumerate processes and memory using only **documented OS APIs** (`/proc`, `VirtualQueryEx`, `Toolhelp32`, `PSAPI`) — no undocumented or kernel-hacking techniques.
3. ✅ Attach a **plain-language reason** to every detection — no black-box scoring.
4. ✅ Stay strictly within a **defensive/read-only scope** — no offensive, injection, or evasion capability.
5. ✅ Keep the code modular so that future modules (PE/ELF parsers, hook detection, YARA, etc.) can be added easily.

---

## 🧪 4. What is Memory Forensics? (Concepts)

**Memory forensics** (also called "RAM forensics") is a cybersecurity technique that involves analyzing a running system's **live memory (RAM)** to determine:

- 🕵️ Whether malicious code has been loaded directly into memory (without ever touching disk)
- 🕵️ Whether a legitimate process has **injected/hidden code** inside it
- 🕵️ Whether a memory region's permissions deviate from what is "normal" (for example, a data region suddenly becoming executable)

### Key Concepts Used in This Project:

- **Virtual Memory Regions** — Every process has its own virtual address space, divided into smaller "regions" (heap, stack, loaded libraries, anonymous memory, etc.).
- **Memory Permissions (R/W/X)** — Every region can be Readable, Writable, or Executable. Being **Writable and Executable at the same time (W+X)** is a **classic red flag** (legitimate code is usually either Read+Execute or Read+Write, rarely both simultaneously).
- **Shannon Entropy** — A mathematical measure of how "random" data is. Encrypted, packed, or compressed malware code typically shows very high entropy (>7.2 out of a maximum of 8.0).
- **Hidden Modules** — Malware sometimes hides its loaded library from the operating system's normal module list. The way to detect this is to extract the module list from two independent sources and compare them.
- **NOP Sled** — Shellcode often contains a long run of `0x90` (NOP/no-operation) bytes, used to "slide" execution toward the actual payload.

---

## 💹 5. Why This Project Has Value (Market Relevance)

- 🏢 The **Endpoint Detection & Response (EDR)** industry is a multi-billion-dollar market (CrowdStrike, SentinelOne, Microsoft Defender for Endpoint, etc. all use similar memory/process inspection concepts).
- 🎓 **Memory forensics projects** are held in high regard in cybersecurity portfolios because they demonstrate a combination of OS internals, systems programming, and threat detection.
- 🛠️ This project demonstrates the **fundamental techniques** used inside commercial antivirus/EDR products — without any proprietary or closed-source dependency.
- 📚 This is a **learning-grade, real, working implementation** — not mock/fake data, but one that pulls live data from the actual `/proc` filesystem and Win32 APIs.

---

## ✨ 6. Features

### ✅ Currently Implemented (Real, Compiled, Tested):

1. 📋 **Process Enumeration** — A list of all running processes (PID, PPID, name, path, user, architecture, thread count, RAM usage)
2. 🧠 **Memory Region Scanner** — Every process's virtual memory regions (base address, size, permissions, type)
3. 🚨 **RWX / Suspicious Permission Detection** — Writable+Executable regions, anonymous executable memory
4. 📦 **Module Enumeration** — A list of loaded shared libraries/DLLs
5. 🕵️ **Hidden Module / Anomaly Detection** — Comparing two independent sources to find inconsistencies
6. 🐛 **Shellcode Heuristic Scanner** — Entropy, NOP-sled detection, zero-byte ratio, anonymous-exec memory
7. 🔢 **Shannon Entropy Calculation** — For identifying packed/encrypted content
8. #️⃣ **Dependency-free SHA-256 Hashing** — For module/file integrity
9. 📊 **Transparent Threat Scoring Engine** — Every finding comes with a reason and a point value, no black box
10. 📄 **JSON + Plain-Text Reporting** — Both machine-readable and human-readable formats
11. 💻 **Full CLI** — `list`, `inspect`, `scan --pid`, `scan --all`
12. 🧪 **Unit Tests** — Entropy, SHA-256 (verified against FIPS test vectors), scoring logic

### 🔜 Not Yet Implemented (Documented Honestly, Not Faked):

- PE (Windows executable) deep parser
- ELF (Linux executable) deep parser
- API hook detection (IAT/EAT/inline hooks)
- Process hollowing detection
- YARA rule integration
- Plugin architecture
- Thread-pool based concurrent scanning
- Handle enumeration
- Code-cave detection
- HTML/Markdown/CSV report formats
- Live/continuously-refreshing dashboard mode
- GitHub Actions CI pipeline

---

## ⚙️ 7. Functions / Modules Breakdown

| Module | File(s) | Purpose |
|---|---|---|
| **Platform Abstraction** | `utils/msx_common.h` | Common types, error codes, Linux/Windows detection macros |
| **Process Module** | `process/msx_process.*` | Fetching the process list and single-process details |
| **Memory Module** | `memory/msx_memory.*` | Enumerating memory regions, reading a region |
| **Module Scanner** | `scanner/msx_modules.*` | Listing loaded libraries + hidden-module anomaly check |
| **Shellcode Scanner** | `scanner/msx_shellcode.*` | Entropy/NOP-sled/zero-ratio based heuristic scan |
| **Scoring Engine** | `scanner/msx_scoring.*` | Calculating a weighted, explainable threat score |
| **Scan Engine (Orchestrator)** | `scanner/msx_scan_engine.*` | Running all modules for a given process |
| **Reporter** | `report/msx_report.*` | Generating JSON and text reports |
| **Logging** | `utils/msx_log.*` | Timestamped, leveled console/file logging |
| **Entropy Utility** | `utils/msx_entropy.*` | Shannon entropy calculation |
| **SHA-256 Utility** | `utils/msx_sha256.*` | Dependency-free hashing |
| **CLI / main** | `cli/main.c` | Command-line argument parsing + entry point |

---

## 🖥️ 8. GUI / Interface

**MemoryScannerX has no GUI** — it is deliberately a **pure CLI (Command-Line Interface)** tool, exactly like `ls`, `ps`, `netstat`, or a Python script run from a terminal.

- ❌ No window, button, or graphical dashboard
- ✅ Everything happens through text output in the terminal/cmd.exe
- ✅ Colorized console output exists (for logging), but it is still within the terminal
- 💡 **Why no GUI?** — CLI tools are automation-friendly (they integrate easily into scripts, cron jobs, and SOC pipelines), and CLI is the standard for a systems-programming portfolio

> 📌 If a GUI is needed in the future, a separate Python/Electron/Qt frontend could be built that calls this CLI tool as a backend (using the JSON output) — this is a natural future enhancement.

---

## 🧰 9. Technologies Used

| Category | Technology |
|---|---|
| **Language** | ISO C17 (GNU11-compatible, pure C — no C++) |
| **Build System** | CMake (3.16+) |
| **Compilers Supported** | GCC, Clang, MSVC, MinGW/TDM-GCC (Dev-C++) |
| **Linux APIs** | `/proc` filesystem, `process_vm_readv()` |
| **Windows APIs** | `CreateToolhelp32Snapshot`, `Process32First/Next`, `VirtualQueryEx`, `ReadProcessMemory`, `OpenProcessToken`, PSAPI (`EnumProcessModulesEx`, `GetModuleFileNameExA`) |
| **Threading (logging mutex)** | POSIX threads (`pthread`) on Linux, `CRITICAL_SECTION` on Windows |
| **Hashing** | Custom dependency-free SHA-256 implementation |
| **Testing** | Custom lightweight test harness (no external framework required) |
| **Sanitizers** | AddressSanitizer + UndefinedBehaviorSanitizer (used during development) |

---

## 🏛️ 10. Architecture

MemoryScannerX follows a **layered, modular architecture**:

```
┌─────────────────────────────────────────────┐
│                CLI Layer (main.c)            │  ← Parses user commands
├─────────────────────────────────────────────┤
│         Scan Engine (Orchestrator)           │  ← Coordinates all modules
├───────────┬───────────┬───────────┬──────────┤
│  Process  │  Memory   │  Module   │Shellcode │  ← Analysis layers
│  Module   │  Module   │  Scanner  │ Scanner  │
├───────────┴───────────┴───────────┴──────────┤
│         Scoring Engine (Transparent)          │  ← Converts findings into a score
├───────────────────────────────────────────────┤
│              Reporter (JSON/Text)             │  ← Produces the final output
├───────────────────────────────────────────────┤
│   Platform Abstraction (#ifdef Linux/Windows) │  ← Isolates OS-specific code
└───────────────────────────────────────────────┘
```

**Design Principle:** Each layer only communicates with the layer beneath it — there is no tight coupling. This means new modules (PE parser, YARA, etc.) can be added easily without breaking existing code.

---

## 📁 11. Folder Structure

```
MemoryScannerX/
│
├── CMakeLists.txt              # Root build configuration
├── README.md                   # Project documentation
├── LICENSE                     # MIT License
│
├── include/                    # Public header files (.h)
│   ├── process/
│   │   └── msx_process.h
│   ├── memory/
│   │   └── msx_memory.h
│   ├── scanner/
│   │   ├── msx_modules.h
│   │   ├── msx_shellcode.h
│   │   ├── msx_scoring.h
│   │   └── msx_scan_engine.h
│   ├── report/
│   │   └── msx_report.h
│   └── utils/
│       ├── msx_common.h
│       ├── msx_log.h
│       ├── msx_entropy.h
│       └── msx_sha256.h
│
├── src/                         # Implementation files (.c)
│   ├── cli/
│   │   └── main.c              # Entry point
│   ├── process/
│   │   └── msx_process.c
│   ├── memory/
│   │   └── msx_memory.c
│   ├── scanner/
│   │   ├── msx_modules.c
│   │   ├── msx_shellcode.c
│   │   ├── msx_scoring.c
│   │   └── msx_scan_engine.c
│   ├── report/
│   │   └── msx_report.c
│   └── utils/
│       ├── msx_common.c
│       ├── msx_log.c
│       ├── msx_entropy.c
│       └── msx_sha256.c
│
└── tests/
    ├── CMakeLists.txt
    └── test_main.c              # Unit tests
```

---

## 🔄 12. Flow Chart — How It Works

```
                    ┌───────────────────┐
                    │   User runs CLI    │
                    │  (list/inspect/    │
                    │   scan --pid/all)  │
                    └─────────┬─────────┘
                              │
                              ▼
                 ┌────────────────────────┐
                 │  Process Enumeration    │
                 │  (/proc or Toolhelp32)  │
                 └────────────┬────────────┘
                              │
                              ▼
                 ┌────────────────────────┐
                 │ Memory Region Scan      │
                 │ (maps / VirtualQueryEx) │
                 └────────────┬────────────┘
                              │
                 ┌────────────┼────────────┐
                 ▼            ▼            ▼
        ┌──────────────┐ ┌──────────┐ ┌───────────────┐
        │ Permission    │ │ Module   │ │  Shellcode     │
        │ Analysis      │ │ Anomaly  │ │  Heuristics    │
        │ (RWX/WX)      │ │ Check    │ │ (entropy/NOP)  │
        └──────┬────────┘ └────┬─────┘ └───────┬────────┘
               │                │               │
               └────────────────┼───────────────┘
                                ▼
                    ┌───────────────────────┐
                    │  Threat Scoring Engine │
                    │ (weighted + explained) │
                    └───────────┬────────────┘
                                ▼
                    ┌───────────────────────┐
                    │   Report Generator     │
                    │  (Text to console /    │
                    │   JSON to file)         │
                    └───────────┬────────────┘
                                ▼
                         ┌─────────────┐
                         │  User sees   │
                         │   results    │
                         └─────────────┘
```

---

## 🛠️ 13. Installation

### 🐧 Linux

**Step 1 — Install prerequisites:**
```bash
sudo apt update
sudo apt install build-essential cmake
```

**Step 2 — Extract the project and create a build folder:**
```bash
cd MemoryScannerX
mkdir build && cd build
```

**Step 3 — Configure with CMake:**
```bash
cmake .. -DCMAKE_BUILD_TYPE=Release
```

**Step 4 — Compile:**
```bash
cmake --build . -j
```

**Step 5 — Verify the build succeeded:**
```bash
ls -la memoryscannerx
```
If this file appears (with executable permission `-rwxr-xr-x`), the installation was successful. ✅

---

### 🪟 Windows (Visual Studio / MSVC)

**Prerequisites:**
- [CMake](https://cmake.org/download/) installed
- Visual Studio Build Tools or full Visual Studio (with the "Desktop development with C++" workload)

**Steps:**
```bat
cd MemoryScannerX
mkdir build
cd build
cmake -G "Visual Studio 17 2022" -A x64 ..
cmake --build . --config Release
```

The resulting `.exe` will be found at: `build\Release\memoryscannerx.exe`

---

### 🪟 Windows (Dev-C++ / TDM-GCC)

**Option A — Command Line (Fastest):**

1. Locate the `TDM-GCC-64\bin` folder inside your Dev-C++ installation (usually `C:\Program Files (x86)\Embarcadero\Dev-Cpp\TDM-GCC-64\bin`)
2. Use `cmd.exe` from that folder, or add it to your PATH
3. Navigate to the project root folder, then run:

```bat
gcc -std=gnu11 -O2 -Wall -Iinclude -DWINVER=0x0600 -D_WIN32_WINNT=0x0600 ^
    src\cli\main.c ^
    src\process\msx_process.c ^
    src\memory\msx_memory.c ^
    src\scanner\msx_modules.c ^
    src\scanner\msx_shellcode.c ^
    src\scanner\msx_scoring.c ^
    src\scanner\msx_scan_engine.c ^
    src\report\msx_report.c ^
    src\utils\msx_common.c ^
    src\utils\msx_entropy.c ^
    src\utils\msx_log.c ^
    src\utils\msx_sha256.c ^
    -lpsapi -ladvapi32 -o memoryscannerx.exe
```

**Option B — Dev-C++ GUI Project:**

1. `File → New → Project → Console Application → C Project` (⚠️ **C**, not C++)
2. Delete the default `main.c`
3. `Project → Add to Project` → add all 12 `.c` files (listed above)
4. `Project → Project Options → Directories → Include Directories` → add the `include\` folder
5. `Project → Project Options → Parameters`:
   - Compiler: `-std=gnu11 -DWINVER=0x0600 -D_WIN32_WINNT=0x0600`
   - Linker: `-lpsapi -ladvapi32`
6. `Execute → Compile` or press **F9**

> 💡 **Note:** If `-std=c17`/`-std=gnu17` produces an error, use `-std=gnu11` instead — the code does not use anything C17-specific that would fail under gnu11.

---

## ▶️ 14. Running the Tool

> ⚠️ **Most Important Note:** This is a **CLI tool** — like a Python script. **Double-clicking it will open and immediately close the window**, and no output will be visible. Always **run it from a terminal/cmd.**

### Step-by-Step (Windows):

1. Press **Windows key + R**
2. Type `cmd`, press **Enter**
3. Navigate to the folder containing the `.exe`:
   ```bat
   cd C:\Users\SnK\Downloads\ss
   ```
4. Run the command:
   ```bat
   Project2.exe list
   ```
   *(or whatever name you gave your `.exe`)*

### Step-by-Step (Linux):

```bash
cd MemoryScannerX/build
./memoryscannerx list
```

### Why Run as Admin/Root?

- Normal user permissions are sufficient for your own processes
- To view **other users' or system processes** (such as Chrome or system services) fully:
  - **Windows:** open cmd via "Run as Administrator"
  - **Linux:** `sudo ./memoryscannerx scan --all`
- Without admin/root, those processes will simply be **skipped** (no crash, no bug — this is normal, expected behavior)

---

## 📘 15. Usage — Every Command Explained

### 1️⃣ `list` — Show All Running Processes

```bash
./memoryscannerx list
```
**Purpose:** Similar to Task Manager — lists all visible processes: PID, PPID, name, architecture, executable path.

---

### 2️⃣ `inspect --pid <PID>` — Details of One Process

```bash
./memoryscannerx inspect --pid 1234
```
**Purpose:** Shows full details of a specific process: name, path, command line, user, architecture, thread count, RAM (RSS/VM size), integrity level (Windows).

**Where do I get the PID?** Run `list` first, then copy the PID from there.

---

### 3️⃣ `scan --pid <PID>` — Full Security Scan of One Process

```bash
./memoryscannerx scan --pid 1234
```
**What it does:**
- Scans memory regions
- Looks for RWX/suspicious permissions
- Checks for module anomalies
- Runs shellcode heuristics
- Calculates and displays the threat score

**Optional flags:**
```bash
./memoryscannerx scan --pid 1234 --json output.json --text output.txt
```
- `--json FILE` → Save the report as a JSON file
- `--text FILE` → Save the report as a text file

---

### 4️⃣ `scan --all` — Scan All Processes

```bash
./memoryscannerx scan --all
```
**What it does:** Scans every accessible process on the system one by one and reports any that appear suspicious.

**Optional flags:**
```bash
./memoryscannerx scan --all --min-risk medium --json full_report.json
```
- `--min-risk LEVEL` → Only show processes at or above this risk level (`low`, `medium`, `high`, `critical`)
- `--json FILE` → Save the entire report as a JSON file

---

### 5️⃣ `--help` / `-h` — Help Message

```bash
./memoryscannerx --help
```

### 6️⃣ `--version` — Show Version

```bash
./memoryscannerx --version
```

---

## 🖨️ 16. Sample Output

### Output of the `list` command:

```
PID      PPID     NAME                     ARCH     EXE
--------------------------------------------------------------------------
1        0        systemd                  x64      /usr/lib/systemd/systemd
842      1        sh                       x64      /usr/bin/dash
1055     842      chrome                   x64      /usr/bin/chrome
--------------------------------------------------------------------------
Total: 56 processes
```

### Output of `scan --pid` (clean/benign process):

```
================================================================
 MemoryScannerX Forensic Scan Report
================================================================
PID:            842
PPID:           1
Name:           sh
Executable:     /usr/bin/dash
User:           root
Architecture:   64-bit
Threads:        1
RSS:            1.93 MB

-- Memory Regions (25 total) -----------------------------------

-- Module Anomalies (0) ----------------------------------------

-- Shellcode Heuristic Findings (0) ------------------------------

-- Threat Score ----------------------------------------------------
  ------------------------------------------------------------
  TOTAL SCORE: 0   RISK LEVEL: None
================================================================
```

### Output of `scan --pid` (suspicious process — RWX memory found):

```
================================================================
 MemoryScannerX Forensic Scan Report
================================================================
PID:            9911
Name:           wx_test
Architecture:   64-bit

-- Memory Regions (12 total) -----------------------------------
  [SUSPICIOUS] 0x00007fae12340000  size=4096      perms=rwx  (anonymous)

-- Threat Score ----------------------------------------------------
  [+ 15] Executable anonymous region at 0x7fae12340000 (no backing file)
  ------------------------------------------------------------
  TOTAL SCORE: 15   RISK LEVEL: Low
================================================================
```

---

## ⚖️ 17. How Threat Scoring Works

Every suspicious finding earns **points**, and the total score is converted into a **risk level**:

| Finding | Default Points |
|---|---:|
| Writable+Executable region | +20 |
| Anonymous executable memory | +15 |
| Module anomaly (hidden/inconsistent) | +30 |
| Deleted backing file (unlinked binary) | +35 |
| Shellcode NOP-sled pattern | +25 |
| High entropy executable region | +15 |

| Total Score | Risk Level |
|---:|---|
| 0 | None |
| 1–24 | 🟢 Low |
| 25–59 | 🟡 Medium |
| 60–99 | 🟠 High |
| 100+ | 🔴 Critical |

> 💡 **Transparency Guarantee:** Every point comes attached with a **plain-language reason** — there is no "black box AI score." You can see exactly why a score was produced.

---

## ✅ 18. Advantages

1. 🪶 **Lightweight & Dependency-Free** — Only a C compiler is required, no heavy libraries to install
2. 🔓 **Fully Open-Source-Style Code** — The entire source code is available, no hidden binary blobs
3. 🖥️ **True Cross-Platform Design** — The same architecture works for both Linux and Windows
4. 🔍 **Transparent Scoring** — Every detection is explainable
5. 🛡️ **100% Read-Only / Safe** — Never modifies or harms the target process
6. 📚 **Educational Value** — Excellent for learning OS internals, memory management, and security concepts
7. ⚡ **Fast** — Efficient buffered memory reads, minimal overhead

---

## ⚠️ 19. Disadvantages / Limitations

1. 🖥️ **No GUI** — Command-line only, which may be difficult for non-technical users
2. 🪟 **Windows Path Untested** — The code has been written but not compiled/verified on a real Windows machine in this development environment
3. 🔐 **Privilege-Limited** — Without admin/root, other users' processes cannot be scanned properly
4. 🧩 **Incomplete Feature Set** — PE/ELF parsers, YARA, hook detection, and hollowing detection are not yet implemented
5. 📉 **Weaker Hidden-Module Detection on Linux** — Because both comparison "views" are derived from `/proc/maps`, a genuinely independent cross-check would require ptrace/link_map
6. 🐌 **Single-Threaded** — Concurrent/parallel scanning is not yet implemented, which may be slightly slow on larger systems

---

## 🚧 20. Cautions & Safety Notes

1. ⚠️ **Root/Administrator access** grants full system visibility — only run this tool in a **trusted environment**
2. ⚠️ Verify in a test environment before running on any **production/critical system** for the first time
3. ⚠️ `scan --all` scans **every process on the entire system** — this may temporarily use more CPU/IO on larger systems
4. ⚠️ This tool is **not a replacement for antivirus** — it is a **visibility/analysis tool** and does not automatically remove or block anything
5. ⚠️ Before running on Windows, notify your **antivirus/EDR** — memory-reading tools can sometimes trigger false-positive AV alerts (because the technique is used by both memory scanners and malware alike)
6. ⚠️ When modifying the source code, maintain the **read-only/defensive scope** — adding offensive/injection capability to this project goes against its core design principle

---

## 📜 21. Disclaimer

> This software is provided **"AS IS"**, without warranty of any kind — neither of performance nor fitness for a particular purpose. The developer (Syed Shaheer Hussain) is **not responsible** for any direct or indirect damage resulting from the use of this software.
>
> This tool is built solely for **defensive, educational, and authorized security research** purposes. Use it **only on your own systems**, or where you have **explicit permission** to do so. Scanning others' systems without permission may be **illegal** under the laws of your jurisdiction.
>
> This tool contains no offensive, exploit, or malware-generation capability — and none will be added in the future.

---

## 🎓 22. What Was Studied / Learned Building This

The following topics were studied/learned while building this project:

1. 🧠 **Operating System Internals** — Virtual memory, process management, `/proc` filesystem structure
2. 🪟 **Windows Win32 API Programming** — Toolhelp32, PSAPI, Access Tokens, Integrity Levels
3. 🐧 **Linux Systems Programming** — `/proc/pid/maps`, `process_vm_readv`, POSIX APIs
4. 🔐 **Applied Cryptography Basics** — SHA-256 algorithm (implemented from scratch, without a library)
5. 📊 **Information Theory** — Shannon entropy and its security applications
6. 🏗️ **C Systems Programming** — Manual memory management, platform abstraction (`#ifdef`), macro-based generics
7. 🛡️ **Malware Analysis Fundamentals** — RWX detection, shellcode indicators, hidden module concepts
8. 🧪 **Software Engineering Practices** — Modular architecture, unit testing, sanitizer-based debugging (ASan/UBSan)
9. 🔧 **Build Systems** — CMake configuration for cross-platform, multi-compiler projects

---

## 🚀 23. Future Enhancements & Roadmap

### Phase 2 (Planned):
- [ ] Windows PE file parser (headers, sections, imports/exports, TLS)
- [ ] Linux ELF file parser (sections, dynamic symbols, PLT/GOT)
- [ ] API hook detection (IAT/EAT/inline hooks)
- [ ] Process hollowing detection

### Phase 3 (Planned):
- [ ] YARA rule engine integration (optional, compile-time flag)
- [ ] Plugin architecture (dynamically loaded .so/.dll detectors)
- [ ] Thread-pool based concurrent multi-process scanning

### Phase 4 (Planned):
- [ ] HTML / Markdown / CSV report exporters
- [ ] Live/auto-refreshing dashboard mode (`--live` flag, Task-Manager-style continuous view)
- [ ] JSON-based external configuration file for score weights/thresholds
- [ ] GitHub Actions CI pipeline + code coverage
- [ ] Handle enumeration, code-cave detection

---

## ❓ 24. FAQ

**Q: What is this tool for?**
A: Defensive memory forensics — for malware analysis, DFIR, and learning/performing endpoint visibility.

**Q: Is this an antivirus?**
A: No. It doesn't "remove" or "block" anything — it only shows what is suspicious.

**Q: Can this harm any process?**
A: No. It has a 100% read-only design — there is no write, inject, or terminate operation anywhere in the entire codebase.

**Q: Nothing happens when I double-click it — is that a bug?**
A: No — this is a CLI tool. Run it from a terminal/cmd with a command like `.exe list`.

**Q: Has it been tested on Windows?**
A: The code has been written and designed against Windows APIs, but could not be compiled/verified on an actual Windows machine in this development environment (which was a Linux sandbox). Test carefully the first time you run it.

**Q: Can it show Chrome's saved passwords?**
A: **No, and it never will.** This feature is outside the scope of this project and has been deliberately excluded (credential harvesting risk).

---

## 🧾 25. Credits & Copyright

```
Project:      MemoryScannerX
Developed by: Syed Shaheer Hussain
Copyright:    © 2026 Syed Shaheer Hussain
License:      MIT License
Language:     ISO C17 (Pure C)
Category:     Defensive Security / Memory Forensics / DFIR Tooling
```

> Built with 🛡️ for defensive security learning and research.

---

### 📌 Quick Reference Cheat-Sheet

| Command | Purpose |
|---|---|
| `memoryscannerx list` | Show all processes |
| `memoryscannerx inspect --pid X` | Details of one process |
| `memoryscannerx scan --pid X` | Full scan of one process |
| `memoryscannerx scan --all` | Scan all processes |
| `memoryscannerx scan --all --min-risk medium` | Show only Medium+ risk processes |
| `memoryscannerx scan --pid X --json out.json` | Save the report as JSON |
| `memoryscannerx --help` | Help message |
| `memoryscannerx --version` | Show version |

**🔚 End of Documentation.**

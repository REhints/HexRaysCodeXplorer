# HexRaysCodeXplorer

```
 _   _          ______                _____           _     __   __      _
| | | |         | ___ \              /  __ \         | |    \ \ / /     | |
| |_| | _____  _| |_/ /__ _ _   _ ___| /  \/ ___   __| | ___ \ V / _ __ | | ___  _ __ ___ _ __
|  _  |/ _ \ \/ /    // _` | | | / __| |    / _ \ / _` |/ _ \/   \| '_ \| |/ _ \| '__/ _ \ '__|
| | | |  __/>  <| |\ \ (_| | |_| \__ \ \__/\ (_) | (_| |  __/ /^\ \ |_) | | (_) | | |  __/ |
\_| |_/\___/_/\_\_| \_\__,_|\__, |___/\____/\___/ \__,_|\___\/   \/ .__/|_|\___/|_|  \___|_|
                             __/ |                                | |
                            |___/                                 |_|
```

[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](http://www.gnu.org/licenses/gpl-3.0)
[![Code Climate](https://codeclimate.com/github/REhints/HexRaysCodeXplorer/badges/gpa.svg)](https://codeclimate.com/github/REhints/HexRaysCodeXplorer)
[![Issue Count](https://codeclimate.com/github/REhints/HexRaysCodeXplorer/badges/issue_count.svg)](https://codeclimate.com/github/REhints/HexRaysCodeXplorer)

**Hex-Rays Decompiler plugin for better code navigation in reverse engineering.** CodeXplorer automates C++ code reconstruction for applications and malware analysis (Stuxnet, Flame, Equation, Animal Farm, etc.).

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Building from Source](#building-from-source)
- [Usage](#usage)
- [Batch Mode](#batch-mode)
- [Contributors](#contributors)
- [Conference Talks](#conference-talks)

---

## Overview

CodeXplorer is one of the [first publicly available](https://www.hex-rays.com/products/decompiler/manual/third_party.shtml) Hex-Rays Decompiler plugins. The project has been actively maintained [since summer 2013](https://www.hex-rays.com/contests/2013/) with frequent feature updates. Key features have been presented at major security conferences including REcon, ZeroNights, H2HC, NSEC, and Black Hat USA.

### Supported Platforms

| Platform | Architectures |
|----------|---------------|
| Windows  | x86, x64      |
| Linux    | x86, x64      |
| macOS    | x86, x64      |

### Why C++ Instead of IDAPython?

All code is developed in C/C++ for better stability when supporting complex Hex-Rays Decompiler functionality.

### IDA Version Compatibility

We focus on the latest versions of IDA and the Decompiler to leverage new SDK features. Stable operation is only guaranteed on the most recent Hex-Rays products.

---

## Features

Access CodeXplorer through the right-click context menu in the Pseudocode window:

![Context Menu](img/1.jpg)

### Automatic Type Reconstruction

Reconstruct C++ object types by selecting a variable holding a pointer to an object instance, then choosing **REconstruct Type** from the context menu:

![Type Reconstruction](img/2.png)

The reconstructed structure appears in the Output window. For detailed information, see the blog post: [Type REconstruction in HexRaysCodeXplorer](http://rehints.com/2013-09-02-Type-REconstruction-in-HexRaysCodeXplorer.html).

CodeXplorer also supports automatic type reconstruction directly into IDA's local types storage:

![Local Types](img/6.png)

### Virtual Function Table Identification

Automatically identifies references to virtual function tables during type reconstruction and generates corresponding C-structures. For example, reconstructing `struct_local_data_storage` identifies two vtables and generates `struct_local_data_storage_VTABLE_0` and `struct_local_data_storage_VTABLE_4`:

![VTable Identification](img/12.png)

### C-tree Graph Visualization

Visualize the decompiled routine as a tree structure in `citem_t` terms (`hexrays.hpp`). Useful for understanding decompiler internals. The highlighted node corresponds to the cursor position in the Pseudocode window:

![C-tree Graph](img/3.png)

### Ctree Item View

Display the ctree representation for any highlighted element:

![Ctree Item View](img/16.PNG)

### Extract Ctrees to File

Calculate SHA1 hash and dump all ctrees to a file for analysis:

![Extract Ctrees](img/14.PNG)

### Extract Types to File

Export all type information (including reconstructed types) to a file.

### Virtual Function Call Navigation

Navigate through virtual function calls in the Pseudocode window. After representing C++ objects as C-structures, click on virtual function calls (structure fields) to navigate directly:

![VFunc Navigation](img/4.png)

### Jump to Disassembly

Quickly navigate from the current Pseudocode line to the corresponding assembly code in the IDA View window:

![Jump to Disasm](img/8.png)

### Object Explorer

A dedicated interface for navigating virtual table (VTBL) structures. Access via **Object Explorer** in the context menu:

![Object Explorer](img/5.png)

**Object Explorer capabilities:**

- Auto-generate VTBL structures in IDA local types
- Navigate and jump to VTBL addresses in IDA View
- Display hints for the current vtable position
- Show cross-references via "Show XREFS to VTBL"

![XREFS](img/11.png)

- Automatic RTTI object parsing:

![RTTI Parsing](img/13.png)

---

## Installation

1. Download the appropriate plugin binary for your platform from the [Releases](https://github.com/REhints/HexRaysCodeXplorer/releases) page
2. Copy the plugin file to your IDA `plugins` directory:
   - **Windows**: `%IDADIR%\plugins\`
   - **Linux**: `~/.idapro/plugins/` or `$IDADIR/plugins/`
   - **macOS**: `~/.idapro/plugins/` or `$IDADIR/plugins/`
3. Restart IDA Pro

---

## Building from Source

### Prerequisites

- IDA Pro with Hex-Rays Decompiler
- IDA SDK
- HexRays SDK (typically at `$IDADIR/plugins/hexrays_sdk`)

### Windows

1. Open the solution in Visual Studio
2. Edit `src/HexRaysCodeXplorer/PropertySheet.props` and update:
   - `IDADIR` - Path to IDA installation
   - `IDASDK` - Path to IDA SDK
3. Build configurations:
   - `Release | x64` (for 32-bit IDA)
   - `Release x64 | x64` (for 64-bit IDA)

### Linux

```bash
cd src/HexRaysCodeXplorer/

# Build
IDA_DIR=<PATH_TO_IDA> IDA_SDK=<PATH_TO_IDA_SDK> EA64=0 make -f makefile.lnx

# Install
IDA_DIR=<PATH_TO_IDA> IDA_SDK=<PATH_TO_IDA_SDK> EA64=0 make -f makefile.lnx install
```

### macOS

```bash
cd src/HexRaysCodeXplorer/

# Option 1: Using makefile
IDA_DIR=<PATH_TO_IDA> IDA_SDK=<PATH_TO_IDA_SDK> make -f makefile.mac

# Option 2: Using Xcode
open HexRaysCodeXplorer.xcodeproj
```

**Note:** For IDA 7.0+, the plugin extension should be `.dylib`.

Example with full paths:
```bash
export IDA_DIR="/Applications/IDA Pro 7.0/ida.app/Contents/MacOS"
export IDA_SDK="/Applications/IDA Pro 7.0/ida.app/Contents/MacOS/idasdk"
make -f makefile.mac
```

### CMake (Cross-platform)

```bash
cd src/HexRaysCodeXplorer/
mkdir build && cd build
cmake .. -DIdaSdk_ROOT_DIR=<PATH_TO_IDA_SDK> -DHexRaysSdk_ROOT_DIR=<PATH_TO_HEXRAYS_SDK>
cmake --build . --config Release
```

---

## Usage

1. Open a binary in IDA Pro with the Hex-Rays Decompiler
2. Navigate to the Pseudocode window (press `F5` on a function)
3. Right-click to access CodeXplorer features in the context menu
4. Use keyboard shortcuts for quick access to common features

---

## Batch Mode

Process multiple files without user interaction - useful for large-scale malware analysis. This feature was added after Black Hat 2015 research for processing 2 million samples.

**Syntax:**
```
idaq.exe -OHexRaysCodeXplorer:<options>:<function_prefix><path_to_idb>
```

**Example:** Dump types and ctrees for functions with prefix "crypto_":
```bash
idaq.exe -OHexRaysCodeXplorer:dump_types:dump_ctrees:CRYPTOcrypto_path_to_idb
```

---

## Contributors

| Name | GitHub |
|------|--------|
| Alex Matrosov | [@matrosov](https://github.com/matrosov) |
| Eugene Rodionov | [@rodionov](https://github.com/rodionov) |
| Rodrigo Branco | [@rrbranco](https://github.com/rrbranco) |
| Gabriel Barbosa | [@gabrielnb](https://github.com/gabrielnb) |

---

## Conference Talks

### 2015
- **"Distributing the REconstruction of High-Level IR for Large Scale Malware Analysis"** - Black Hat USA [[slides]](https://github.com/REhints/Publications/blob/master/Conferences/BH'2015/BH_2015.pdf)
- **"Object Oriented Code RE with HexRaysCodeXplorer"** - NSEC [[slides]](https://github.com/REhints/Publications/raw/master/Conferences/Nsec'2015/nsec_2015.pdf)

### 2014
- **"HexRaysCodeXplorer: Object Oriented RE for Fun and Profit"** - H2HC [[slides]](https://github.com/REhints/Publications/blob/master/Conferences/ZeroNights'2013/ZN_2013_pdf.pdf)

### 2013
- **"HexRaysCodeXplorer: Make Object-Oriented RE Easier"** - ZeroNights [[slides]](https://github.com/REhints/Publications/blob/master/Conferences/ZeroNights'2013/ZN_2013_pdf.pdf)
- **"Reconstructing Gapz: Position-Independent Code Analysis Problem"** - REcon [[slides]](https://github.com/REhints/Publications/blob/master/Conferences/RECON'2013/RECON_2013.pdf)

---

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](http://www.gnu.org/licenses/gpl-3.0) for details.

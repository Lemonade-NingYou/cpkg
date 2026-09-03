# cpkg – A Lightweight C Package Manager

<div align="center">
  <img src="image/cpkg icon.jpg" alt="cpkg Icon" width="200">
  
  ![License](https://img.shields.io/badge/license-GPLv3-blue.svg)
  ![Platform](https://img.shields.io/badge/platform-Linux-green.svg)
  ![Version](https://img.shields.io/badge/version-2.0.0--beta-brightgreen.svg)
  ![Status](https://img.shields.io/badge/status-public%20beta-brightgreen.svg)

**Build, install, and manage C libraries with confidence**
</div>

## Language
[English](#) | [中文](readme/md-zh_CN.md) | [Deutsch](readme/md-de_DE.md)

---

## Copyright & License

Copyright (C) 2026 Lemonade-NingYou

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

The complete license text is also available at:  
Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

---

## 🎉 Public Beta Announcement

We are thrilled to announce that **cpkg 2.0.0** is now in **Public Beta**!  

All core functionalities are fully implemented and tested:
- ✅ **Build** – package your C projects into a single `.cpl` file
- ✅ **Install** – verify and install packages to system directories
- ✅ **Remove** – cleanly uninstall packages using the recorded manifest
- ✅ **List** – view all installed packages with their metadata

The tool is ready for real-world use. We welcome your feedback and contributions.

---

## Introduction

cpkg is a lightweight C package manager that simplifies packaging, installing, and managing C libraries and headers.  

This repository contains a **completely refactored** version of cpkg, featuring a modular design, integrity checks (SHA‑256), incremental builds, and a clean manifest system.

All core subcommands (`build`, `install`, `remove`, `list`) are fully functional.

### Free Software Compliance

cpkg is **free software** under the GPLv3. All its build-time and run-time dependencies are also free software:

- `libyaml-dev` – MIT license
- `libarchive-dev` – BSD 2‑Clause license
- `libssl-dev` – OpenSSL / Apache‑style license
- `libcjson-dev` – MIT license

We are committed to ensuring that cpkg remains free and respects your freedom.

## Features

- **Build** – Package source directories into a self-contained `.cpl` file.
- **Install** – Verify and install `.cpl` packages to system directories.
- **Remove** – Uninstall packages by reading the recorded manifest.
- **List** – Show all installed packages with their metadata.
- **Integrity** – SHA‑256 hash validation prevents corruption or tampering.
- **Incremental** – Only modified files are copied during build (saves time).
- **Clean** – Automatically cleans temporary files after installation.
- **Manifest** – Records every installed file for future removal.

## Project Status

| Feature       | Status                  |
|---------------|-------------------------|
| `build`       | ✅ Complete             |
| `install`     | ✅ Complete             |
| `remove`      | ✅ Complete             |
| `list`        | ✅ Complete             |

All features are now production-ready. The project is in **public beta** – we encourage testing and reporting issues.

## Getting Started

### Build cpkg from source

```bash
git clone https://github.com/Lemonade-NingYou/cpkg.git
cd cpkg
mkdir build && cd build
cmake ..
make
sudo make install
```

### Dependencies

- `libyaml-dev` (for YAML parsing)
- `libarchive-dev` (for compression)
- `libssl-dev` (for SHA‑256)
- `libcjson-dev` (for JSON handling)

On Debian/Ubuntu:
```bash
sudo apt install libyaml-dev libarchive-dev libssl-dev libcjson-dev
```

All dependencies are freely available under open-source licenses (see above).

## Configuration File (`config.txt`)

Place a `config.txt` file in your project root. It uses **YAML** syntax.

### Example

```yaml
# config.txt - 示例配置文件（YAML格式）

PocketName: mylib
version: 1.2.3

authors:
  - Alice <alice@example.com>
  - Bob <bob@example.com>

license: MIT
description: |
  A sample library demonstrating separated include/libs.
  Supports multiple lines.
homepage: https://example.com/mylib
repository: https://github.com/example/mylib

# 分开定义 include 和 libs 的源路径
files:
  include:
    - include/*.h
  libs:
    - libs/test1.so
    - libs/test2.a

# 可选默认目录（打包后归档内的路径）
default_dirs:
  include: include
  libs: libs

# 高级选项
strict: false
flatten: false
ignore_hidden: true
follow_symlinks: false
```

### Field Reference

| Field               | Type         | Description                                                                 |
|---------------------|--------------|-----------------------------------------------------------------------------|
| `PocketName`        | String       | **Required** – Name of the package.                                         |
| `version`           | String       | **Required** – Version string.                                              |
| `authors`           | List[String] | List of authors (name <email>).                                             |
| `license`           | String       | License identifier (e.g., MIT, GPL-3.0).                                    |
| `description`       | String       | Multi‑line description of the package.                                      |
| `homepage`          | String       | Project homepage URL.                                                       |
| `repository`        | String       | Source repository URL.                                                      |
| `files.include`     | List[String] | **Glob patterns** for header files (e.g., `include/*.h`).                   |
| `files.libs`        | List[String] | **Glob patterns** for library files (e.g., `libs/*.so`).                    |
| `files.exclude`     | List[String] | (Optional) Glob patterns to exclude.                                        |
| `files.special`     | List[String] | (Optional) Special files to be handled separately.                          |
| `default_dirs.include` | String    | Destination directory for includes inside the archive (default: `include`). |
| `default_dirs.libs` | String       | Destination directory for libraries inside the archive (default: `libs`).   |
| `strict`            | Boolean      | If `true`, fail on warnings (default: `false`).                             |
| `flatten`           | Boolean      | Flatten directory structure during installation (default: `false`).         |
| `ignore_hidden`     | Boolean      | Skip hidden files (default: `true`).                                        |
| `follow_symlinks`   | Boolean      | Follow symbolic links (default: `false`).                                   |

> **Note**: Globs are expanded using `glob(3)`. Relative paths are resolved from the build directory.

## Usage

### Build a package

```bash
cpkg -b /path/to/project
```

This will:
- Read `config.txt` from that directory.
- Copy all matched files into `.cpkg/libs` and `.cpkg/include`.
- Compress the configuration and the files into a `.cpl` file.

The output file will be named `<PocketName>-<version>.cpl` in the same directory.

### Install a package

```bash
sudo cpkg -i mylib-1.2.3.cpl
```

This will:
- Validate the magic number and SHA‑256 hash.
- Decompress the configuration and the files.
- Install libraries to `/usr/lib/x86_64-linux-gnu/`.
- Install headers to `/usr/include/x86_64-linux-gnu/` **and** `/usr/include/`.
- Record all installed files in `/var/cache/cpkg/<PocketName>.json`.

> **Important**: Installation writes to system directories – you need **root privileges** (use `sudo`).

### Remove a package

```bash
sudo cpkg -r mylib
```

This will:
- Read the manifest file `/var/cache/cpkg/mylib.json`.
- Delete every file listed in `installed_files`.
- Remove the manifest file itself.

### List installed packages

```bash
cpkg -l
```

This will display all installed packages along with their metadata (name, version, authors, license, description, homepage, repository).

### Help & Version

```bash
cpkg -h   # Show help
cpkg -V   # Show version
```

## File Format (`.cpl`)

A `.cpl` file has the following structure:

| Offset | Size  | Description                         |
|--------|-------|-------------------------------------|
| 0      | 3     | Magic bytes: `"CPL"`                |
| 3      | 32    | SHA‑256 hash of the entire data block |
| 35     | 4     | Size of compressed JSON config      |
| 39     | var.  | Gzipped JSON config                 |
| ...    | 4     | Size of compressed pocket (files)   |
| ...    | var.  | Gzipped pocket (tar.gz)             |

The hash ensures the integrity of the whole data section.

## Contributing

We welcome contributions! Please follow these steps:

1. Fork the [cpkg GitHub repository](https://github.com/Lemonade-NingYou/cpkg).
2. Create a new branch for your changes.
3. Make your changes and test them thoroughly.
4. Create a pull request to the main branch.

For major changes, please open an issue first to discuss what you would like to change.

## Contact

- Project Maintainer: Lemonade-NingYou (via GitHub issues or email)
- For general questions about freedom and licensing, please refer to the [Free Software Foundation](https://www.fsf.org/).

## License

cpkg is licensed under the GPLv3 license. See the [COPYING](COPYING) file for the full text, or visit <https://www.gnu.org/licenses/>.
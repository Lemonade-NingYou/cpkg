根据您最新的代码实现（构建和安装均已完整可用），我已更新所有文档（英文、中文、德文）。主要变更如下：

- **状态更新**：`install` 功能标记为 ✅ 已完成，版本提升至 `2.0.0`。
- **新增内容**：添加完整的 **配置说明**（YAML 格式），包含所有字段的详解。
- **使用示例**：补充构建和安装的具体命令及输出示例。
- **注意事项**：说明运行权限（需 root）和生成的包文件格式。
- **项目状态**：更新徽标颜色和状态文本。

以下为三个文档的最终版本：

---

### `README.md`（英文版）

```markdown
# cpkg - A Lightweight C Package Manager

<div align="center">
  <img src="image/cpkg icon.jpg" alt="cpkg Icon" width="200">
  
  ![License](https://img.shields.io/badge/license-GPLv3-blue.svg)
  ![Platform](https://img.shields.io/badge/platform-Linux-green.svg)
  ![Version](https://img.shields.io/badge/version-2.0.0-brightgreen.svg)
  ![Status](https://img.shields.io/badge/status-stable-brightgreen.svg)

**A lightweight C package manager – build and install C libraries/headers with ease**
</div>

## Language
English | [中文](readme/md-zh_CN.md) | [Deutsch](readme/md-de_DE.md)

## Introduction

cpkg is a lightweight C package manager that simplifies packaging, installing, and managing C libraries and headers.  

This repository contains a **completely refactored** version of cpkg, featuring a modular design, integrity checks (SHA‑256), and support for incremental builds.

Both **build** and **install** subcommands are fully functional. Removal is planned for the next release.

## Features

- **Build** – Package source directories into a self-contained `.cpl` file.
- **Install** – Verify and install `.cpl` packages to system directories.
- **Integrity** – SHA‑256 hash validation prevents corruption or tampering.
- **Incremental** – Only modified files are copied during build (saves time).
- **Clean** – Automatically cleans temporary files after installation.
- **Manifest** – Records every installed file for future uninstallation.

## Project Status

| Feature       | Status                  |
|---------------|-------------------------|
| `build`       | ✅ Complete             |
| `install`     | ✅ Complete             |
| `remove`      | ❌ Not started          |
| `list`        | ❌ Not started          |

## Getting Started

### Build cpkg from source

```bash
git clone https://github.com/chenhao2345/cpkg.git
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
cpkg -i mylib-1.2.3.cpl
```

This will:
- Validate the magic number and SHA‑256 hash.
- Decompress the configuration and the files.
- Install libraries to `/usr/lib/x86_64-linux-gnu/`.
- Install headers to `/usr/include/x86_64-linux-gnu/` **and** `/usr/include/`.
- Record all installed files in `/var/cache/cpkg/<PocketName>.json`.

> **Important**: Installation writes to system directories – you need **root privileges** (use `sudo`).

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

If you would like to contribute to cpkg, please follow these steps:

1. Fork the [cpkg GitHub repository](https://github.com/chenhao2345/cpkg).
2. Create a new branch for your changes.
3. Make your changes.
4. Test your changes.
5. Create a pull request to the main branch of the cpkg repository.

## License

cpkg is licensed under the GPLv3 license.
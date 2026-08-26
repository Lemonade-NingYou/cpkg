# cpkg - A Lightweight C Package Manager

<div align="center">
  <img src="image/cpkg icon.jpg" alt="cpkg Icon" width="200">
  
  ![License](https://img.shields.io/badge/license-GPLv3-blue.svg)
  ![Platform](https://img.shields.io/badge/platform-Linux-green.svg)
  ![Version](https://img.shields.io/badge/version-1.0-orange.svg)
  ![Status](https://img.shields.io/badge/status-refactoring-yellow.svg)

**A lightweight C package manager – currently undergoing a major refactoring**
</div>

## Language
English | [中文](readme/md-zh_CN.md) | [Deutsch](readme/md-de_DE.md)

## Introduction

cpkg is a lightweight C package manager designed to simplify the installation, update, and removal of C libraries and headers.  

This repository contains a **low-level refactoring** of the original cpkg. The codebase has been reorganised, and the build pipeline is being rewritten for better modularity, security, and performance.  

At this stage, only the **package building** functionality is fully implemented. The installation subsystem is under active development and is not yet functional.

## Features and Goals

- **Build** a package from a source directory into a `.cpl` package file (working)
- **Install** a `.cpl` package into the system (in progress)
- Simple command-line interface
- Cross-platform support (Linux, macOS, Windows – planned)

## Project Status

| Feature       | Status                  |
|---------------|-------------------------|
| `build`       | ✅ Complete             |
| `install`     | 🚧 Under development   |
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

### Usage

Currently, the only fully supported command is:

```bash
cpkg -b <build-directory>
```

This will read `config.txt` from the specified directory, package the specified libraries and headers, and produce a `.cpl` file.

The install command is partially implemented but **not yet functional**:

```bash
cpkg -i <package.cpl>   # (not ready)
```

Additional options:

```bash
cpkg -h                 # Show help
cpkg -V                 # Show version
```

## Contributing

If you would like to contribute to cpkg, please follow these steps:

1. Fork the [cpkg GitHub repository](https://github.com/chenhao2345/cpkg).
2. Create a new branch for your changes.
3. Make your changes.
4. Test your changes.
5. Create a pull request to the main branch of the cpkg repository.

## License

cpkg is licensed under the GPLv3 license.
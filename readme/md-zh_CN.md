# cpkg - 一个轻量级的 C 包管理器

<div align="center">
  <img src="../image/cpkg icon.jpg" alt="cpkg Icon" width="200">
  
  ![License](https://img.shields.io/badge/license-GPLv3-blue.svg)
  ![Platform](https://img.shields.io/badge/platform-Linux-green.svg)
  ![Version](https://img.shields.io/badge/version-1.0-orange.svg)
  ![Status](https://img.shields.io/badge/status-重构中-yellow.svg)

**一个轻量级的 C 包管理器 – 正在进行底层重构**
</div>

## 语言
[English](../README.md) | 中文 | [Deutsch](md-de_DE.md)

## 介绍

cpkg 是一个轻量级的 C 包管理器，旨在简化 C 库和头文件的安装、更新和卸载。

本仓库是 cpkg 的**底层重构版本**，代码结构已重新组织，构建流程正在重写，以提高模块化、安全性和性能。

目前，**构建（build）** 功能已完整实现，安装（install）子系统正在开发中，尚不可用。

## 特性与目标

- **构建**：从源码目录构建 `.cpl` 包文件（已完成）
- **安装**：将 `.cpl` 包安装到系统中（开发中）
- 简单的命令行界面
- 跨平台支持（Linux、macOS、Windows – 计划中）

## 项目状态

| 功能         | 状态                  |
|--------------|-----------------------|
| `build`      | ✅ 已完成             |
| `install`    | 🚧 开发中             |
| `remove`     | ❌ 未开始             |
| `list`       | ❌ 未开始             |

## 安装与使用

### 从源码构建 cpkg

```bash
git clone https://github.com/chenhao2345/cpkg.git
cd cpkg
mkdir build && cd build
cmake ..
make
sudo make install
```

### 使用方法

当前唯一完全支持的命令是：

```bash
cpkg -b <构建目录>
```

该命令会读取指定目录下的 `config.txt`，打包指定的库和头文件，并生成一个 `.cpl` 文件。

安装命令部分实现，但**尚未可用**：

```bash
cpkg -i <package.cpl>   # (未完成)
```

其他选项：

```bash
cpkg -h                 # 显示帮助
cpkg -V                 # 显示版本号
```

## 贡献

如果您想为 cpkg 做出贡献，请按以下步骤操作：

1. Fork [cpkg GitHub 仓库](https://github.com/chenhao2345/cpkg)。
2. 创建一个新的分支用于您的修改。
3. 进行修改。
4. 测试您的修改。
5. 提交一个 pull request 到 cpkg 仓库的主分支。

## 许可证

cpkg 使用 GPLv3 许可证。
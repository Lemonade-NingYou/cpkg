# cpkg - 一个轻量级的 C 包管理器

<div align="center">
  <img src="../image/cpkg icon.jpg" alt="cpkg Icon" width="200">
  
  ![License](https://img.shields.io/badge/license-GPLv3-blue.svg)
  ![Platform](https://img.shields.io/badge/platform-Linux-green.svg)
  ![Version](https://img.shields.io/badge/version-2.0.0--beta-brightgreen.svg)
  ![Status](https://img.shields.io/badge/status-公测版-brightgreen.svg)

**轻松构建、安装和管理 C 库**
</div>

## 语言
[English](../README.md) | 中文 | [Deutsch](md-de_DE.md)

---

## 🎉 公测版发布公告

我们很高兴宣布 **cpkg 2.0.0** 现已进入 **公测版**！

所有核心功能均已完整实现并通过测试：
- ✅ **构建** – 将您的 C 项目打包成单个 `.cpl` 文件
- ✅ **安装** – 验证并安装包到系统目录
- ✅ **卸载** – 根据记录清单干净地卸载包
- ✅ **列表** – 查看所有已安装的包及其元数据

该工具已可用于实际场景，欢迎反馈和贡献。

---

## 介绍

cpkg 是一个轻量级的 C 包管理器，用于简化 C 库和头文件的打包、安装与管理。

本仓库是 cpkg 的**完全重构版**，采用模块化设计，支持完整性校验（SHA‑256）、增量构建和清单系统。

## 特性

- **构建** – 将源码目录打包为自包含的 `.cpl` 文件。
- **安装** – 验证并安装 `.cpl` 包到系统目录。
- **卸载** – 通过读取记录清单删除已安装文件。
- **列表** – 显示所有已安装包及其元数据。
- **完整性** – SHA‑256 哈希校验防止损坏或篡改。
- **增量** – 构建时仅复制修改过的文件（节省时间）。
- **清理** – 安装后自动清除临时文件。
- **清单** – 记录每个已安装文件，便于未来卸载。

## 项目状态

| 功能         | 状态                  |
|--------------|-----------------------|
| `build`      | ✅ 已完成             |
| `install`    | ✅ 已完成             |
| `remove`     | ✅ 已完成             |
| `list`       | ✅ 已完成             |

所有功能均已达到生产就绪状态，项目处于 **公测版**，欢迎测试和反馈问题。

## 从源码构建

```bash
git clone https://github.com/chenhao2345/cpkg.git
cd cpkg
mkdir build && cd build
cmake ..
make
sudo make install
```

### 依赖项

- `libyaml-dev`（YAML 解析）
- `libarchive-dev`（压缩）
- `libssl-dev`（SHA‑256）
- `libcjson-dev`（JSON 处理）

Debian/Ubuntu 安装命令：
```bash
sudo apt install libyaml-dev libarchive-dev libssl-dev libcjson-dev
```

## 配置文件（`config.txt`）

在项目根目录放置 `config.txt`，采用 **YAML** 语法。

### 示例

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

### 字段说明

| 字段                   | 类型         | 描述                                                                 |
|------------------------|--------------|----------------------------------------------------------------------|
| `PocketName`           | 字符串       | **必需** – 包名。                                                    |
| `version`              | 字符串       | **必需** – 版本号。                                                  |
| `authors`              | 字符串列表   | 作者列表（姓名 <邮箱>）。                                            |
| `license`              | 字符串       | 许可证标识（如 MIT、GPL-3.0）。                                      |
| `description`          | 字符串       | 多行描述。                                                           |
| `homepage`             | 字符串       | 项目主页 URL。                                                       |
| `repository`           | 字符串       | 源码仓库 URL。                                                       |
| `files.include`        | 字符串列表   | **通配符模式**，指定头文件（如 `include/*.h`）。                     |
| `files.libs`           | 字符串列表   | **通配符模式**，指定库文件（如 `libs/*.so`）。                       |
| `files.exclude`        | 字符串列表   | （可选）排除模式。                                                   |
| `files.special`        | 字符串列表   | （可选）特殊文件，单独处理。                                         |
| `default_dirs.include` | 字符串       | 归档内头文件的目标目录（默认：`include`）。                          |
| `default_dirs.libs`    | 字符串       | 归档内库文件的目标目录（默认：`libs`）。                             |
| `strict`               | 布尔值       | 若为 `true`，遇到警告则失败（默认：`false`）。                      |
| `flatten`              | 布尔值       | 安装时展平目录结构（默认：`false`）。                                |
| `ignore_hidden`        | 布尔值       | 忽略隐藏文件（默认：`true`）。                                       |
| `follow_symlinks`      | 布尔值       | 跟随符号链接（默认：`false`）。                                      |

> **注意**：通配符使用 `glob(3)` 展开，相对路径基于构建目录解析。

## 使用方法

### 构建包

```bash
cpkg -b /path/to/project
```

该命令将：
- 读取指定目录中的 `config.txt`。
- 将所有匹配的文件复制到 `.cpkg/libs` 和 `.cpkg/include`。
- 压缩配置和文件，生成 `.cpl` 文件。

输出文件为 `<PocketName>-<version>.cpl`，位于同一目录。

### 安装包

```bash
sudo cpkg -i mylib-1.2.3.cpl
```

该命令将：
- 验证魔术字和 SHA‑256 哈希。
- 解压配置和文件。
- 将库文件安装到 `/usr/lib/x86_64-linux-gnu/`。
- 将头文件安装到 `/usr/include/x86_64-linux-gnu/` **和** `/usr/include/`。
- 记录所有已安装文件到 `/var/cache/cpkg/<PocketName>.json`。

> **重要**：安装会写入系统目录，需要 **root 权限**（使用 `sudo`）。

### 卸载包

```bash
sudo cpkg -r mylib
```

该命令将：
- 读取记录文件 `/var/cache/cpkg/mylib.json`。
- 删除 `installed_files` 中列出的所有文件。
- 删除记录文件本身。

### 列出已安装的包

```bash
cpkg -l
```

将显示所有已安装包及其元数据（名称、版本、作者、许可证、描述、主页、仓库）。

### 帮助与版本

```bash
cpkg -h   # 显示帮助
cpkg -V   # 显示版本号
```

## 文件格式（`.cpl`）

`.cpl` 文件的结构如下：

| 偏移 | 大小  | 描述                               |
|------|-------|------------------------------------|
| 0    | 3     | 魔术字：`"CPL"`                    |
| 3    | 32    | 整个数据块的 SHA‑256 哈希          |
| 35   | 4     | 压缩的 JSON 配置大小               |
| 39   | 可变  | gzip 压缩的 JSON 配置              |
| ...  | 4     | 压缩的 pocket（文件）大小          |
| ...  | 可变  | gzip 压缩的 pocket（tar.gz）       |

哈希确保整个数据部分的完整性。

## 贡献

如果您想贡献代码，请按以下步骤操作：

1. Fork [cpkg GitHub 仓库](https://github.com/chenhao2345/cpkg)。
2. 为您的修改创建新分支。
3. 进行修改并充分测试。
4. 提交 pull request 到主分支。

## 许可证

cpkg 使用 GPLv3 许可证。
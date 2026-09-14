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

## 版权与许可证

版权所有 (C) 2026 Lemonade-NingYou

本程序是自由软件：您可以根据自由软件基金会发布的 GNU 通用公共许可证（GPL）第 3 版或（您选择的）任何后续版本的条款重新分发和/或修改它。

本程序分发的目的是希望它有用，但**没有任何担保**；甚至没有适销性或特定用途适用性的隐含担保。详情请参阅 GNU 通用公共许可证。

您应该已经随本程序收到了一份 GNU 通用公共许可证的副本。如果没有，请访问 <https://www.gnu.org/licenses/>。

完整许可证文本也可从以下地址获取：  
Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA。

---

## 🎉 公测版发布公告

我们很高兴宣布 **cpkg 2.0.0** 现已进入 **公测版**！

所有核心功能均已完整实现并通过测试：
- ✅ **构建** – 将您的 C 项目打包成单个 `.cpl` 文件
- ✅ **安装** – 验证并安装包到系统目录
- ✅ **卸载** – 根据记录清单干净地卸载包
- ✅ **列表** – 查看所有已安装的包及其元数据
- ✅ **手册** – 查看每个包的手册，支持 Markdown 渲染与 C 语法高亮

该工具已可用于实际场景，欢迎反馈和贡献。

---

## 介绍

cpkg 是一个轻量级的 C 包管理器，用于简化 C 库、头文件和手册的打包、安装与管理。

本仓库是 cpkg 的**完全重构版**，采用模块化设计，支持完整性校验（SHA‑256）、增量构建和清单系统。

### 自由软件合规性

cpkg 是 **自由软件**，采用 GPLv3 许可证。其所有构建时和运行时依赖均为自由软件：

- `libyaml-dev` – MIT 许可证
- `libarchive-dev` – BSD 2‑Clause 许可证
- `libssl-dev` – OpenSSL / Apache‑风格许可证
- `libcjson-dev` – MIT 许可证

我们致力于确保 cpkg 保持自由，并尊重您的自由。

## 特性

- **构建** – 将源码目录打包为自包含的 `.cpl` 文件。
- **安装** – 验证并安装 `.cpl` 包到系统目录。
- **卸载** – 通过读取记录清单删除已安装文件。
- **列表** – 显示所有已安装包及其元数据。
- **手册** – 渲染每个包的手册，支持 Markdown（标题、行内代码、加粗、斜体、删除线、链接、围栏代码块）与 C 语法高亮。
- **完整性** – SHA‑256 哈希校验防止损坏或篡改。
- **增量** – 构建时仅复制修改过的文件（节省时间）。
- **清理** – 安装后自动清除临时文件。
- **清单** – 记录每个已安装文件，便于未来卸载。
- **安全** – 解压时防止路径穿越，卸载时使用前缀白名单。

## 项目状态

| 功能         | 状态                  |
|--------------|-----------------------|
| `build`      | ✅ 已完成             |
| `install`    | ✅ 已完成             |
| `remove`     | ✅ 已完成             |
| `list`       | ✅ 已完成             |
| `manual`     | ✅ 已完成             |

所有功能均已达到生产就绪状态，项目处于 **公测版**，欢迎测试和反馈问题。

## 从源码构建

```bash
git clone https://github.com/Lemonade-NingYou/cpkg.git
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

所有依赖均以开源许可证自由提供（见上文）。

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
  A sample library demonstrating separated include/libs/manual.
  Supports multiple lines.
homepage: https://example.com/mylib
repository: https://github.com/example/mylib

# 分开定义 include、libs 和 manual 的源路径
files:
  include:
    - include/*.h
  libs:
    - libs/test1.so
    - libs/test2.a
  manual:
    - docs/manual.txt

# 可选默认目录（打包后归档内的路径）
default_dirs:
  include: include
  libs: libs
  manual: docs

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
| `files.manual`         | 字符串列表   | **通配符模式**，指定手册文件（如 `docs/manual.txt`）。               |
| `files.exclude`        | 字符串列表   | （可选）排除模式。                                                   |
| `files.special`        | 字符串列表   | （可选）特殊文件，单独处理。                                         |
| `default_dirs.include` | 字符串       | 归档内头文件的目标目录（默认：`include`）。                          |
| `default_dirs.libs`    | 字符串       | 归档内库文件的目标目录（默认：`libs`）。                             |
| `default_dirs.manual`  | 字符串       | 归档内手册文件的目标目录（默认：`manual`）。                         |
| `strict`               | 布尔值       | 若为 `true`，遇到警告则失败（默认：`false`）。                      |
| `flatten`              | 布尔值       | 安装时展平目录结构（默认：`false`）。                                |
| `ignore_hidden`        | 布尔值       | 忽略隐藏文件（默认：`true`）。                                      |
| `follow_symlinks`      | 布尔值       | 跟随符号链接（默认：`false`）。                                      |

> **注意**：通配符使用 `glob(3)` 展开，相对路径基于构建目录解析。

## 使用方法

### 构建包

```bash
cpkg -b /path/to/project
```

该命令将：
- 读取指定目录中的 `config.txt`。
- 将所有匹配的文件复制到 `.cpkg/libs`、`.cpkg/include` 和 `.cpkg/manual`。
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
- 将手册安装到 `/usr/share/cpkg/manual/<PocketName>/`。
- 记录所有已安装文件到 `/var/cache/cpkg/<PocketName>.json`。

> **重要**：安装会写入系统目录，需要 **root 权限**（使用 `sudo`）。

### 卸载包

```bash
sudo cpkg -r mylib
```

该命令将：
- 读取记录文件 `/var/cache/cpkg/mylib.json`。
- 删除 `installed_files` 中列出的所有文件（带路径前缀白名单校验）。
- 删除记录文件本身。

### 列出已安装的包

```bash
cpkg -l
```

将显示所有已安装包及其元数据（名称、版本、作者、许可证、描述、主页、仓库）。

### 查看包手册

```bash
cpkg -m mylib
```

将渲染 `/usr/share/cpkg/manual/mylib/manual.txt`，支持：

- Markdown 标题（`#` 到 `######`），每级样式不同。
- 行内代码 `` `code` `` 显示为灰色。
- **加粗**、*斜体*、~~删除线~~。
- `[文字](url)` 链接。
- 围栏代码块内 C 语法高亮（关键字、类型、字符串、数字、注释、预处理指令、函数名、变量名）。

### 帮助与版本

```bash
cpkg -h   # 显示帮助
cpkg -V   # 显示版本号
```

## 文件格式（`.cpl`）

`.cpl` 文件的结构如下：

| 偏移 | 大小  | 描述                               |
|------|-------|------------------------------------|
| 0    | 4     | 魔术字：`"CPKG"`                   |
| 4    | 32    | 整个数据块的 SHA‑256 哈希          |
| 36   | 4     | 压缩的 JSON 配置大小               |
| 40   | 可变  | gzip 压缩的 JSON 配置              |
| ...  | 4     | 压缩的 pocket（文件）大小          |
| ...  | 可变  | gzip 压缩的 pocket（tar.gz，包含 `libs/`、`include/`、`manual/`） |

哈希确保整个数据部分的完整性。

## 本次修复的问题

- **`VerifyMagic` 双重 `fclose`** – `VerifyMagic` 不再关闭流，由调用者统一关闭一次。
- **`install_dir_to_multi` 相对路径丢失** – 安装时保留源目录结构，不再把所有文件平铺到 basename。
- **`--list` 选项类型** – `--list` 改为 `no_argument`，与 `-l` 一致。
- **`outerror` 缺少错误码** – 补充 `ReadRecordInformationError`、`RemoveFilesError`、`CreateManualDir`、`ManualNotExist`、`InstallManualsError`。
- **路径穿越保护** – `DecompressPocketToDir` 拒绝绝对路径和 `../` 条目。
- **任意文件删除** – `CPKG_remove` 在 `unlink` 前校验路径前缀白名单（`/usr/lib/`、`/usr/include/`、`/usr/share/cpkg/manual/`）。

## 贡献

如果您想贡献代码，请按以下步骤操作：

1. Fork [cpkg GitHub 仓库](https://github.com/Lemonade-NingYou/cpkg)。
2. 为您的修改创建新分支。
3. 进行修改并充分测试。
4. 提交 pull request 到主分支。

重大更改请先创建议题讨论。

## 联系方式

- 项目维护者：Lemonade-NingYou（通过 GitHub 议题或邮件）
- 关于自由软件和许可的通用问题，请参考[自由软件基金会](https://www.fsf.org/)。

## 许可证

cpkg 使用 GPLv3 许可证。完整文本请参见 [COPYING](COPYING) 文件，或访问 <https://www.gnu.org/licenses/>。
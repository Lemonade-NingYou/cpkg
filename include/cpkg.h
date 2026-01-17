/*
 * Copyright (C) 2025 lemonade_NingYou
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef CPKG_H
#define CPKG_H

#include <stdio.h>
#include <stdint.h>

// ========================== 魔术字定义 ==========================
#define CPK_MAGIC "CPK\x01"             // CPK 魔术字
#define CPK_MAGIC_LEN 4                 // 魔术字长度  
#define CPK_HEADER_SIZE sizeof(CPK_Header)  // 头部大小

// ========================== 通用常量 ==========================
#define MAX_PATH_LEN 1024               // 最大路径长度
#define MAX_LINE_LEN 512                // 最大行长度
#define WORK_DIR "/usr/bin/cpkg"       // 工作目录
#define INSTALL_DIR "installed"   // 软件包安装目录
#define INSTALLED_LOG_FILE "installed.file"   // 已安装包文件
#define MAX_COMMAND_LEN 4096            // 最大命令长度

// ========================== 控制文件名 ==========================
#define META_DIR "CPKG"               // 元数据目录
#define CONTROL_FILE "control"          // 包含软件包最基本的元数据
#define INSTALL_SCRIPT "install.sh"        // 安装脚本
#define REMOVE_SCRIPT "remove.sh"        // 卸载脚本
#define CONFFILES_LIST "conffiles"      // 应被视为配置文件的文件列表
#define MD5SUMS_FILE "md5sums"          // 文件MD5校验和
#define COPYRIGHT_FILE "copyright"      // 版权和许可证信息
#define CHANGELOG_FILE "changelog"      // 变更历史
#define TEMPLATES_FILE "templates"      // debconf模板文件
#define CONFIG_SCRIPT "config"          // debconf配置脚本

// ========================== 数据结构 ===========================
typedef struct {
    char magic[4];           // 魔术字 "CPK\x01"
    char path[256];        // 软件包路径，例如"./mypackage/"
    char name[64];          // 软件包名称
    uint32_t version;        // 版本号
    unsigned char hash[32];  // 哈希值（SHA256）
    char description[256];  // 软件包描述
    char author[64];       // 作者信息
    char license[64];      // 许可证信息
    char reserved[64];       // 保留字段
} CPK_Header;

// ======================== 内部函数声明 =========================
int check_sudo_privileges(void); // 检查 sudo 权限
int read_cpk_header(FILE *pkg_file, CPK_Header *header); // 读取 CPK 头部
int check_hash(FILE *pkg_file, const unsigned char *expected_hash); // 检查哈希值
int uncompress_package(FILE *pkg_file, const char *install_dir); // 解压缩软件包内容
int execute_script(const char *script_path); // 执行脚本文件
int confirm_package_action(const char *pkg_name, const char *action); // 确认安装（移除）单个软件包
// ========================== 函数声明 ===========================
int info_package(const char *pkg_path);         // 查询软件包信息
int install_package(const char *pkg_path);      // 安装单个软件包
int remove_package(const char *pkg_name);       // 移除单个软件包

#endif // CPKG_H
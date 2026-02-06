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

// ========================== 结构体定义 ==========================
typedef struct {
    char packet[64];           // 库名称
    char version[64];          // 版本
    char brief[256];           // 描述
    char include[10][256];     // 头文件位置，最多10个
    int include_count;         // 头文件数量
    char lib[10][256];         // 库所在目录或文件，最多10个
    int lib_count;            // 库数量
    char include_path[256];    // 安装位置，空字符串表示NULL/默认位置
    char lib_path[256];        // 安装位置，空字符串表示NULL/默认位置
    int packet_set;           // 标记字段是否已设置
    int version_set;
    int brief_set;
    int include_set;
    int lib_set;
    int include_path_set;
    int lib_path_set;
} ControlInfo;

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
// int add_directory_to_archive_recursive(struct archive *a, const char *base_dir, const char *current_dir, int depth); // 递归添加目录到归档
int compress_package(FILE *pkg_file, const char *install_dir); // 压缩目录内容
int uncompress_package(FILE *pkg_file, const char *install_dir); // 解压缩软件包内容
int copy_files(const char *src_dir, const char *dst_dir); // 复制文件到指定目录
int create_directory(const char *dir_path); // 创建目录
int remove_directory(const char *dir_path); // 删除目录
int execute_script(const char *script_path); // 执行脚本文件
int confirm_package_action(const char *pkg_name, const char *action); // 确认安装（移除）单个软件包
int parse_control_file(const char *control_path, ControlInfo *info); // 解析控制文件
int parse_list(const char* value, char list[][256], int *count); // 解析列表
int parse_path_call(const char* line, char* func_name, char* path); // 解析路径函数调用
void print_control_info(const ControlInfo* info); // 打印控制信息
int create_script(const char* build_path, const char* control_file_path, const ControlInfo* info); // 创建安装/卸载脚本

// ========================== 函数声明 ===========================
int info_package(const char *pkg_path);         // 查询软件包信息
int install_package(const char *pkg_path);      // 安装单个软件包
int remove_package(const char *pkg_name);       // 移除单个软件包
int build_package(const char *build_path);        // 构建软件包

#endif // CPKG_H
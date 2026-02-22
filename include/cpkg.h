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
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

/* 路径和目录定义 */
#define MAX_PATH_LEN       1024    /**< 最大路径长度 */
#define CONTROL            "control"   /**< 控制文件名 */
#define META_DIR_NAME      "CPKG"      /**< 元数据目录名 */
#define WORK_DIR_NAME      "/usr/cpkg-work" /**< 工作目录名 */
#define INSTALL_DIR        "installed" /**< 安装目录名 */

/**
 * 控制信息结构体，从 control 文件中解析得到
 */
typedef struct {
    char name[MAX_PATH_LEN];               /**< 包名 */
    char version[MAX_PATH_LEN];            /**< 版本号 */
    char description[MAX_PATH_LEN];        /**< 描述 */
    char homepage[MAX_PATH_LEN];           /**< 主页 */
    char author[MAX_PATH_LEN];             /**< 作者 */
    char license[MAX_PATH_LEN];            /**< 许可证 */
    char include_install_path[MAX_PATH_LEN]; /**< 头文件安装路径 */
    char lib_install_path[MAX_PATH_LEN];   /**< 库文件安装路径 */
    char **include_files;                   /**< 头文件列表（动态数组） */
    char **lib_files;                       /**< 库文件列表（动态数组） */
    int include_file_count;                 /**< 头文件数量 */
    int lib_file_count;                      /**< 库文件数量 */
} Control_Info;

/**
 * CPK 包头部结构，位于 .cpk 文件开头
 */
typedef struct {
    char magic[4];                           /**< 魔数，应为 "CPKG" */
    char hash[65];                           /**< 哈希值（SHA256，十六进制字符串） */
    char name[MAX_PATH_LEN];                 /**< 包名 */
    char version[MAX_PATH_LEN];              /**< 版本号 */
    char description[MAX_PATH_LEN];          /**< 描述 */
    char homepage[MAX_PATH_LEN];             /**< 主页 */
    char author[MAX_PATH_LEN];                /**< 作者 */
    char license[MAX_PATH_LEN];               /**< 许可证 */
    char include_install_path[3 * MAX_PATH_LEN]; /**< 头文件安装路径（扩展） */
    char lib_install_path[3 * MAX_PATH_LEN];      /**< 库文件安装路径（扩展） */
} CPK_Header;

/* 权限与交互 */
int check_sudo_privileges(void);               /**< 检查是否有 root 权限 */
int tf_choose(const char *msg);                 /**< 询问用户 yes/no */

/* 文件和目录操作 */
int mkdir_p(const char *path, mode_t mode);     /**< 递归创建目录 */
int cp_file(const char *src_file, const char *dst_dir); /**< 复制文件到目标目录 */
int rm_rf(const char *del_dir);                 /**< 递归删除文件/目录 */
int extract_archive(FILE *fp, const char *dest); /**< 从 FILE* 解压 tar.gz 到目标目录 */
char *archive_create_tgz(const char *src_dir, size_t *out_len); /**< 创建 tar.gz 压缩包并返回内存数据 */ 
char **collect_files(const char *dir_path, int *count);   /**< 收集目录下所有文件名 */
int write_install_file(FILE *install_info, CPK_Header *header, int include_file_count, char **include_file_list, int lib_file_count, char **lib_file_list);    /**< 写入安装信息到文件 */
int read_install_file(FILE *install_info, CPK_Header *header, int *include_file_count, char ***include_file_list, int *lib_file_count, char ***lib_file_list);    /**< 读取安装信息文件 */

/* 包信息处理 */
CPK_Header *make_Header(Control_Info *ctrl_info); /**< 从 Control_Info 创建 CPK_Header */
char *sha256_mem(const unsigned char *data, size_t len); /**< 计算内存数据的 SHA256 哈希值 */
Control_Info *read_control_info(FILE *fp);        /**< 读取并解析 control 文件 */
void printf_control_info(Control_Info *ctrl_info); /**< 打印控制信息 */
off_t get_file_size(const char *path);            /**< 获取文件大小 */

/* 包管理命令 */
int install_package(const char *pkg_path);        /**< 安装 .cpk 包 */
int remove_package(const char *pkg_name);         /**< 移除已安装的包 */
int make_build_package(const char *package_path_dir); /**< 构建包（从目录生成 .cpk） */
int cpkg_list(void);                            /**< 列出已安装的包 */

#endif /* CPKG_H */
/*
 * Copyright (C) 2026 Lemonade-NingYou
 *
 * This file is part of cpkg.
 *
 * cpkg is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * cpkg is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with cpkg. If not, see <https://www.gnu.org/licenses/>.
 */
#ifndef UTILS_H
#define UTILS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>

#define MAGIC      "CPL"          ///< .cpl 包魔数字符串
#define MAGIC_LEN  3              ///< 魔数长度
#define SHA256_LEN 32             ///< SHA‑256 摘要长度（字节）
#define CHUNK_SIZE 4096           ///< 复制文件时的缓冲区大小
#define WORK_DIR   "/var/cache/cpkg" ///< CPKG 工作目录（存放记录和临时文件）
#define TEMP_PATH  WORK_DIR "/temp/" ///< 安装时解压临时目录
#define LOCKFILE_PATH WORK_DIR "/lock" ///< 进程锁文件路径

/**
 * @brief 配置结构体，存储从 config.txt 解析的所有信息。
 * 对应 YAML 格式中的字段，用于构建和安装。
 */
typedef struct Config {
    char PocketName[64];           ///< 包名（必填）
    char version[32];              ///< 版本号（必填）
    char** authors;                ///< 作者列表（字符串数组）
    int author_count;              ///< 作者数量
    char license[64];              ///< 许可证
    char description[512];         ///< 描述
    char homepage[128];            ///< 项目主页
    char repository[128];          ///< 源码仓库

    // files 部分：匹配模式
    char** include_patterns;       ///< 头文件匹配模式（glob）
    int include_count;             ///< 匹配模式数量
    char** lib_patterns;           ///< 库文件匹配模式（glob）
    int lib_count;                 ///< 匹配模式数量
    char** exclude_patterns;       ///< 排除模式（暂未使用）
    int exclude_count;
    char** special_files;          ///< 特殊文件（暂未使用）
    int special_count;

    // default_dirs：构建时的相对路径
    char default_libs_dir[64];     ///< 库文件默认源目录（默认 "libs"）
    char default_include_dir[64];  ///< 头文件默认源目录（默认 "include"）

    // 高级选项
    bool strict;                   ///< 严格模式（暂未使用）
    bool flatten;                  ///< 是否扁平化目录（暂未使用）
    bool ignore_hidden;            ///< 忽略隐藏文件（默认 true）
    bool follow_symlinks;          ///< 是否跟随符号链接（默认 false）
} Config;

/**
 * @brief 安装文件列表，用于记录已安装的绝对路径。
 */
typedef struct {
    char **paths;                  ///< 路径字符串数组
    int count;                     ///< 当前数量
    int capacity;                  ///< 分配容量
} InstallList;

/* ---------- 配置解析与转换 ---------- */
Config* ReadConfig(const char* ConfigPath);                ///< 从 YAML 文件读取配置
void FreeConfig(Config* config);                          ///< 释放 Config 及其内部数组
char* ChangeStructToJson(const Config* config);           ///< 将 Config 转为 JSON 字符串（用于打包）

/* ---------- 文件/目录操作 ---------- */
bool is_dir(const char* path);                            ///< 判断是否为目录
bool get_file_size(const char* path, uint64_t* size);     ///< 获取普通文件大小
bool get_directory_size(const char* path, uint64_t* total); ///< 递归计算目录总大小
int copy_path_incremental(const char* src, const char* dst_base); ///< 增量复制文件或目录
int remove_directory(const char *path);                   ///< 递归删除目录及其内容
int copy_file_simple(const char *src, const char *dst);   ///< 简单复制单个文件

/* ---------- 压缩/解压（基于 libarchive） ---------- */
unsigned char* GzipToMemory(const char* filePath, size_t* outSize); ///< 将单个文件压缩为 tar.gz 内存块
unsigned char* GzipToMemoryDir(const char* libsPath, const char* includePath, size_t* outSize); ///< 将 libs 和 include 两个目录打包为 tar.gz
unsigned char* DecompressGzipToMemory(const unsigned char* compressed_data, size_t compressed_len, size_t* out_len); ///< 解压 tar.gz 内存块到内存
int DecompressPocketToDir(const unsigned char* pocket_gzip, size_t pocket_len, const char* dest_dir); ///< 解压 pocket 到目录

/* ---------- 哈希 ---------- */
int ComputeSha256(const unsigned char* data, size_t len, unsigned char* digest, unsigned int* digest_len); ///< 计算 SHA‑256
bool VerifyHash(const unsigned char* expected_hash, const unsigned char* data, size_t data_len); ///< 验证哈希是否匹配

/* ---------- 锁与初始化 ---------- */
void InitCpkg(void);              ///< 创建工作目录（/var/cache/cpkg）
void GetLock(void);               ///< 获取进程锁（阻塞）
void ReleaseLock(void);           ///< 释放进程锁

/* ---------- 包格式验证 ---------- */
int VerifyMagic(FILE* stream);    ///< 检查文件头魔数是否为 "CPL"

/* ---------- JSON 解析 ---------- */
Config* ParseConfigFromJson(const char* json_str);        ///< 从 JSON 字符串解析 Config

/* ---------- 安装辅助 ---------- */
void install_list_init(InstallList *list);                ///< 初始化安装列表
int install_list_add(InstallList *list, const char *path);///< 向列表添加路径
void install_list_free(InstallList *list);                ///< 释放列表
int install_dir_to_multi(const char *src_dir, const char **dst_bases, int dst_count, InstallList *list); ///< 将源目录内容安装到多个目标基目录，并记录文件
void fprint_json_string(FILE* f, const char* str);        ///< 向文件写入 JSON 转义字符串

#endif // UTILS_H
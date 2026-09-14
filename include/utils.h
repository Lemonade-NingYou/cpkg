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
#ifndef CPKG_UTILS_H
#define CPKG_UTILS_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#define WORK_DIR        "/var/cache/cpkg"
#define TEMP_PATH       "/tmp/cpkg_temp"
#define LOCKFILE_PATH   WORK_DIR "/.lock"

#define MAGIC           "CPKG"
#define MAGIC_LEN       4
#define SHA256_LEN      32
#define CHUNK_SIZE      8192

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#ifndef MANUAL_PATH
#define MANUAL_PATH "/usr/share/cpkg/manual/"
#endif

typedef struct {
    char  PocketName[256];
    char  version[64];
    char** authors;
    int   author_count;
    char  license[64];
    char  description[512];
    char  homepage[256];
    char  repository[256];

    char** include_patterns;
    int    include_count;
    char** lib_patterns;
    int    lib_count;
    char** exclude_patterns;
    int    exclude_count;
    char** special_files;
    int    special_count;
    char** manual_patterns;
    int    manual_count;

    char  default_libs_dir[64];
    char  default_include_dir[64];
    char  default_manual_dir[64];

    bool  strict;
    bool  flatten;
    bool  ignore_hidden;
    bool  follow_symlinks;
} Config;

typedef struct {
    char** paths;
    int    count;
    int    capacity;
} InstallList;

/* ---------- 配置读写 ---------- */
Config* ReadConfig(const char* ConfigPath);
void    FreeConfig(Config* config);
char*   ChangeStructToJson(const Config* cfg);
Config* ParseConfigFromJson(const char* json_str);

/* ---------- 基础工具 ---------- */
bool is_dir(const char* path);
bool get_file_size(const char* path, uint64_t* size);
bool get_directory_size(const char* path, uint64_t* total);

/* ---------- 压缩 / 解压 ---------- */
unsigned char* GzipToMemory(const char* filePath, size_t* outSize);
unsigned char* GzipToMemoryDir(const char* libsPath,
                               const char* includePath,
                               const char* manualPath,
                               size_t* outSize);
unsigned char* DecompressGzipToMemory(const unsigned char* compressed_data,
                                      size_t compressed_len,
                                      size_t* out_len);
int DecompressPocketToDir(const unsigned char* pocket_gzip,
                          size_t pocket_len,
                          const char* dest_dir);

/* ---------- SHA256 ---------- */
int  ComputeSha256(const unsigned char* data, size_t len,
                   unsigned char* digest, unsigned int* digest_len);
bool VerifyHash(const unsigned char* expected_hash,
                const unsigned char* data, size_t data_len);
int  VerifyMagic(FILE* stream);

/* ---------- 锁和初始化 ---------- */
void InitCpkg(void);
void GetLock(void);
void ReleaseLock(void);

/* ---------- 增量复制 ---------- */
int copy_path_incremental(const char* src, const char* dst_base);
int copy_file_simple(const char* src, const char* dst);
int remove_directory(const char* path);

/* ---------- 安装辅助 ---------- */
void install_list_init(InstallList* list);
int  install_list_add(InstallList* list, const char* path);
void install_list_free(InstallList* list);
int  install_dir_to_multi(const char* src_dir, const char** dst_bases,
                          int dst_count, InstallList* list);

/* ---------- JSON 输出辅助 ---------- */
void fprint_json_string(FILE* f, const char* str);

#endif /* CPKG_UTILS_H */
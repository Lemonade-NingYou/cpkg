#ifndef UTILS_H
#define UTILS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>

#define MAGIC "CPL"
#define MAGIC_LEN 3
#define SHA256_LEN 32
#define CHUNK_SIZE 4096
#define WORK_DIR "/var/cache/cpkg"
#define TEMP_PATH WORK_DIR "/temp/"
#define LOCKFILE_PATH WORK_DIR "/lock"

// 配置文件结构体
typedef struct Config {
    char PocketName[64];
    char version[32];
    char** authors;  // 作者列表
    int author_count;
    char license[64];
    char description[512];
    char homepage[128];
    char repository[128];

    // files 部分
    char** include_patterns;
    int include_count;
    char** lib_patterns;
    int lib_count;
    char** exclude_patterns;
    int exclude_count;
    char** special_files;
    int special_count;

    // default_dirs
    char default_libs_dir[64];
    char default_include_dir[64];

    // 高级选项
    bool strict;
    bool flatten;
    bool ignore_hidden;
    bool follow_symlinks;
} Config;

// 安装列表结构体
typedef struct {
    char **paths;
    int count;
    int capacity;
} InstallList;

/**
 * @brief 读取 config.txt 文件（YAML 格式）
 */
Config* ReadConfig(const char* ConfigPath);

/**
 * @brief 释放 Config 结构体内存
 */
void FreeConfig(Config* config);

/**
 * @brief 将 Config 结构体转换为 JSON 格式字符串
 */
char* ChangeStructToJson(const Config* config);

/**
 * @brief 判断文件夹是否存在
 */
bool is_dir(const char* path);

/**
 * @brief 获取普通文件大小（字节）
 */
bool get_file_size(const char* path, uint64_t* size);

/**
 * @brief 获取目录总大小（递归）
 */
bool get_directory_size(const char* path, uint64_t* total);

/**
 * @brief 将单个文件压缩为 tar.gz 格式并存储在内存中
 */
unsigned char* GzipToMemory(const char* filePath, size_t* outSize);

/**
 * @brief 将两个目录压缩为 tar.gz 格式
 */
unsigned char* GzipToMemoryDir(const char* libsPath, const char* includePath, size_t* outSize);

/**
 * @brief 计算输入数据的 SHA-256 摘要
 */
int ComputeSha256(const unsigned char* data, size_t len, unsigned char* digest, unsigned int* digest_len);

/**
 * @brief 初始化工作目录
 */
void InitCpkg(void);

/**
 * @brief 创建锁文件
 */
void GetLock(void);

/**
 * @brief 释放锁文件
 */
void ReleaseLock(void);

/**
 * @brief 增量复制文件或目录
 */
int copy_path_incremental(const char* src, const char* dst_base);

/**
 * @brief 验证魔术字
 */
int VerifyMagic(FILE* stream);

/**
 * @brief 解压 gzip 压缩的数据到内存
 */
unsigned char* DecompressGzipToMemory(const unsigned char* compressed_data,
                                      size_t compressed_len,
                                      size_t* out_len);

/**
 * @brief 解压 pocket (tar.gz) 到指定目录
 */
int DecompressPocketToDir(const unsigned char* pocket_gzip,
                          size_t pocket_len,
                          const char* dest_dir);

/**
 * @brief 从 JSON 字符串解析 Config 结构体
 */
Config* ParseConfigFromJson(const char* json_str);

/**
 * @brief 验证包数据的完整性
 */
bool VerifyHash(const unsigned char* expected_hash, const unsigned char* data, size_t data_len);

/* ----- 安装辅助函数 ----- */
void install_list_init(InstallList *list);
int install_list_add(InstallList *list, const char *path);
void install_list_free(InstallList *list);
int copy_file_simple(const char *src, const char *dst);
int remove_directory(const char *path);
int install_dir_to_multi(const char *src_dir, const char **dst_bases,
                         int dst_count, InstallList *list);

#endif  // UTILS_H
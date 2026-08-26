#ifndef UTILS_H
#define UTILS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>

#define WORK_DIR "/var/cache/cpkg"
#define LOCKFILE_PATH WORK_DIR "/lock"

// 配置文件结构体
typedef struct Config {
    char PocketName[50];
    char version[32];
    char authors[64];
    char license[64];
    char description[128];
    int libs;                  // libNames 数组长度
    char **libNames;           // 动态分配
    int include;               // includeNames 数组长度
    char **includeNames;       // 动态分配
} Config;

/**
 * @brief 读取 config.txt 文件（格式：key: value，数组用逗号分隔）
 * @param ConfigPath 配置文件路径
 * @return Config* 结构体指针，需调用 FreeConfig 释放
 */
Config *ReadConfig(const char *ConfigPath);

/**
 * @brief 释放 Config 结构体内存
 * @param config 要释放的结构体指针
 */
void FreeConfig(Config *config);

/**
 * @brief 将 Config 结构体转换为 JSON 格式字符串
 * @param config 结构体指针
 * @return char* JSON 字符串，需调用 free 释放
 */
char *ChangeStructToJson(const Config *config);

/**
 * @brief 判断文件夹是否存在
 * @param path 目录路径
 * @return true 存在，false 不存在或不是目录
 */
bool is_dir(const char *path);

/**
 * @brief 获取普通文件大小（字节）
 * @param path 文件路径
 * @param size 输出参数
 * @return true 成功，false 失败（非普通文件或无法访问）
 */
bool get_file_size(const char *path, uint64_t *size);

/**
 * @brief 获取目录总大小（递归累加，不跟随符号链接）
 * @param path 目录路径
 * @param total 输出总大小（字节）
 * @return true 成功，false 路径不存在或非目录
 */
bool get_directory_size(const char *path, uint64_t *total);

/**
 * @brief 将单个文件压缩为 tar.gz 格式并存储在内存中
 * @param filePath 文件路径
 * @param outSize 输出参数，返回压缩后数据大小（字节）
 * @return unsigned char* 压缩数据指针，需调用 free 释放；失败返回 NULL
 */
unsigned char *GzipToMemory(const char *filePath, size_t *outSize);

/**
 * @brief 将两个目录压缩为 tar.gz 格式，归档内包含 libs/ 和 include/ 目录
 * @param libsPath 库目录路径
 * @param includePath 包含目录路径
 * @param outSize 输出压缩后数据大小
 * @return unsigned char* 压缩数据指针，需 free；失败返回 NULL
 */
unsigned char *GzipToMemoryDir(const char *libsPath, const char *includePath, size_t *outSize);

/**
 * @brief 初始化 .cpkg 目录结构
 */
void InitCpkg(void);

/**
 * @brief 创建锁文件以防止并发操作
 * @note 锁文件路径为 .cpkg/lockfile.lock
 * @return void
 * @warning 如果无法创建锁文件，将打印错误并退出程序
 */
void GetLock(void);

/**
 * @brief 释放锁文件
 * @note 释放锁文件后，其他进程可以继续操作
 * @return void
 * @warning 如果无法释放锁文件，将打印警告信息
 */
void ReleaseLock(void);
#endif // UTILS_H
#define _GNU_SOURCE   // 启用 GNU 扩展，包括 glob_t

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <glob.h>
#include <errno.h>
#include <stdio.h>
#include <libgen.h>
#include <dirent.h>
#include <archive.h>
#include <archive_entry.h>
#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/sha.h>
#include "../include/cpkg.h"
#include "../include/help.h"  // 假设 cpk_printf 在此定义

/**
 * @brief 检查root权限
 * @note 检查当前用户是否具有root权限，如果没有，则提示用户使用sudo执行此命令
 * @return 成功时返回0，失败时返回 1
 */
int check_sudo_privileges(void)
{
    if(geteuid()!= 0)
        return 1;
    return 0;
}

/**
 * @brief 选择是否继续
 * @note 询问用户是否继续，并返回用户的选择（是/否）
 * @param msg 提示信息
 * @return 成功时返回 0（继续），失败时返回 1（中止）
 */
int tf_choose(const char *msg)
{
    printf("%s (Y/n) ", msg);
    int ch = 0;
    while ((ch = getchar()) == '\n' || ch == EOF) continue;
    if (ch == 'y' || ch == 'Y') 
        return 0;
    return 1;
}

/**
 * @brief 创建目录（递归创建）
 * @note 创建目录，如果父目录不存在，则递归创建
 * @param path 要创建的目录路径
 * @param mode 目录权限
 * @return 成功时返回0，失败时返回-1并设置errno
 */
int mkdir_p(const char *path, mode_t mode) 
{
    char *p, *pp;
    struct stat st;
    int ret = 0;

    if (path == NULL || *path == '\0')
        return -1;

    char *path_copy = strdup(path);
    if (path_copy == NULL)
        return -1;

    p = path_copy;
    pp = p;

    while ((p = strchr(p, '/')) != NULL) {
        *p = '\0';
        if (pp != p) {
            if (stat(path_copy, &st) != 0) {
                if (mkdir(path_copy, mode) != 0 && errno != EEXIST) {
                    ret = -1;
                    break;
                }
            } else if (!S_ISDIR(st.st_mode)) {
                errno = ENOTDIR;
                ret = -1;
                break;
            }
        }
        *p = '/';
        pp = p + 1;
        p++;
    }

    if (ret == 0 && *pp != '\0') {
        if (stat(path_copy, &st) != 0) {
            if (mkdir(path_copy, mode) != 0 && errno != EEXIST) {
                ret = -1;
            }
        } else if (!S_ISDIR(st.st_mode)) {
            errno = ENOTDIR;
            ret = -1;
        }
    }

    free(path_copy);
    return ret;
}

/**
 * @brief 复制文件到指定目录
 * @param src_file 源文件路径
 * @param dst_dir  目标目录路径
 * @return 成功返回0，失败返回-1并设置errno
 */
int cp_file(const char *src_file, const char *dst_dir)
{
    FILE *src_fp = NULL, *dst_fp = NULL;
    struct stat st;
    char *dst_path = NULL;
    const char *filename;
    int ret = -1;

    if (stat(src_file, &st) != 0) return -1;
    if (!S_ISREG(st.st_mode)) { errno = EINVAL; return -1; }
    if (stat(dst_dir, &st) != 0) return -1;
    if (!S_ISDIR(st.st_mode)) { errno = ENOTDIR; return -1; }

    char *src_copy = strdup(src_file);
    if (src_copy == NULL) { errno = ENOMEM; return -1; }
    filename = basename(src_copy);

    size_t len = strlen(dst_dir) + strlen(filename) + 2;
    dst_path = (char *)malloc(len);
    if (dst_path == NULL) { free(src_copy); errno = ENOMEM; return -1; }
    snprintf(dst_path, len, "%s/%s", dst_dir, filename);
    free(src_copy);

    src_fp = fopen(src_file, "rb");
    if (src_fp == NULL) goto cleanup;

    dst_fp = fopen(dst_path, "wb");
    if (dst_fp == NULL) goto cleanup;

    char buffer[8192];
    size_t n;
    while ((n = fread(buffer, 1, sizeof(buffer), src_fp)) > 0) {
        if (fwrite(buffer, 1, n, dst_fp) != n) goto cleanup;
    }
    if (ferror(src_fp)) goto cleanup;

    ret = 0;

cleanup:
    if (src_fp) fclose(src_fp);
    if (dst_fp) fclose(dst_fp);
    free(dst_path);
    return ret;
}

/**
 * @brief 递归删除目录或文件（类似 rm -rf）
 * @param del_dir 要删除的路径（文件或目录）
 * @return 完全成功返回 0，否则返回 -1（部分内容可能已删除）
 */
int rm_rf(const char *del_dir) 
{
    struct stat st;
    if (lstat(del_dir, &st) != 0)
        return (errno == ENOENT) ? 0 : -1;

    if (S_ISDIR(st.st_mode) && !S_ISLNK(st.st_mode)) {
        DIR *dir = opendir(del_dir);
        if (!dir) return -1;

        struct dirent *entry;
        int ret = 0;
        while ((entry = readdir(dir)) != NULL) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                continue;
            char *sub_path = malloc(strlen(del_dir) + strlen(entry->d_name) + 2);
            if (!sub_path) { closedir(dir); return -1; }
            sprintf(sub_path, "%s/%s", del_dir, entry->d_name);
            if (rm_rf(sub_path) != 0) ret = -1;
            free(sub_path);
        }
        closedir(dir);
        if (rmdir(del_dir) != 0 && errno != ENOENT) ret = -1;
        return ret;
    } else {
        if (unlink(del_dir) != 0 && errno != ENOENT) return -1;
        return 0;
    }
}

/**
 * @brief 创建文件头
 * @note 从 Control_Info 结构体创建 CPK_Header，深度复制所有字段（包括文件名列表）
 * @param ctrl_info Control_Info 结构体指针
 * @return 成功时返回文件头指针，失败时返回 NULL
 */
CPK_Header *make_Header(Control_Info *ctrl_info)
{
    if (!ctrl_info) return NULL;

    CPK_Header *header = (CPK_Header *)malloc(sizeof(CPK_Header));
    if (!header) return NULL;
    memset(header, 0, sizeof(CPK_Header));

    memcpy(header->magic, "CPKG", 4);

    // 临时哈希值
    strncpy(header->hash, "0", sizeof(header->hash) - 1);
    header->hash[sizeof(header->hash) - 1] = '\0';

    // 安全复制：使用 strnlen 限制读取长度
#define SAFE_COPY(dest, src) \
    do { \
        size_t src_len = strnlen(src, sizeof(src) - 1); \
        memcpy(dest, src, src_len); \
        dest[src_len] = '\0'; \
    } while (0)

    SAFE_COPY(header->name, ctrl_info->name);
    SAFE_COPY(header->version, ctrl_info->version);
    SAFE_COPY(header->description, ctrl_info->description);
    SAFE_COPY(header->homepage, ctrl_info->homepage);
    SAFE_COPY(header->author, ctrl_info->author);
    SAFE_COPY(header->license, ctrl_info->license);
    SAFE_COPY(header->include_install_path, ctrl_info->include_install_path);
    SAFE_COPY(header->lib_install_path, ctrl_info->lib_install_path);

#undef SAFE_COPY
    return header;
}

/**
 * @brief 计算内存数据的 SHA256 哈希值
 * @param data 内存数据指针（通常由 malloc 获得）
 * @param len  数据长度（字节数）
 * @return 成功时返回十六进制哈希字符串（动态分配），失败时返回 NULL
 */
char *sha256_mem(const unsigned char *data, size_t len) 
{
    if (!data || len == 0) return NULL;

    SHA256_CTX ctx;
    if (!SHA256_Init(&ctx)) return NULL;
    if (!SHA256_Update(&ctx, data, len)) return NULL;

    unsigned char hash[SHA256_DIGEST_LENGTH];
    if (!SHA256_Final(hash, &ctx)) return NULL;

    char *hash_str = malloc(SHA256_DIGEST_LENGTH * 2 + 1);
    if (!hash_str) return NULL;

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        sprintf(hash_str + i * 2, "%02x", hash[i]);
    hash_str[SHA256_DIGEST_LENGTH * 2] = '\0';

    return hash_str;
}

/**
 * @brief 打印控制信息
 * @note 打印 Control_Info 结构体中的内容
 * @param ctrl_info Control_Info 结构体指针
 */
void printf_control_info(Control_Info *ctrl_info)
{
    printf("package name: %s\n", ctrl_info->name);
    printf("version: %s\n", ctrl_info->version);
    printf("description: %s\n", ctrl_info->description);
    printf("homepage: %s\n", ctrl_info->homepage);
    printf("author: %s\n", ctrl_info->author);
    printf("license: %s\n", ctrl_info->license);
    printf("include_install_path: %s\n", ctrl_info->include_install_path);
    printf("lib_install_path: %s\n", ctrl_info->lib_install_path);
    printf("include_files:\n");
    for (int i = 0; i < ctrl_info->include_file_count; i++)
        printf("  %s\n", ctrl_info->include_files[i]);
    printf("lib_files:\n");
    for (int i = 0; i < ctrl_info->lib_file_count; i++)
        printf("  %s\n", ctrl_info->lib_files[i]);
    printf("\n");
}

/**
 * 遍历指定目录，将所有常规文件的文件名（含相对路径）存入动态数组。
 * @param dir_path 目标目录路径
 * @param count    输出参数，返回文件数量
 * @return 成功返回动态分配的字符串数组，失败返回 NULL
 */
char **collect_files(const char *dir_path, int *count) 
{
    DIR *dir = opendir(dir_path);
    if (!dir) {
        cpk_printf(ERROR, "opendir: %s\n", strerror(errno));
        return NULL;
    }

    char **files = NULL;
    int file_count = 0;
    struct dirent *entry;
    struct stat st;

    while ((entry = readdir(dir)) != NULL) {
        // 跳过 "." 和 ".."
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        // 构造完整路径
        char full_path[1024];
        snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, entry->d_name);

        // 获取文件信息
        if (stat(full_path, &st) != 0) {
            cpk_printf(WARNING, "stat: %s\n", strerror(errno));
            continue;
        }

        // 只收集常规文件（可调整条件，例如也收集符号链接）
        if (S_ISREG(st.st_mode)) {
            // 动态扩展数组
            char **new_files = realloc(files, (file_count + 1) * sizeof(char *));
            if (!new_files) {
                cpk_printf(ERROR, "realloc: %s\n", strerror(errno));
                // 释放已分配内存
                for (int i = 0; i < file_count; i++) free(files[i]);
                free(files);
                closedir(dir);
                return NULL;
            }
            files = new_files;

            // 复制文件名（这里使用完整路径，也可以只存文件名）
            files[file_count] = strdup(full_path);
            if (!files[file_count]) {
                cpk_printf(ERROR, "strdup: %s\n", strerror(errno));
                // 释放之前的内容
                for (int i = 0; i < file_count; i++) free(files[i]);
                free(files);
                closedir(dir);
                return NULL;
            }
            file_count++;
        }
    }

    closedir(dir);
    *count = file_count;
    return files;
}

/**
 * @brief 写入安装信息文件
 * @note 格式：CPK_Header + include_file_count + (len+data) for each include + lib_file_count + (len+data) for each lib
 * @param install_info  已打开的可写文件流
 * @param header        包头部信息
 * @param include_file_count  头文件数量
 * @param include_file_list   头文件路径数组
 * @param lib_file_count      库文件数量
 * @param lib_file_list       库文件路径数组
 * @return 成功返回0，失败返回-1并设置errno
 */
int write_install_file(FILE *install_info, CPK_Header *header,
                            int include_file_count, char **include_file_list,
                            int lib_file_count, char **lib_file_list)
{
    if (!install_info || !header) {
        errno = EINVAL;
        return -1;
    }

    // 写入头部
    if (fwrite(header, sizeof(CPK_Header), 1, install_info) != 1) {
        // fwrite 失败时已设置 errno
        return -1;
    }

    // 写入 include 文件数量
    if (fwrite(&include_file_count, sizeof(int), 1, install_info) != 1) {
        return -1;
    }

    // 写入每个 include 文件路径
    for (int i = 0; i < include_file_count; i++) {
        size_t len = strlen(include_file_list[i]);
        int len_int = (int)len;  // 假设长度不超过 INT_MAX
        if (fwrite(&len_int, sizeof(int), 1, install_info) != 1) {
            return -1;
        }
        if (len > 0 && fwrite(include_file_list[i], 1, len, install_info) != len) {
            return -1;
        }
    }

    // 写入 lib 文件数量
    if (fwrite(&lib_file_count, sizeof(int), 1, install_info) != 1) {
        return -1;
    }

    // 写入每个 lib 文件路径
    for (int i = 0; i < lib_file_count; i++) {
        size_t len = strlen(lib_file_list[i]);
        int len_int = (int)len;
        if (fwrite(&len_int, sizeof(int), 1, install_info) != 1) {
            return -1;
        }
        if (len > 0 && fwrite(lib_file_list[i], 1, len, install_info) != len) {
            return -1;
        }
    }

    // 确保所有数据已写入
    if (fflush(install_info) != 0) {
        return -1;
    }

    return 0;
}

/**
 * @brief 从文件中读取安装信息
 * @param install_info       已打开的可读文件流
 * @param header             输出参数：接收包头部信息（调用者需确保缓冲区足够）
 * @param include_file_count 输出参数：头文件数量
 * @param include_file_list  输出参数：头文件路径数组（动态分配，调用者需释放）
 * @param lib_file_count     输出参数：库文件数量
 * @param lib_file_list      输出参数：库文件路径数组（动态分配，调用者需释放）
 * @return 成功返回0，失败返回-1并设置errno
 */
int read_install_file(FILE *install_info, CPK_Header *header,
                           int *include_file_count, char ***include_file_list,
                           int *lib_file_count, char ***lib_file_list)
{
    if (!install_info || !header || !include_file_count || !include_file_list ||
        !lib_file_count || !lib_file_list) {
        errno = EINVAL;
        return -1;
    }

    // 初始化输出指针
    *include_file_count = 0;
    *include_file_list = NULL;
    *lib_file_count = 0;
    *lib_file_list = NULL;

    // 读取头部
    if (fread(header, sizeof(CPK_Header), 1, install_info) != 1) {
        // fread 失败，errno 可能已设置
        return -1;
    }

    // 读取 include 文件数量
    int count;
    if (fread(&count, sizeof(int), 1, install_info) != 1) {
        return -1;
    }
    *include_file_count = count;

    if (count > 0) {
        *include_file_list = (char **)malloc(count * sizeof(char *));
        if (!*include_file_list) {
            return -1; // errno 已由 malloc 设置
        }
        // 初始化为 NULL，便于错误时释放
        for (int i = 0; i < count; i++) {
            (*include_file_list)[i] = NULL;
        }
    } else {
        *include_file_list = NULL;
    }

    // 读取每个 include 文件路径
    for (int i = 0; i < count; i++) {
        int len;
        if (fread(&len, sizeof(int), 1, install_info) != 1) {
            goto error;
        }
        if (len < 0) {
            errno = EINVAL;
            goto error;
        }
        char *str = (char *)malloc(len + 1);
        if (!str) {
            goto error;
        }
        if (len > 0) {
            if (fread(str, 1, len, install_info) != (size_t)len) {
                free(str);
                goto error;
            }
        }
        str[len] = '\0';
        (*include_file_list)[i] = str;
    }

    // 读取 lib 文件数量
    if (fread(&count, sizeof(int), 1, install_info) != 1) {
        goto error;
    }
    *lib_file_count = count;

    if (count > 0) {
        *lib_file_list = (char **)malloc(count * sizeof(char *));
        if (!*lib_file_list) {
            goto error;
        }
        for (int i = 0; i < count; i++) {
            (*lib_file_list)[i] = NULL;
        }
    } else {
        *lib_file_list = NULL;
    }

    for (int i = 0; i < count; i++) {
        int len;
        if (fread(&len, sizeof(int), 1, install_info) != 1) {
            goto error;
        }
        if (len < 0) {
            errno = EINVAL;
            goto error;
        }
        char *str = (char *)malloc(len + 1);
        if (!str) {
            goto error;
        }
        if (len > 0) {
            if (fread(str, 1, len, install_info) != (size_t)len) {
                free(str);
                goto error;
            }
        }
        str[len] = '\0';
        (*lib_file_list)[i] = str;
    }

    return 0;

error:
    // 清理已分配的 include 文件列表
    if (*include_file_list) {
        for (int i = 0; i < *include_file_count; i++) {
            free((*include_file_list)[i]);
        }
        free(*include_file_list);
        *include_file_list = NULL;
    }
    *include_file_count = 0;

    // 清理已分配的 lib 文件列表
    if (*lib_file_list) {
        for (int i = 0; i < *lib_file_count; i++) {
            free((*lib_file_list)[i]);
        }
        free(*lib_file_list);
        *lib_file_list = NULL;
    }
    *lib_file_count = 0;

    return -1;
}
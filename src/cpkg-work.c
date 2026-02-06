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

#define _XOPEN_SOURCE 700
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <string.h>
#include <strings.h>  // 添加此头文件以支持 strncasecmp
#include <archive.h>
#include <archive_entry.h>
#include <openssl/sha.h>
#include <openssl/evp.h>  // 使用 OpenSSL EVP API 替代旧的 SHA256 API
#include <unistd.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include "../include/help.h"
#include "../include/cpkg.h"

// 函数声明
int add_directory_to_archive_recursive(struct archive *a, const char *base_dir, const char *current_dir, int depth);

/**
 * @brief 检察 sudo 权限
 * @return 0 表示成功，非0表示失败
 */
int check_sudo_privileges(void) 
{
    if (geteuid() != 0) 
    {
        return -1; // 权限不足
    }
    return 0; // 成功
}

/**
 * @brief 读取 CPK 头部
 * @param pkg_file 软件包文件指针
 * @param header 指向 CPK_Header 结构体的指针，用于存储读取的头部信息
 * @return 0 表示成功，非0表示失败
 */
int read_cpk_header(FILE *pkg_file, CPK_Header *header) 
{
    // 读取 CPK 头部
    size_t read_size = fread(header, 1, CPK_HEADER_SIZE, pkg_file);
    if (read_size != CPK_HEADER_SIZE) 
    {
        return -1; // 读取失败
    }
    return 0; // 成功
}

/**
 * @brief 检查哈希值 SHA256 使用 OpenSSL EVP API 实现
 * @param pkg_file 软件包文件指针
 * @param expected_hash 预期的哈希值
 * @return 0 表示成功，非0表示失败
 */
int check_hash(FILE *pkg_file, const unsigned char *expected_hash) 
{
    EVP_MD_CTX *mdctx; // EVP 消息摘要上下文
    unsigned char hash[EVP_MAX_MD_SIZE]; // 计算得到的哈希值
    unsigned int hash_len; // 哈希值长度
    unsigned char buffer[4096]; // 读取缓冲区
    size_t bytes_read; // 读取的字节数

    // 创建消息摘要上下文
    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) 
    {
        return -1; // 创建上下文失败
    }

    // 初始化 SHA256 摘要
    if (!EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL)) 
    {
        EVP_MD_CTX_free(mdctx);
        return -1; // 初始化失败
    }

    fseek(pkg_file, CPK_HEADER_SIZE, SEEK_SET); // 跳过头部

    // 读取文件并计算哈希值
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), pkg_file)) != 0) 
    {
        if (!EVP_DigestUpdate(mdctx, buffer, bytes_read)) 
        {
            EVP_MD_CTX_free(mdctx);
            return -1; // 更新哈希计算失败
        }
    }

    // 完成哈希计算
    if (!EVP_DigestFinal_ex(mdctx, hash, &hash_len)) 
    {
        EVP_MD_CTX_free(mdctx);
        return -1; // 完成哈希计算失败
    }

    EVP_MD_CTX_free(mdctx);

    // 检查哈希值长度
    if (hash_len != SHA256_DIGEST_LENGTH) 
    {
        return -1; // 哈希值长度不正确
    }

    // 比较计算得到的哈希值与预期哈希值
    if (memcmp(hash, expected_hash, SHA256_DIGEST_LENGTH) != 0) 
    {
        return -1; // 哈希值不匹配
    }
    return 0; // 哈希值匹配
}

/**
 * @brief 压缩指定目录内容为 tar.gz 格式并写入文件
 * @param pkg_file 目标文件指针
 * @param install_dir 要压缩的目录路径
 * @return 0 成功，-1 失败
 */
int compress_package(FILE *pkg_file, const char *install_dir)
{
    struct archive *a; // 归档对象
    int r; // 返回值
    
    // 检查参数有效性
    if (pkg_file == NULL)
    {
        cpk_printf(ERROR, "Invalid file pointer");
        return -1;
    }
    
    if (install_dir == NULL || install_dir[0] == '\0')
    {
        cpk_printf(ERROR, "Invalid directory path");
        return -1;
    }
    
    // 检查目录是否存在
    struct stat st;
    if (stat(install_dir, &st) != 0)
    {
        cpk_printf(ERROR, "Directory '%s' does not exist: %s", 
                  install_dir, strerror(errno));
        return -1;
    }
    
    if (!S_ISDIR(st.st_mode))
    {
        cpk_printf(ERROR, "Path '%s' is not a directory", install_dir);
        return -1;
    }
    
    // 打开归档对象用于写入
    a = archive_write_new();
    if (a == NULL)
    {
        cpk_printf(ERROR, "Failed to create archive object");
        return -1;
    }
    
    // 设置压缩格式为 tar.gz
    r = archive_write_add_filter_gzip(a);
    if (r != ARCHIVE_OK)
    {
        cpk_printf(ERROR, "Failed to add gzip filter: %s", archive_error_string(a));
        archive_write_free(a);
        return -1;
    }
    
    r = archive_write_set_format_ustar(a);
    if (r != ARCHIVE_OK)
    {
        cpk_printf(ERROR, "Failed to set tar format: %s", archive_error_string(a));
        archive_write_free(a);
        return -1;
    }
    
    // 打开文件进行归档
    r = archive_write_open_FILE(a, pkg_file);
    if (r != ARCHIVE_OK)
    {
        cpk_printf(ERROR, "Failed to open archive for writing: %s", archive_error_string(a));
        archive_write_free(a);
        return -1;
    }
    
    // 递归遍历目录并添加文件到归档
    int result = add_directory_to_archive_recursive(a, install_dir, "", 0);
    
    // 关闭归档
    r = archive_write_close(a);
    if (r != ARCHIVE_OK)
    {
        cpk_printf(WARNING, "Failed to close archive: %s", archive_error_string(a));
        result = -1;
    }
    
    archive_write_free(a);
    
    if (result == 0)
    {
        cpk_printf(INFO, "Successfully compressed directory '%s'", install_dir);
    }
    
    return result;
}

/**
 * @brief 递归遍历目录并添加文件到归档（辅助函数）
 * @param a 归档对象
 * @param base_dir 基础目录
 * @param current_dir 当前相对路径
 * @param depth 递归深度（用于避免无限递归）
 * @return 0 成功，-1 失败
 */
int add_directory_to_archive_recursive(struct archive *a, const char *base_dir, const char *current_dir, int depth)
{
    char full_path[MAX_PATH_LEN];
    char rel_path[MAX_PATH_LEN];
    DIR *dir;
    struct dirent *entry;
    struct stat st;
    int result = 0;
    
    // 构建完整路径
    if (current_dir[0] == '\0')
    {
        snprintf(full_path, sizeof(full_path), "%s", base_dir);
    }
    else
    {
        snprintf(full_path, sizeof(full_path), "%s/%s", base_dir, current_dir);
    }
    
    // 打开目录
    dir = opendir(full_path);
    if (dir == NULL)
    {
        cpk_printf(ERROR, "Failed to open directory '%s': %s", 
                  full_path, strerror(errno));
        return -1;
    }
    
    // 遍历目录内容
    while ((entry = readdir(dir)) != NULL && result == 0)
    {
        // 跳过 . 和 ..
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
        {
            continue;
        }
        
        // 构建相对路径
        if (current_dir[0] == '\0')
        {
            snprintf(rel_path, sizeof(rel_path), "%s", entry->d_name);
        }
        else
        {
            snprintf(rel_path, sizeof(rel_path), "%s/%s", current_dir, entry->d_name);
        }
        
        // 构建完整路径
        snprintf(full_path, sizeof(full_path), "%s/%s", base_dir, rel_path);
        
        // 获取文件信息
        if (lstat(full_path, &st) != 0)
        {
            cpk_printf(WARNING, "Failed to stat '%s': %s", 
                      full_path, strerror(errno));
            continue;
        }
        
        // 创建归档条目
        struct archive_entry *entry_obj = archive_entry_new();
        if (entry_obj == NULL)
        {
            cpk_printf(ERROR, "Failed to create archive entry for '%s'", rel_path);
            result = -1;
            break;
        }
        
        // 设置条目标题（相对路径）
        archive_entry_set_pathname(entry_obj, rel_path);
        
        // 设置文件类型和权限
        archive_entry_set_perm(entry_obj, st.st_mode);
        
        // 设置用户和组信息
        archive_entry_set_uid(entry_obj, st.st_uid);
        archive_entry_set_gid(entry_obj, st.st_gid);
        
        // 设置时间戳
        archive_entry_set_mtime(entry_obj, st.st_mtime, 0);
        
        // 根据文件类型处理
        if (S_ISDIR(st.st_mode))
        {
            // 目录
            archive_entry_set_filetype(entry_obj, AE_IFDIR);
            archive_entry_set_size(entry_obj, 0);
            
            // 写入目录条目
            if (archive_write_header(a, entry_obj) != ARCHIVE_OK)
            {
                cpk_printf(ERROR, "Failed to write directory header for '%s': %s", 
                          rel_path, archive_error_string(a));
                result = -1;
            }
            
            // 递归处理子目录
            if (result == 0 && depth < 100) // 限制递归深度，避免栈溢出
            {
                result = add_directory_to_archive_recursive(a, base_dir, rel_path, depth + 1);
            }
        }
        else if (S_ISREG(st.st_mode))
        {
            // 普通文件
            archive_entry_set_filetype(entry_obj, AE_IFREG);
            archive_entry_set_size(entry_obj, st.st_size);
            
            // 写入文件条目
            if (archive_write_header(a, entry_obj) != ARCHIVE_OK)
            {
                cpk_printf(ERROR, "Failed to write file header for '%s': %s", 
                          rel_path, archive_error_string(a));
                result = -1;
            }
            else
            {
                // 写入文件内容
                FILE *file = fopen(full_path, "rb");
                if (file == NULL)
                {
                    cpk_printf(ERROR, "Failed to open file '%s' for reading: %s", 
                              full_path, strerror(errno));
                    result = -1;
                }
                else
                {
                    char buffer[8192];
                    size_t bytes_read;
                    
                    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0)
                    {
                        if (archive_write_data(a, buffer, bytes_read) != (ssize_t)bytes_read)
                        {
                            cpk_printf(ERROR, "Failed to write file data for '%s': %s", 
                                      rel_path, archive_error_string(a));
                            result = -1;
                            break;
                        }
                    }
                    
                    fclose(file);
                }
            }
        }
        else if (S_ISLNK(st.st_mode))
        {
            // 符号链接
            char link_target[1024];
            ssize_t link_len;
            
            archive_entry_set_filetype(entry_obj, AE_IFLNK);
            archive_entry_set_size(entry_obj, 0);
            
            // 读取链接目标
            link_len = readlink(full_path, link_target, sizeof(link_target) - 1);
            if (link_len < 0)
            {
                cpk_printf(ERROR, "Failed to read symlink '%s': %s", 
                          full_path, strerror(errno));
                result = -1;
            }
            else
            {
                link_target[link_len] = '\0';
                archive_entry_set_symlink(entry_obj, link_target);
                
                // 写入符号链接条目
                if (archive_write_header(a, entry_obj) != ARCHIVE_OK)
                {
                    cpk_printf(ERROR, "Failed to write symlink header for '%s': %s", 
                              rel_path, archive_error_string(a));
                    result = -1;
                }
            }
        }
        else
        {
            // 其他类型文件（设备文件等），跳过但记录警告
            cpk_printf(WARNING, "Skipping special file '%s'", rel_path);
        }
        
        // 释放条目对象
        archive_entry_free(entry_obj);
        
        if (result != 0)
        {
            break;
        }
    }
    
    closedir(dir);
    return result;
}

/**
 * @brief 解压缩软件包内容到安装目录 tar.gz 解压缩，使用libarchive
 * @param pkg_file 软件包文件指针
 * @param install_dir 安装目录路径
 * @return 0 表示成功，非0表示失败
 */
int uncompress_package(FILE *pkg_file, const char *install_dir) 
{
    struct archive *a; // 归档对象
    struct archive *ext; // 解压对象
    struct archive_entry *entry; // 归档条目
    int r; // 返回值

    // 初始化归档对象
    a = archive_read_new();
    archive_read_support_format_tar(a);
    archive_read_support_filter_gzip(a);

    // 初始化解压对象
    ext = archive_write_disk_new();
    archive_write_disk_set_options(ext, ARCHIVE_EXTRACT_TIME);
    archive_write_disk_set_standard_lookup(ext);

    // 重新定位文件指针到内容开始位置
    fseek(pkg_file, CPK_HEADER_SIZE, SEEK_SET);

    // 打开归档
    r = archive_read_open_FILE(a, pkg_file);
    if (r != ARCHIVE_OK)
    {
        return -1; // 打开归档失败
    }

    // 解压归档内容
    while (archive_read_next_header(a, &entry) == ARCHIVE_OK) 
    {
        // 构建目标路径
        const char *current_file = archive_entry_pathname(entry);
        char full_output_path[MAX_PATH_LEN];
        snprintf(full_output_path, sizeof(full_output_path), "%s/%s", install_dir, current_file);
        archive_entry_set_pathname(entry, full_output_path);

        // 写入到磁盘
        r = archive_write_header(ext, entry);
        if (r != ARCHIVE_OK)
        {
            return -1; // 写入头部失败  
        }

        // 复制数据
        const void *buff;
        size_t size;
        la_int64_t offset;

        while (1)
        {
            r = archive_read_data_block(a, &buff, &size, &offset);
            if (r == ARCHIVE_EOF)
                break;
            if (r != ARCHIVE_OK)
            {
                return -1; // 读取数据块失败
            }

            r = archive_write_data_block(ext, buff, size, offset);
            if (r != ARCHIVE_OK)
            {
                return -1; // 写入数据块失败
            }
        }
    }
    // 关闭归档对象
    archive_read_close(a);
    archive_read_free(a);
    archive_write_close(ext);
    archive_write_free(ext);

    return 0;
}

/**
 * @brief 创建目录，包括所有必要的父目录
 * @param dir_path 目录路径
 * @return 0 成功，-1 失败
 */
int create_directory(const char *dir_path)
{
    if (dir_path == NULL || dir_path[0] == '\0')
    {
        cpk_printf(ERROR, "Invalid directory path");
        return -1;
    }
    
    // 检查目录是否已存在
    struct stat st;
    if (stat(dir_path, &st) == 0)
    {
        if (S_ISDIR(st.st_mode))
        {
            // 目录已存在
            return 0;
        }
        else
        {
            // 路径存在但不是目录
            cpk_printf(ERROR, "Path '%s' exists but is not a directory", dir_path);
            return -1;
        }
    }
    
    // 创建目录，包括父目录
    char tmp_path[MAX_PATH_LEN];
    char *p = NULL;
    size_t len;
    
    // 复制路径到临时缓冲区
    snprintf(tmp_path, sizeof(tmp_path), "%s", dir_path);
    len = strlen(tmp_path);
    
    // 去除尾部斜杠
    if (tmp_path[len-1] == '/')
    {
        tmp_path[len-1] = '\0';
    }
    
    // 逐级创建目录
    for (p = tmp_path + 1; *p; p++)
    {
        if (*p == '/')
        {
            *p = '\0';
            
            // 创建当前层级目录
            if (mkdir(tmp_path, 0755) != 0 && errno != EEXIST)
            {
                cpk_printf(ERROR, "Failed to create directory '%s': %s", 
                          tmp_path, strerror(errno));
                return -1;
            }
            
            *p = '/';
        }
    }
    
    // 创建最终目录
    if (mkdir(tmp_path, 0755) != 0 && errno != EEXIST)
    {
        cpk_printf(ERROR, "Failed to create directory '%s': %s", 
                  tmp_path, strerror(errno));
        return -1;
    }
    
    return 0;
}

/**
 * @brief 递归删除目录及其所有内容
 * @param dir_path 目录路径
 * @return 0 成功，-1 失败
 */
int remove_directory(const char *dir_path)
{
    if (dir_path == NULL || dir_path[0] == '\0')
    {
        cpk_printf(ERROR, "Invalid directory path");
        return -1;
    }
    
    // 检查目录是否存在
    struct stat st;
    if (stat(dir_path, &st) != 0)
    {
        if (errno == ENOENT)
        {
            // 目录不存在，这不算错误
            return 0;
        }
        else
        {
            cpk_printf(ERROR, "Failed to stat directory '%s': %s", 
                      dir_path, strerror(errno));
            return -1;
        }
    }
    
    if (!S_ISDIR(st.st_mode))
    {
        cpk_printf(ERROR, "Path '%s' is not a directory", dir_path);
        return -1;
    }
    
    // 打开目录
    DIR *dir = opendir(dir_path);
    if (dir == NULL)
    {
        cpk_printf(ERROR, "Failed to open directory '%s': %s", 
                  dir_path, strerror(errno));
        return -1;
    }
    
    struct dirent *entry;
    char path[MAX_PATH_LEN];
    
    // 遍历目录内容
    while ((entry = readdir(dir)) != NULL)
    {
        // 跳过 . 和 ..
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
        {
            continue;
        }
        
        // 构建完整路径
        snprintf(path, sizeof(path), "%s/%s", dir_path, entry->d_name);
        
        // 获取文件信息
        if (lstat(path, &st) != 0)
        {
            cpk_printf(WARNING, "Failed to stat '%s': %s", path, strerror(errno));
            continue;
        }
        
        // 如果是目录，递归删除
        if (S_ISDIR(st.st_mode))
        {
            if (remove_directory(path) != 0)
            {
                closedir(dir);
                return -1;
            }
        }
        // 如果是文件或链接，直接删除
        else
        {
            if (unlink(path) != 0)
            {
                cpk_printf(ERROR, "Failed to remove file '%s': %s", 
                          path, strerror(errno));
                closedir(dir);
                return -1;
            }
        }
    }
    
    closedir(dir);
    
    // 删除空目录
    if (rmdir(dir_path) != 0)
    {
        cpk_printf(ERROR, "Failed to remove directory '%s': %s", 
                  dir_path, strerror(errno));
        return -1;
    }
    
    return 0;
}

/**
 * @brief 复制单个文件
 * @param src_file 源文件路径
 * @param dst_file 目标文件路径
 * @return 0 成功，-1 失败
 */
static int copy_file(const char *src_file, const char *dst_file)
{
    FILE *src = fopen(src_file, "rb");
    if (src == NULL)
    {
        cpk_printf(ERROR, "Failed to open source file '%s': %s", 
                  src_file, strerror(errno));
        return -1;
    }
    
    FILE *dst = fopen(dst_file, "wb");
    if (dst == NULL)
    {
        cpk_printf(ERROR, "Failed to create destination file '%s': %s", 
                  dst_file, strerror(errno));
        fclose(src);
        return -1;
    }
    
    // 复制文件内容
    char buffer[8192];
    size_t bytes;
    
    while ((bytes = fread(buffer, 1, sizeof(buffer), src)) > 0)
    {
        if (fwrite(buffer, 1, bytes, dst) != bytes)
        {
            cpk_printf(ERROR, "Failed to write to destination file '%s'", dst_file);
            fclose(src);
            fclose(dst);
            return -1;
        }
    }
    
    // 检查读取错误
    if (ferror(src))
    {
        cpk_printf(ERROR, "Error reading source file '%s'", src_file);
        fclose(src);
        fclose(dst);
        return -1;
    }
    
    // 获取源文件权限
    struct stat st;
    if (stat(src_file, &st) == 0)
    {
        // 设置目标文件权限
        if (chmod(dst_file, st.st_mode) != 0)
        {
            cpk_printf(WARNING, "Failed to set permissions for '%s': %s", 
                      dst_file, strerror(errno));
        }
    }
    
    fclose(src);
    fclose(dst);
    
    return 0;
}

/**
 * @brief 递归复制文件或目录到指定目录
 * @param src_path 源路径（文件或目录）
 * @param dst_dir 目标目录
 * @return 0 成功，-1 失败
 */
int copy_files(const char *src_path, const char *dst_dir)
{
    if (src_path == NULL || src_path[0] == '\0')
    {
        cpk_printf(ERROR, "Invalid source path");
        return -1;
    }
    
    if (dst_dir == NULL || dst_dir[0] == '\0')
    {
        cpk_printf(ERROR, "Invalid destination directory");
        return -1;
    }
    
    // 确保目标目录存在
    if (create_directory(dst_dir) != 0)
    {
        cpk_printf(ERROR, "Failed to create destination directory '%s'", dst_dir);
        return -1;
    }
    
    struct stat st;
    if (stat(src_path, &st) != 0)
    {
        cpk_printf(ERROR, "Failed to access source path '%s': %s", 
                  src_path, strerror(errno));
        return -1;
    }
    
    // 如果是文件，直接复制
    if (S_ISREG(st.st_mode))
    {
        // 提取文件名
        const char *filename = strrchr(src_path, '/');
        if (filename == NULL)
        {
            filename = src_path;
        }
        else
        {
            filename++; // 跳过斜杠
        }
        
        // 构建目标文件路径
        char dst_path[MAX_PATH_LEN];
        snprintf(dst_path, sizeof(dst_path), "%s/%s", dst_dir, filename);
        
        return copy_file(src_path, dst_path);
    }
    // 如果是目录，递归复制
    else if (S_ISDIR(st.st_mode))
    {
        // 打开源目录
        DIR *dir = opendir(src_path);
        if (dir == NULL)
        {
            cpk_printf(ERROR, "Failed to open source directory '%s': %s", 
                      src_path, strerror(errno));
            return -1;
        }
        
        struct dirent *entry;
        int result = 0;
        
        // 遍历目录内容
        while ((entry = readdir(dir)) != NULL)
        {
            // 跳过 . 和 ..
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            {
                continue;
            }
            
            // 构建源路径和目标路径
            char src_entry_path[MAX_PATH_LEN];
            char dst_entry_path[MAX_PATH_LEN];
            
            snprintf(src_entry_path, sizeof(src_entry_path), "%s/%s", src_path, entry->d_name);
            snprintf(dst_entry_path, sizeof(dst_entry_path), "%s/%s", dst_dir, entry->d_name);
            
            // 获取文件信息
            if (lstat(src_entry_path, &st) != 0)
            {
                cpk_printf(WARNING, "Failed to stat '%s': %s", 
                          src_entry_path, strerror(errno));
                continue;
            }
            
            // 如果是目录，递归复制
            if (S_ISDIR(st.st_mode))
            {
                if (copy_files(src_entry_path, dst_entry_path) != 0)
                {
                    result = -1;
                    break;
                }
            }
            // 如果是文件，直接复制
            else if (S_ISREG(st.st_mode))
            {
                if (copy_file(src_entry_path, dst_entry_path) != 0)
                {
                    result = -1;
                    break;
                }
            }
            // 如果是符号链接，警告但不复制（可选实现）
            else if (S_ISLNK(st.st_mode))
            {
                cpk_printf(WARNING, "Skipping symbolic link '%s'", src_entry_path);
            }
            // 其他类型忽略
            else
            {
                cpk_printf(WARNING, "Skipping special file '%s'", src_entry_path);
            }
        }
        
        closedir(dir);
        return result;
    }
    // 其他类型（符号链接、设备文件等）忽略
    else
    {
        cpk_printf(WARNING, "Skipping non-regular file/directory '%s'", src_path);
        return 0;
    }
}

/**
 * @brief 调用脚本
 * @param script_path 脚本路径
 * @return 0 表示成功，非0表示失败
 */
int execute_script(const char *script_path)
{
    struct stat sb;
    // 检查脚本是否存在
    if (stat(script_path, &sb) != 0) 
    {
        // 脚本不存在，这不是错误（可选脚本）
        return 0;
    }
    
    // 检查是否是常规文件
    if (!S_ISREG(sb.st_mode))
    {
        // 不是常规文件，忽略
        return 0;
    }
    
    // 检查是否可执行
    if (!(sb.st_mode & S_IXUSR) && !(sb.st_mode & S_IXGRP) && !(sb.st_mode & S_IXOTH))
    {
        // 尝试添加执行权限
        if (chmod(script_path, sb.st_mode | S_IXUSR) != 0)
        {
            // 无法设置执行权限
            cpk_printf(WARNING, "Script '%s' is not executable and cannot be made executable\n", script_path);
            return 0;
        }
    }
    
    // 执行脚本
    char command[MAX_COMMAND_LEN];
    // 使用绝对路径的bash，避免shell注入
    snprintf(command, sizeof(command), "/bin/bash '%s'", script_path);
    
    int ret = system(command);
    if (ret != 0) 
    {
        cpk_printf(ERROR, "Script '%s' execution failed with return code: %d\n", script_path, WEXITSTATUS(ret));
        return -1; // 脚本执行失败
    }
    
    return 0; // 成功
}

/**
 * @brief 确认安装（移除）单个软件包
 * @param pkg_name 软件包名称
 * @param action 操作类型（安装或移除）
 * @return 0 表示成功，非0表示失败
 */
int confirm_package_action(const char *pkg_name, const char *action) 
{
    char response[4];
    printf("Are you sure you want to %s the package '%s'? (Y/n): ", action, pkg_name);

    // yes/no 输入处理，yes y Y \n都视为确认
    if (fgets(response, sizeof(response), stdin) != NULL) 
    {
        // 去除换行符
        response[strcspn(response, "\n")] = 0;
        if (strcmp(response, "yes") == 0 || strcmp(response, "y") == 0 || strcmp(response, "Y") == 0 || strcmp(response, "") == 0)
        {
            return 0; // 确认操作
        }
    }
    printf("Operation cancelled by user.\n");
    return 1; // 取消操作
}

/**
 * @brief 解析列表（如 {"path1","path2"}）
 * @param value 列表字符串
 * @param list 存储列表元素的数组
 * @param count 列表元素数量
 * @return 0 成功，-1 失败
 */
int parse_list(const char* value, char list[][256], int *count) 
{
    int max_count = *count;
    *count = 0;
    
    // 跳过空格
    while (*value && isspace(*value)) value++;
    
    // 检查是否以 { 开头
    if (*value != '{') 
    {
        return -1; // 格式错误
    }
    value++;
    
    // 解析列表内容
    while (*value && *value != '}') 
    {
        // 跳过空格
        while (*value && isspace(*value)) value++;
        if (*value == '}' || *value == '\0') break;
        
        // 检查是否有引号
        char quote_char = '\0';
        if (*value == '"' || *value == '\'') 
        {
            quote_char = *value;
            value++;
        }
        
        // 提取路径
        char buffer[256] = {0};
        int i = 0;
        while (*value && i < 255) 
        {
            if (quote_char) 
            {
                if (*value == quote_char) 
                {
                    value++;
                    break;
                }
            }
            else
            {
                if (*value == ',' || *value == '}') break;
            }
            buffer[i++] = *value++;
        }
        buffer[i] = '\0';
        
        // 去除尾部空格
        while (i > 0 && isspace(buffer[i-1])) 
        {
            buffer[--i] = '\0';
        }
        
        // 保存到列表
        if (i > 0 && *count < max_count) 
        {
            strcpy(list[*count], buffer);
            (*count)++;
        }
        
        // 跳过逗号
        if (*value == ',') value++;
        while (*value && isspace(*value)) value++;
    }
    
    return 0;
}

/**
 * @brief 解析路径函数调用（如 include_path("path") 或 include_path(NULL)）
 * @param line 包含路径函数调用的行
 * @param func_name 存储函数名的缓冲区
 * @param path 存储路径的缓冲区
 * @return 0 成功，-1 失败
 */
int parse_path_call(const char* line, char* func_name, char* path) 
{
    // 查找 '('
    const char* start = strchr(line, '(');
    if (!start) return -1;
    
    // 提取函数名
    int func_len = start - line;
    while (func_len > 0 && isspace(line[func_len-1])) func_len--;
    strncpy(func_name, line, func_len);
    func_name[func_len] = '\0';
    
    // 查找 ')'
    const char* end = strchr(start, ')');
    if (!end) return -1;
    
    // 提取参数
    start++; // 跳过 '('
    int path_len = end - start;
    while (path_len > 0 && isspace(start[path_len-1])) path_len--;
    
    if (path_len == 0) 
    {
        path[0] = '\0';
    } 
    else 
    {
        // 检查是否为 NULL
        if (strncasecmp(start, "NULL", 4) == 0) 
        {
            path[0] = '\0';
        } 
        else 
        {
            // 去除可能的引号
            char quote_char = '\0';
            if (*start == '"' || *start == '\'') 
            {
                quote_char = *start;
                start++;
                path_len--;
                
                if (path_len > 0 && start[path_len-1] == quote_char) 
                {
                    path_len--;
                }
            }
            
            strncpy(path, start, path_len);
            path[path_len] = '\0';
        }
    }
    
    return 0;
}

/**
 * @brief 解析 control 文件
 * @param control_file_path control 文件路径
 * @param info 存储解析结果的 ControlInfo 结构体指针
 * @return 0 成功，1 失败
 */
int parse_control_file(const char* control_file_path, ControlInfo* info)
{
    // 初始化结构体
    memset(info, 0, sizeof(ControlInfo));
    
    FILE *control_file = fopen(control_file_path, "r");
    if (!control_file) 
    {
        cpk_printf(ERROR, "Failed to open control file: %s", control_file_path);
        return 1;
    }
    
    char line[MAX_LINE_LEN];
    int line_num = 0;
    
    while (fgets(line, sizeof(line), control_file)) 
    {
        line_num++;
        
        // 去除换行符
        line[strcspn(line, "\n")] = '\0';
        
        // 跳过空格
        char *p = line;
        while (*p && isspace(*p)) p++;
        
        // 跳过空行和注释
        if (*p == '\0' || *p == '#') 
        {
            continue;
        }
        
        // 检查是否是路径函数调用
        if (strstr(p, "include_path") && strchr(p, '(') && strchr(p, ')')) 
        {
            if (info->include_path_set) 
            {
                cpk_printf(ERROR, "Duplicate include_path at line %d", line_num);
                fclose(control_file);
                return 1;
            }
            
            char func_name[32];
            if (parse_path_call(p, func_name, info->include_path) == 0) 
            {
                if (strcmp(func_name, "include_path") == 0) 
                {
                    info->include_path_set = 1;
                } 
                else 
                {
                    cpk_printf(ERROR, "Unknown function: %s at line %d", func_name, line_num);
                    fclose(control_file);
                    return 1;
                }
            } 
            else 
            {
                cpk_printf(ERROR, "Invalid include_path format at line %d", line_num);
                fclose(control_file);
                return 1;
            }
            continue;
        }
        
        if (strstr(p, "lib_path") && strchr(p, '(') && strchr(p, ')')) 
        {
            if (info->lib_path_set) 
            {
                cpk_printf(ERROR, "Duplicate lib_path at line %d", line_num);
                fclose(control_file);
                return 1;
            }
            
            char func_name[32];
            if (parse_path_call(p, func_name, info->lib_path) == 0) 
            {
                if (strcmp(func_name, "lib_path") == 0) 
                {
                    info->lib_path_set = 1;
                } 
                else 
                {
                    cpk_printf(ERROR, "Unknown function: %s at line %d", func_name, line_num);
                    fclose(control_file);
                    return 1;
                }
            } 
            else 
            {
                cpk_printf(ERROR, "Invalid lib_path format at line %d", line_num);
                fclose(control_file);
                return 1;
            }
            continue;
        }
        
        // 解析键值对
        char *colon = strchr(p, ':');
        if (!colon) 
        {
            cpk_printf(WARNING, "Invalid format at line %d (missing colon)", line_num);
            continue;
        }
        
        // 提取键
        char key[64] = {0};
        int key_len = colon - p;
        while (key_len > 0 && isspace(p[key_len-1])) key_len--;
        strncpy(key, p, key_len);
        key[key_len] = '\0';
        
        // 提取值
        char *value = colon + 1;
        while (*value && isspace(*value)) value++;
        
        // 去除注释
        char *comment = strchr(value, '#');
        if (comment) 
        {
            *comment = '\0';
            // 去除尾部空格
            while (comment > value && isspace(*(comment-1))) 
            {
                *(--comment) = '\0';
            }
        }
        
        // 处理不同的键
        if (strcmp(key, "packet") == 0) 
        {
            if (info->packet_set) 
            {
                cpk_printf(ERROR, "Duplicate packet at line %d", line_num);
                fclose(control_file);
                return 1;
            }
            strncpy(info->packet, value, sizeof(info->packet)-1);
            info->packet_set = 1;
        }
        else if (strcmp(key, "version") == 0) 
        {
            if (info->version_set) 
            {
                cpk_printf(ERROR, "Duplicate version at line %d", line_num);
                fclose(control_file);
                return 1;
            }
            strncpy(info->version, value, sizeof(info->version)-1);
            info->version_set = 1;
        }
        else if (strcmp(key, "brief") == 0) 
        {
            if (info->brief_set) 
            {
                cpk_printf(ERROR, "Duplicate brief at line %d", line_num);
                fclose(control_file);
                return 1;
            }
            // 去除引号
            if (*value == '"' && value[strlen(value)-1] == '"') 
            {
                value[strlen(value)-1] = '\0';
                strncpy(info->brief, value+1, sizeof(info->brief)-1);
            } 
            else 
            {
                strncpy(info->brief, value, sizeof(info->brief)-1);
            }
            info->brief_set = 1;
        }
        else if (strcmp(key, "include") == 0) 
        {
            if (info->include_set) 
            {
                cpk_printf(ERROR, "Duplicate include at line %d", line_num);
                fclose(control_file);
                return 1;
            }
            info->include_count = 10; // 设置最大数量
            if (parse_list(value, info->include, &info->include_count) != 0) 
            {
                cpk_printf(ERROR, "Invalid include list format at line %d", line_num);
                fclose(control_file);
                return 1;
            }
            info->include_set = 1;
        }
        else if (strcmp(key, "lib") == 0) 
        {
            if (info->lib_set) 
            {
                cpk_printf(ERROR, "Duplicate lib at line %d", line_num);
                fclose(control_file);
                return 1;
            }
            info->lib_count = 10; // 设置最大数量
            if (parse_list(value, info->lib, &info->lib_count) != 0) 
            {
                cpk_printf(ERROR, "Invalid lib list format at line %d", line_num);
                fclose(control_file);
                return 1;
            }
            info->lib_set = 1;
        }
        else 
        {
            cpk_printf(WARNING, "Unknown key '%s' at line %d", key, line_num);
        }
    }
    
    fclose(control_file);
    
    // 检查完整性
    int missing = 0;
    if (!info->packet_set) 
    {
        cpk_printf(ERROR, "Missing required field: packet");
        missing++;
    }
    if (!info->version_set) 
    {
        cpk_printf(ERROR, "Missing required field: version");
        missing++;
    }
    if (!info->brief_set) 
    {
        cpk_printf(ERROR, "Missing required field: brief");
        missing++;
    }
    if (!info->include_set) 
    {
        cpk_printf(ERROR, "Missing required field: include");
        missing++;
    }
    if (!info->lib_set) 
    {
        cpk_printf(ERROR, "Missing required field: lib");
        missing++;
    }
    if (!info->include_path_set) 
    {
        cpk_printf(ERROR, "Missing required field: include_path");
        missing++;
    }
    if (!info->lib_path_set) 
    {
        cpk_printf(ERROR, "Missing required field: lib_path");
        missing++;
    }
    
    if (missing > 0) 
    {
        return 1;
    }
    
    return 0;
}

/**
 * @brief 打印 ControlInfo 结构体内容
 * @param info ControlInfo 结构体指针
 */
void print_control_info(const ControlInfo* info)
{
    cpk_printf(INFO, "Control file parsed successfully:");
    cpk_printf(INFO, "  packet: %s", info->packet);
    cpk_printf(INFO, "  version: %s", info->version);
    cpk_printf(INFO, "  brief: %s", info->brief);
    cpk_printf(INFO, "  include: %d items", info->include_count);
    for (int i = 0; i < info->include_count; i++) 
    {
        cpk_printf(INFO, "    - %s", info->include[i]);
    }
    cpk_printf(INFO, "  lib: %d items", info->lib_count);
    for (int i = 0; i < info->lib_count; i++) 
    {
        cpk_printf(INFO, "    - %s", info->lib[i]);
    }
    cpk_printf(INFO, "  include_path: %s", info->include_path[0] ? info->include_path : "NULL");
    cpk_printf(INFO, "  lib_path: %s", info->lib_path[0] ? info->lib_path : "NULL");
}

/**
 * @brief 根据 ControlInfo 创建安装/卸载脚本
 * @param build_path 构建路径
 * @param control_file_path control文件路径
 * @param info ControlInfo结构体指针
 * @return 0 成功，-1 失败
 */
int create_script(const char* build_path, const char* control_file_path, const ControlInfo* info)
{
    // 创建安装脚本
    char install_script_path[MAX_PATH_LEN];
    sprintf(install_script_path, "%s/%s/%s", build_path, META_DIR, INSTALL_SCRIPT);
    
    FILE *install_script = fopen(install_script_path, "w");
    if (!install_script)
    {
        cpk_printf(ERROR, "Failed to create install script: %s", install_script_path);
        return -1;
    }
    
    // 写入安装脚本头部
    fprintf(install_script, "#!/bin/bash\n");
    fprintf(install_script, "# %s - %s\n", info->packet, info->brief);
    fprintf(install_script, "# Installation script generated by cpkg\n\n");
    
    // 设置安装路径变量
    const char *include_dest = info->include_path[0] ? info->include_path : "/usr/include";
    const char *lib_dest = info->lib_path[0] ? info->lib_path : "/usr/lib";
    
    fprintf(install_script, "# Installation directories\n");
    fprintf(install_script, "INCLUDE_DEST=\"%s\"\n", include_dest);
    fprintf(install_script, "LIB_DEST=\"%s\"\n", lib_dest);
    fprintf(install_script, "PACKAGE_NAME=\"%s\"\n\n", info->packet);
    
    // 创建目标目录（如果不存在）
    fprintf(install_script, "# Create destination directories if they don't exist\n");
    fprintf(install_script, "mkdir -p \"$INCLUDE_DEST\"\n");
    fprintf(install_script, "mkdir -p \"$LIB_DEST\"\n\n");
    
    // 安装头文件
    if (info->include_count > 0)
    {
        fprintf(install_script, "# Install header files\n");
        for (int i = 0; i < info->include_count; i++)
        {
            // 提取文件名
            char *filename = strrchr(info->include[i], '/');
            if (filename)
                filename++;
            else
                filename = (char *)info->include[i];
            
            fprintf(install_script, "echo \"Installing header: %s\"\n", filename);
            fprintf(install_script, "cp \"$PWD/include/%s\" \"$INCLUDE_DEST/\" 2>/dev/null || {\n", filename);
            fprintf(install_script, "  echo \"Failed to install header: %s\"\n", filename);
            fprintf(install_script, "  exit 1\n");
            fprintf(install_script, "}\n");
        }
        fprintf(install_script, "\n");
    }
    
    // 安装库文件
    if (info->lib_count > 0)
    {
        fprintf(install_script, "# Install library files\n");
        for (int i = 0; i < info->lib_count; i++)
        {
            // 提取文件名
            char *filename = strrchr(info->lib[i], '/');
            if (filename)
                filename++;
            else
                filename = (char *)info->lib[i];
            
            fprintf(install_script, "echo \"Installing library: %s\"\n", filename);
            fprintf(install_script, "cp \"$PWD/lib/%s\" \"$LIB_DEST/\" 2>/dev/null || {\n", filename);
            fprintf(install_script, "  echo \"Failed to install library: %s\"\n", filename);
            fprintf(install_script, "  exit 1\n");
            fprintf(install_script, "}\n");
            
            // 如果是共享库，可能需要运行 ldconfig
            if (strstr(filename, ".so") != NULL)
            {
                fprintf(install_script, "echo \"Running ldconfig for shared library\"\n");
                fprintf(install_script, "ldconfig 2>/dev/null || true\n");
            }
        }
        fprintf(install_script, "\n");
    }
    
    // 更新已安装包列表
    fprintf(install_script, "# Update installed packages list\n");
    fprintf(install_script, "INSTALLED_FILE=\"%s/%s\"\n", WORK_DIR, INSTALLED_LOG_FILE);
    fprintf(install_script, "echo \"%s\" >> \"$INSTALLED_FILE\"\n", info->packet);
    
    fprintf(install_script, "\necho \"Installation of %s completed successfully!\"\n", info->packet);
    fprintf(install_script, "exit 0\n");
    
    fclose(install_script);
    
    // 设置安装脚本执行权限
    if (chmod(install_script_path, 0755) != 0)
    {
        cpk_printf(WARNING, "Failed to set execute permission on install script: %s", 
                  strerror(errno));
    }
    
    // 创建卸载脚本
    char remove_script_path[MAX_PATH_LEN];
    sprintf(remove_script_path, "%s/%s/%s", build_path, META_DIR, REMOVE_SCRIPT);
    
    FILE *remove_script = fopen(remove_script_path, "w");
    if (!remove_script)
    {
        cpk_printf(ERROR, "Failed to create remove script: %s", remove_script_path);
        return -1;
    }
    
    // 写入卸载脚本头部
    fprintf(remove_script, "#!/bin/bash\n");
    fprintf(remove_script, "# %s - %s\n", info->packet, info->brief);
    fprintf(remove_script, "# Removal script generated by cpkg\n\n");
    
    // 设置卸载路径变量
    fprintf(remove_script, "# Removal directories\n");
    fprintf(remove_script, "INCLUDE_DEST=\"%s\"\n", include_dest);
    fprintf(remove_script, "LIB_DEST=\"%s\"\n", lib_dest);
    fprintf(remove_script, "PACKAGE_NAME=\"%s\"\n\n", info->packet);
    
    // 询问确认
    fprintf(remove_script, "# Ask for confirmation\n");
    fprintf(remove_script, "read -p \"Are you sure you want to remove %s? (y/N): \" confirm\n", info->packet);
    fprintf(remove_script, "if [[ ! \"$confirm\" =~ ^[Yy]$ ]]; then\n");
    fprintf(remove_script, "  echo \"Removal cancelled.\"\n");
    fprintf(remove_script, "  exit 0\n");
    fprintf(remove_script, "fi\n\n");
    
    // 移除头文件
    if (info->include_count > 0)
    {
        fprintf(remove_script, "# Remove header files\n");
        for (int i = 0; i < info->include_count; i++)
        {
            // 提取文件名
            char *filename = strrchr(info->include[i], '/');
            if (filename)
                filename++;
            else
                filename = (char *)info->include[i];
            
            fprintf(remove_script, "echo \"Removing header: %s\"\n", filename);
            fprintf(remove_script, "rm -f \"$INCLUDE_DEST/%s\" 2>/dev/null || {\n", filename);
            fprintf(remove_script, "  echo \"Warning: Could not remove header: %s\"\n", filename);
            fprintf(remove_script, "}\n");
        }
        fprintf(remove_script, "\n");
    }
    
    // 移除库文件
    if (info->lib_count > 0)
    {
        fprintf(remove_script, "# Remove library files\n");
        for (int i = 0; i < info->lib_count; i++)
        {
            // 提取文件名
            char *filename = strrchr(info->lib[i], '/');
            if (filename)
                filename++;
            else
                filename = (char *)info->lib[i];
            
            fprintf(remove_script, "echo \"Removing library: %s\"\n", filename);
            fprintf(remove_script, "rm -f \"$LIB_DEST/%s\" 2>/dev/null || {\n", filename);
            fprintf(remove_script, "  echo \"Warning: Could not remove library: %s\"\n", filename);
            fprintf(remove_script, "}\n");
            
            // 如果是共享库，运行 ldconfig
            if (strstr(filename, ".so") != NULL)
            {
                fprintf(remove_script, "echo \"Running ldconfig after library removal\"\n");
                fprintf(remove_script, "ldconfig 2>/dev/null || true\n");
            }
        }
        fprintf(remove_script, "\n");
    }
    
    // 从已安装包列表中移除
    fprintf(remove_script, "# Remove from installed packages list\n");
    fprintf(remove_script, "INSTALLED_FILE=\"%s/%s\"\n", WORK_DIR, INSTALLED_LOG_FILE);
    fprintf(remove_script, "if [ -f \"$INSTALLED_FILE\" ]; then\n");
    fprintf(remove_script, "  grep -v \"^%s$\" \"$INSTALLED_FILE\" > \"$INSTALLED_FILE.tmp\"\n", info->packet);
    fprintf(remove_script, "  mv \"$INSTALLED_FILE.tmp\" \"$INSTALLED_FILE\"\n");
    fprintf(remove_script, "fi\n\n");
    
    fprintf(remove_script, "echo \"Removal of %s completed successfully!\"\n", info->packet);
    fprintf(remove_script, "exit 0\n");
    
    fclose(remove_script);
    
    // 设置卸载脚本执行权限
    if (chmod(remove_script_path, 0755) != 0)
    {
        cpk_printf(WARNING, "Failed to set execute permission on remove script: %s", 
                  strerror(errno));
    }
    
    cpk_printf(INFO, "Created install script: %s", install_script_path);
    cpk_printf(INFO, "Created remove script: %s", remove_script_path);
    
    return 0;
}
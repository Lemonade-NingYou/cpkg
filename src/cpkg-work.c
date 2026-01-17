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

#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <string.h>
#include <archive.h>
#include <archive_entry.h>
#include <openssl/sha.h>
#include <unistd.h>
#include "../include/help.h"
#include "../include/cpkg.h"

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
 * @brief 检查哈希值 SHA256 OpenSSL实现
 * @param pkg_file 软件包文件指针
 * @param expected_hash 预期的哈希值
 * @return 0 表示成功，非0表示失败
 */
int check_hash(FILE *pkg_file, const unsigned char *expected_hash) 
{
    SHA256_CTX sha256; // SHA256 上下文
    unsigned char hash[SHA256_DIGEST_LENGTH]; // 计算得到的哈希值
    unsigned char buffer[4096]; // 读取缓冲区
    size_t bytes_read; // 读取的字节数

    SHA256_Init(&sha256); // 初始化 SHA256 上下文
    fseek(pkg_file, CPK_HEADER_SIZE, SEEK_SET); // 跳过头部

    // 读取文件并计算哈希值
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), pkg_file)) != 0) 
    {
        SHA256_Update(&sha256, buffer, bytes_read); // 更新哈希计算
    }

    SHA256_Final(hash, &sha256); // 完成哈希计算

    // 比较计算得到的哈希值与预期哈希值
    if (memcmp(hash, expected_hash, SHA256_DIGEST_LENGTH) != 0) 
    {
        return -1; // 哈希值不匹配
    }
    return 0; // 哈希值匹配
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
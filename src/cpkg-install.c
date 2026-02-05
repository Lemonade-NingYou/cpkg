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
#include "../include/cpkg.h"
#include "../include/help.h"

/**
 * @brief 安装单个软件包
 * @param pkg_path 软件包路径
 * @return 0 表示成功，非0表示失败
 */
int install_package(const char *pkg_path) 
{
    // sudo 权限检查
    if (check_sudo_privileges()) 
    {
        cpk_printf(ERROR, "This operation requires sudo privileges.\n");
        return 1; // 返回1表示失败
    }

    if(!pkg_path)
    {
        cpk_printf(ERROR, "--install requires at least one package file as an argument.\n");
        less_info_cpkg();
        return 1; // 返回1表示失败
    }
    
    // 检查软件包文件是否存在
    FILE *pkg_file = fopen(pkg_path, "rb");
    if (!pkg_file) 
    {
        cpk_printf(ERROR, "Package file '%s' not found.\n", pkg_path);
        return 1; // 返回1表示失败
    }

    // 读取 CPK 头部
    CPK_Header header;
    if (read_cpk_header(pkg_file, &header))
    {
        cpk_printf(ERROR, "Failed to read or verify CPK header.\n");
        fclose(pkg_file);
        return 1; // 返回1表示失败
    }
    
    // 检查哈希值
    if(check_hash(pkg_file, header.hash))
    {
        cpk_printf(ERROR, "Package hash verification failed.\n");
        fclose(pkg_file);
        return 1; // 返回1表示失败
    }

        // 确认安装操作
    if (confirm_package_action(header.name, "install")) 
    {
        cpk_printf(INFO, "Package installation cancelled by user: %s\n", header.name);
        // 关闭文件
        fclose(pkg_file);
        return 0; // 用户取消操作，返回0表示成功
    }

    // 解压缩软件包内容到安装目录 tar.gz 解压缩
    char install_dir[MAX_PATH_LEN];
    snprintf(install_dir, sizeof(install_dir), "%s/%s", WORK_DIR, INSTALL_DIR); // 使用 snprintf 替代 strcat
    if(uncompress_package(pkg_file, install_dir))
    {
        cpk_printf(ERROR, "Failed to extract package contents.\n");
        fclose(pkg_file);
        return 1; // 返回1表示失败
    }

    // 调用安装脚本（如果存在）
    char script_path[MAX_PATH_LEN];
    snprintf(script_path, sizeof(script_path), "%s/%s/%s", install_dir, header.name, INSTALL_SCRIPT);
    if(execute_script(script_path))
    {
        cpk_printf(WARNING, "Installation script execution failed or not found. Continuing installation.\n");
    }

    // 记录已安装软件包信息
    char installed_path[MAX_PATH_LEN];
    snprintf(installed_path, sizeof(installed_path), "%s/%s", install_dir, header.name);
    FILE *installed_file = fopen(installed_path, "a");
    if (installed_file) 
    {
        fprintf(installed_file, "%s %u\n", header.name, header.version);
        fclose(installed_file);
    }
    else 
    {
        // 格式： 软件包名称:安装路径:版本号
        fprintf(installed_file, "%s:%s:%u\n", header.name, install_dir, header.version);
    }

    cpk_printf(INFO, "Package '%s' installed successfully.\n", header.name);
    fclose(pkg_file);
    return 0; // 返回0表示成功
}
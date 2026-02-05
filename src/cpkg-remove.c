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
#include <string.h>
#include "../include/cpkg.h"
#include "../include/help.h"

/**
 * @brief 移除单个软件包
 * @param pkg_name 软件包名称
 * @return 0 表示成功，非0表示失败
 */
int remove_package(const char *pkg_name) 
{
    // sudo 权限检查
    if (check_sudo_privileges()) 
    {
        cpk_printf(ERROR, "This operation requires sudo privileges.\n");
        return 1; // 返回1表示失败
    }

    if (!pkg_name)
    {
        cpk_printf(ERROR, "--remove (without --pending) needs at least one package name argument\n");
        less_info_cpkg();
        return 1; // 返回1表示失败
    }
    
    // 构建已安装包日志文件路径
    char pkg_path[512];
    snprintf(pkg_path, sizeof(pkg_path), "%s/%s", WORK_DIR, INSTALLED_LOG_FILE);

    // 构建临时已安装包日志文件路径
    char temp_pkg_path[512];
    snprintf(temp_pkg_path, sizeof(temp_pkg_path), "%s/%s.tmp", WORK_DIR, INSTALLED_LOG_FILE); 

    // 打开已安装包日志文件
    FILE *log_file = fopen(pkg_path, "r");
    if (!log_file) 
    {
        cpk_printf(ERROR, "Failed to open installed packages log file: %s\n", pkg_path);
        return 1;
    }

    FILE *temp_log_file = fopen(temp_pkg_path, "w");
    if (!temp_log_file) 
    {
        cpk_printf(ERROR, "Failed to open temporary log file: %s\n", temp_pkg_path);
        fclose(log_file);
        return 1;
    }

    // 格式： 软件包名称:安装路径:版本号
    // 查找软件包信息，并将非目标包写入临时文件，以实现删除效果
    char line[MAX_LINE_LEN];
    char remove_script_path[MAX_PATH_LEN];
    int found = 0;
    while (fgets(line, sizeof(line), log_file)) 
    {
        char current_pkg_name[64];
        char installed_path[256];
        char version[64];
        if (sscanf(line, "%63[^:]:%255[^:]:%63[^\n]", current_pkg_name, installed_path, version) < 1) 
        {
            continue;
        }

        if (strcmp(current_pkg_name, pkg_name) == 0) 
        {
            found = 1; // 找到目标包，跳过写入
            snprintf(remove_script_path, sizeof(remove_script_path), "%s", installed_path);
            continue;
        }
        fputs(line, temp_log_file); // 写入非目标包信息
    }

    // 关闭文件
    fclose(log_file);
    fclose(temp_log_file);

    // 检查是否找到软件包
    if (!found)
    {
        cpk_printf(ERROR, "Package not found in installed packages log: %s\n", pkg_name);
        return 1;
    }

    // 确认安装（移除）操作
    if (confirm_package_action(pkg_name, "remove")) 
    {
        cpk_printf(INFO, "Package removal cancelled by user: %s\n", pkg_name);
        // 删除临时文件
        remove(temp_pkg_path);
        return 0; // 用户取消操作，返回0表示成功
    }

    // 构建卸载脚本路径
    snprintf(remove_script_path, sizeof(remove_script_path), "%s/%s/%s/%s/%s", WORK_DIR, INSTALL_DIR, remove_script_path, META_DIR, REMOVE_SCRIPT);
    // 执行卸载脚本（如果存在）
    if (execute_script(remove_script_path))
    {
        cpk_printf(WARNING, "Removal script execution failed or not found. Continuing removal.\n");
    }

    // 删除旧日志文件并重命名临时日志文件
    if (remove(pkg_path) != 0)
    {
        cpk_printf(ERROR, "Failed to remove old log file: %s\n", pkg_path);
        return 1;
    }

    if (rename(temp_pkg_path, pkg_path) != 0)
    {
        cpk_printf(ERROR, "Failed to rename temporary log file to original: %s\n", pkg_path);
        return 1;
    }

    return 0;
}
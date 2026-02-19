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
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/stat.h>
#include <dirent.h>
#include "../include/cpkg.h"
#include "../include/help.h"

/**
 * @brief 移除已安装的软件包
 * @param pkg_name 软件包名称
 * @return 0 表示成功，非0表示失败
 */
int remove_package(const char *pkg_name) 
{
    if (!pkg_name || strlen(pkg_name) == 0) {
        cpk_printf(ERROR, "Package name cannot be empty.\n");
        return 1;
    }

    // 检查权限
    if (check_sudo_privileges() != 0) {
        cpk_printf(ERROR, "This operation requires sudo privileges.\n");
        return 1;
    }

    // 从工作目录查找已安装的包
    char pkg_install_path[MAX_PATH_LEN];
    snprintf(pkg_install_path, MAX_PATH_LEN, "%s/%s/%s", WORK_DIR_NAME, INSTALL_DIR, pkg_name);

    // 检查包是否存在
    struct stat st;
    if (stat(pkg_install_path, &st) != 0) {
        cpk_printf(ERROR, "Package '%s' is not installed.\n", pkg_name);
        return 1;
    }

    cpk_printf(INFO, "Removing package: %s\n", pkg_name);

    // 移除包文件（递归删除整个目录）
    if (rm_rf(pkg_install_path) != 0) {
        cpk_printf(ERROR, "Failed to remove package '%s'.\n", pkg_name);
        return 1;
    }

    // 列出移除前的内容（可选，用于调试）
    printf("Verifying removal...\n");
    if (stat(pkg_install_path, &st) == 0) {
        cpk_printf(WARNING, "Package directory still exists after removal attempt.\n");
        return 1;
    }

    printf("Package '%s' removed successfully.\n", pkg_name);
    return 0;
}
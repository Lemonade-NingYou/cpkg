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
#ifndef OPENAPI_H
#define OPENAPI_H

#include <stdbool.h>
#include <stdio.h>

/**
 * @brief 将项目构建为 .cpl 包文件。
 * @param BuildPath 包含 config.txt 的项目目录路径。
 * @return 成功返回 0，失败返回非零错误码（参见 outerror.h）。
 */
int CPKG_build(char *BuildPath);

/**
 * @brief 安装 .cpl 包到系统目录（/usr/lib/... 和 /usr/include/...）。
 * @param InstallPath .cpl 包文件的路径。
 * @return 成功返回 0，失败返回非零错误码。
 */
int CPKG_install(char *InstallPath);

/**
 * @brief 卸载已安装的包（根据记录文件删除已安装文件）。
 * @param PocketName 要卸载的包名（与记录文件名对应）。
 * @return 成功返回 0，失败返回非零错误码。
 */
int CPKG_remove(char *PocketName);

/**
 * @brief 列出所有已安装的包。
 * @return 成功返回 Successful (0)，失败返回错误码（如目录打开失败）。
 */
int CPKG_list(void);
#endif // OPENAPI_H
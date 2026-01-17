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
#include <stdbool.h>
#include <string.h>
#include "../include/cpkg.h"
#include "../include/help.h"

/**
 * @brief 实现软件包信息查询功能
 * @param package_path 软件包路径
 * @return 成功返回0，失败返回非0
 */
int info_package(const char *package_path)
{
    FILE *file = fopen(package_path, "rb");
    if (file == NULL) 
    {
        cpk_printf(ERROR, "无法打开软件包文件: %s\n", package_path);
        return 1;
    }

    CPK_Header header;
    if (!read_cpk_header(file, &header)) 
    {
        cpk_printf(ERROR, "无法读取软件包头部信息\n");
        fclose(file);
        return 1;
    }

    printf("软件包名称: %s\n", header.name);
    printf("    版本号: %u\n", header.version);
    printf("    描述: %s\n", header.description);
    printf("    作者: %s\n", header.author);
    printf("    许可证: %s\n", header.license);

    fclose(file);
    return 0;
}
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

#include "../include/help.h"
#include "../include/cpkg.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>

int cpkg_list(void)
{
    printf("Reading package list...\n");

    char installed_txt_path[MAX_PATH_LEN];
    snprintf(installed_txt_path, sizeof(installed_txt_path),
             "%s/installed.txt", WORK_DIR_NAME);

    FILE *fp = fopen(installed_txt_path, "rb");
    if (fp == NULL) {
        if (errno == ENOENT) {
            cpk_printf(ERROR, "No packages installed.\n");
            return 0;
        }
        cpk_printf(ERROR, "Failed to open file: %s\n", installed_txt_path);
        return -1;
    }

    CPK_Header header;
    int include_count, lib_count;
    char **include_files = NULL;
    char **lib_files = NULL;
    int record_num = 0;
    int ret;

    while (1) {
        ret = read_install_file(fp, &header, &include_count, &include_files,
                                &lib_count, &lib_files);
        if (ret != 0) {
            if (feof(fp))
                break; // 正常结束
            // 读取错误
            cpk_printf(ERROR, "Failed to read package record %d: %s\n", record_num + 1, strerror(errno));
            fclose(fp);
            return -1;
        }

        record_num++;
        // 输出包名和版本
        printf("%s %s\n", header.name, header.version);

        // 释放动态分配的文件列表
        if (include_files) {
            for (int i = 0; i < include_count; i++)
                free(include_files[i]);
            free(include_files);
        }
        if (lib_files) {
            for (int i = 0; i < lib_count; i++)
                free(lib_files[i]);
            free(lib_files);
        }
    }

    fclose(fp);

    if (record_num == 0)
        printf("No packages installed.\n");

    return 0;
}
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
#include "utils.h"
#include "outerror.h"
#include "openapi.h"
#include <cjson/cJSON.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/**
 * @brief 列出所有已安装的包。
 * @return 成功返回 Successful (0)，失败返回错误码（如目录打开失败）。
 */
int CPKG_list(void) {
    DIR *dir = opendir(WORK_DIR);
    if (!dir) {
        fprintf(stderr, "Failed to open work directory %s: %s\n", WORK_DIR, strerror(errno));
        return ReadRecordInformationError;  // 复用现有错误码
    }

    struct dirent *entry;
    int found = 0;

    while ((entry = readdir(dir)) != NULL) {
        const char *name = entry->d_name;
        size_t len = strlen(name);
        // 仅处理 .json 后缀的文件
        if (len < 5 || strcmp(name + len - 5, ".json") != 0)
            continue;

        char filepath[PATH_MAX];
        snprintf(filepath, sizeof(filepath), "%s/%s", WORK_DIR, name);

        FILE *fp = fopen(filepath, "r");
        if (!fp) {
            fprintf(stderr, "Warning: cannot open %s: %s\n", filepath, strerror(errno));
            continue;
        }

        // 读取整个文件
        fseek(fp, 0, SEEK_END);
        long size = ftell(fp);
        fseek(fp, 0, SEEK_SET);
        if (size <= 0) {
            fclose(fp);
            fprintf(stderr, "Warning: empty file %s\n", filepath);
            continue;
        }

        char *content = (char*)malloc(size + 1);
        if (!content) {
            fclose(fp);
            fprintf(stderr, "Warning: memory allocation failed for %s\n", filepath);
            continue;
        }
        size_t readbytes = fread(content, 1, size, fp);
        content[readbytes] = '\0';
        fclose(fp);

        // 解析 JSON
        cJSON *root = cJSON_Parse(content);
        free(content);
        if (!root) {
            fprintf(stderr, "Warning: invalid JSON in %s\n", filepath);
            continue;
        }

        // 提取字段
        cJSON *pname = cJSON_GetObjectItem(root, "PocketName");
        cJSON *ver = cJSON_GetObjectItem(root, "version");
        cJSON *authors = cJSON_GetObjectItem(root, "authors");
        cJSON *license = cJSON_GetObjectItem(root, "license");
        cJSON *desc = cJSON_GetObjectItem(root, "description");
        cJSON *home = cJSON_GetObjectItem(root, "homepage");
        cJSON *repo = cJSON_GetObjectItem(root, "repository");

        const char *pname_str = cJSON_IsString(pname) ? pname->valuestring : "N/A";
        const char *ver_str = cJSON_IsString(ver) ? ver->valuestring : "N/A";
        const char *license_str = cJSON_IsString(license) ? license->valuestring : "N/A";
        const char *desc_str = cJSON_IsString(desc) ? desc->valuestring : "N/A";
        const char *home_str = cJSON_IsString(home) ? home->valuestring : "N/A";
        const char *repo_str = cJSON_IsString(repo) ? repo->valuestring : "N/A";

        // 处理 authors 数组 → 转为逗号分隔的字符串
        char authors_str[1024] = "None";
        if (cJSON_IsArray(authors)) {
            int count = cJSON_GetArraySize(authors);
            if (count > 0) {
                char buf[1024] = "";
                for (int i = 0; i < count; i++) {
                    cJSON *item = cJSON_GetArrayItem(authors, i);
                    if (cJSON_IsString(item)) {
                        if (i > 0) strcat(buf, ", ");
                        strcat(buf, item->valuestring);
                    }
                }
                if (strlen(buf) > 0) {
                    strncpy(authors_str, buf, sizeof(authors_str) - 1);
                    authors_str[sizeof(authors_str)-1] = '\0';
                }
            }
        }

        // 打印包信息（首次打印表头）
        if (found == 0) {
            printf("Installed packages:\n");
        }
        printf("Package: %s\n", pname_str);
        printf("  Version: %s\n", ver_str);
        printf("  Authors: %s\n", authors_str);
        printf("  License: %s\n", license_str);
        printf("  Description: %s\n", desc_str);
        printf("  Homepage: %s\n", home_str);
        printf("  Repository: %s\n", repo_str);
        printf("----------------------------------------\n");

        found++;
        cJSON_Delete(root);
    }

    closedir(dir);

    if (found == 0) {
        printf("No installed packages found.\n");
    }

    return Successful;
}
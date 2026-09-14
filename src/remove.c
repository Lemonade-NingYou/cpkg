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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* 仅允许删除以下前缀内的文件，防止 manifest 被篡改后任意删除系统文件 */
static const char *allowed_prefixes[] = {
    "/usr/lib/",
    "/usr/include/",
    "/usr/share/cpkg/manual/",
    NULL
};

static int is_safe_to_unlink(const char *path) {
    if (!path) return 0;
    if (path[0] != '/') return 0;
    if (strstr(path, "/../") != NULL) return 0;
    for (int i = 0; allowed_prefixes[i]; i++) {
        if (strncmp(path, allowed_prefixes[i], strlen(allowed_prefixes[i])) == 0)
            return 1;
    }
    return 0;
}

int CPKG_remove(char *PocketName) {
    // 1. 上锁
    GetLock();

    // 2. 拼接记录文件路径并读取
    char record_path[PATH_MAX];
    snprintf(record_path, sizeof(record_path), "%s/%s.json", WORK_DIR, PocketName);
    FILE *fp = fopen(record_path, "r");
    if (fp == NULL) {
        ReleaseLock();
        return ReadRecordInformationError;
    }

    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (file_size <= 0) {
        fclose(fp);
        ReleaseLock();
        return ReadRecordInformationError;
    }

    char *json_str = (char *)malloc(file_size + 1);
    if (!json_str) {
        fclose(fp);
        ReleaseLock();
        return MemoryAllocError;
    }
    size_t bytes_read = fread(json_str, 1, file_size, fp);
    json_str[bytes_read] = '\0';
    fclose(fp);

    cJSON *root = cJSON_Parse(json_str);
    free(json_str);
    if (!root) {
        ReleaseLock();
        return ParseConfigError;
    }

    cJSON *files_array = cJSON_GetObjectItem(root, "installed_files");
    if (!cJSON_IsArray(files_array)) {
        cJSON_Delete(root);
        ReleaseLock();
        return ParseConfigError;
    }

    int array_size = cJSON_GetArraySize(files_array);
    int delete_failures = 0;

    // 3. 删除记录里的所有文件（带安全校验）
    for (int i = 0; i < array_size; i++) {
        cJSON *item = cJSON_GetArrayItem(files_array, i);
        if (cJSON_IsString(item)) {
            const char *file_path = item->valuestring;
            if (!is_safe_to_unlink(file_path)) {
                fprintf(stderr, "Warning: refusing to delete unsafe path %s\n", file_path);
                delete_failures++;
                continue;
            }
            if (unlink(file_path) != 0) {
                fprintf(stderr, "Warning: failed to delete %s: %s\n", file_path, strerror(errno));
                delete_failures++;
            }
        }
    }

    // 4. 尝试删除手册目录（空目录）
    char manual_dir[PATH_MAX];
    snprintf(manual_dir, sizeof(manual_dir), "%s%s", MANUAL_PATH, PocketName);
    rmdir(manual_dir);

    // 5. 删除记录文件本身
    if (remove(record_path) != 0) {
        fprintf(stderr, "Warning: failed to remove manifest file %s: %s\n", record_path, strerror(errno));
        delete_failures++;
    }

    cJSON_Delete(root);

    if (delete_failures > 0) {
        fprintf(stderr, "Package removed with %d error(s)\n", delete_failures);
        ReleaseLock();
        return RemoveFilesError;
    }

    printf("Package Remove successfully\n");
    ReleaseLock();
    return Successful;
}
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

    // 获取文件大小
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (file_size <= 0) {
        fclose(fp);
        ReleaseLock();
        return ReadRecordInformationError;
    }

    // 读取整个文件到缓冲区
    char *json_str = (char *)malloc(file_size + 1);
    if (!json_str) {
        fclose(fp);
        ReleaseLock();
        return MemoryAllocError;
    }
    size_t bytes_read = fread(json_str, 1, file_size, fp);
    json_str[bytes_read] = '\0';
    fclose(fp);

    // 解析 JSON
    cJSON *root = cJSON_Parse(json_str);
    free(json_str);
    if (!root) {
        ReleaseLock();
        return ParseConfigError;  // 解析失败
    }

    // 获取 installed_files 数组
    cJSON *files_array = cJSON_GetObjectItem(root, "installed_files");
    if (!cJSON_IsArray(files_array)) {
        cJSON_Delete(root);
        ReleaseLock();
        return ParseConfigError;
    }

    int array_size = cJSON_GetArraySize(files_array);
    int delete_failures = 0;

    // 3. 删除参数里的所有文件
    for (int i = 0; i < array_size; i++) {
        cJSON *item = cJSON_GetArrayItem(files_array, i);
        if (cJSON_IsString(item)) {
            const char *file_path = item->valuestring;
            if (unlink(file_path) != 0) {
                fprintf(stderr, "Warning: failed to delete %s: %s\n", file_path, strerror(errno));
                delete_failures++;
            }
        }
    }

    // 4. 删除记录文件本身
    if (remove(record_path) != 0) {
        fprintf(stderr, "Warning: failed to remove manifest file %s: %s\n", record_path, strerror(errno));
        delete_failures++;
    }

    cJSON_Delete(root);

    // 6. 返回结果，解锁
    if (delete_failures > 0) {
        fprintf(stderr, "Package removed with %d error(s)\n", delete_failures);
        ReleaseLock();
        return RemoveFilesError;  // 自定义错误码，可改用其他现有错误码
    }

    printf("Package Remove successfully\n");
    ReleaseLock();
    return Successful;
}
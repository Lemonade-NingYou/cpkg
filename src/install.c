#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

#include "openapi.h"
#include "outerror.h"
#include "utils.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

int CPKG_install(char* InstallPath) {
    // 检查工作目录
    if (is_dir(WORK_DIR) == false) {
        printf("welcome to use cpkg!\n");
        InitCpkg();
    }

    GetLock();

    FILE* CPLFile = fopen(InstallPath, "rb");
    if (CPLFile == NULL) {
        ReleaseLock();
        return OpenCPLFile;
    }

    // 验证魔术字
    int MagicReturn = VerifyMagic(CPLFile);
    if (MagicReturn != Successful) {
        fclose(CPLFile);
        ReleaseLock();
        return MagicReturn;
    }

    // 读取哈希
    unsigned char expected_hash[SHA256_LEN];
    if (fread(expected_hash, 1, SHA256_LEN, CPLFile) != SHA256_LEN) {
        fclose(CPLFile);
        ReleaseLock();
        return ReadHashError;
    }

    // 读取 JSON 大小
    unsigned char JsonSize[4];
    if (fread(JsonSize, 1, 4, CPLFile) != 4) {
        fclose(CPLFile);
        ReleaseLock();
        return ReadJsonSizeError;
    }
    uint32_t Jsonsize;
    memcpy(&Jsonsize, JsonSize, 4);

    unsigned char* JsonGzip = (unsigned char*)malloc(Jsonsize);
    if (JsonGzip == NULL) {
        fclose(CPLFile);
        ReleaseLock();
        return MemoryAllocError;
    }
    if (fread(JsonGzip, 1, Jsonsize, CPLFile) != Jsonsize) {
        fclose(CPLFile);
        free(JsonGzip);
        ReleaseLock();
        return ReadJsonMemoryError;
    }

    // 读取 Pocket 大小
    unsigned char PocketSize[4];
    if (fread(PocketSize, 1, 4, CPLFile) != 4) {
        fclose(CPLFile);
        free(JsonGzip);
        ReleaseLock();
        return ReadPocketSizeError;
    }
    uint32_t Pocketsize;
    memcpy(&Pocketsize, PocketSize, 4);

    unsigned char* PocketGzip = (unsigned char*)malloc(Pocketsize);
    if (PocketGzip == NULL) {
        fclose(CPLFile);
        free(JsonGzip);
        ReleaseLock();
        return MemoryAllocError;
    }
    if (fread(PocketGzip, 1, Pocketsize, CPLFile) != Pocketsize) {
        fclose(CPLFile);
        free(JsonGzip);
        free(PocketGzip);
        ReleaseLock();
        return ReadPocketMemoryError;
    }

    // 校验数据完整性
    size_t total_size = sizeof(uint32_t) + Jsonsize + sizeof(uint32_t) + Pocketsize;
    unsigned char* full_data = (unsigned char*)malloc(total_size);
    if (full_data == NULL) {
        fclose(CPLFile);
        free(JsonGzip);
        free(PocketGzip);
        ReleaseLock();
        return MemoryAllocError;
    }
    unsigned char* ptr = full_data;
    memcpy(ptr, &Jsonsize, sizeof(uint32_t)); ptr += sizeof(uint32_t);
    memcpy(ptr, JsonGzip, Jsonsize); ptr += Jsonsize;
    memcpy(ptr, &Pocketsize, sizeof(uint32_t)); ptr += sizeof(uint32_t);
    memcpy(ptr, PocketGzip, Pocketsize);

    if (!VerifyHash(expected_hash, full_data, total_size)) {
        free(full_data);
        fclose(CPLFile);
        free(JsonGzip);
        free(PocketGzip);
        ReleaseLock();
        return HashMismatchError;
    }
    free(full_data);

    // ------------------ 解压 JSON（保留原始字符串）------------------
    size_t json_decomp_len;
    unsigned char* json_decomp = DecompressGzipToMemory(JsonGzip, Jsonsize, &json_decomp_len);
    if (!json_decomp) {
        fclose(CPLFile);
        free(JsonGzip);
        free(PocketGzip);
        ReleaseLock();
        return DecompressJsonError;
    }
    // 解析配置（此时 json_decomp 仍有效）
    Config* config = ParseConfigFromJson((const char*)json_decomp);
    if (!config) {
        fclose(CPLFile);
        free(JsonGzip);
        free(PocketGzip);
        free(json_decomp);
        ReleaseLock();
        return ParseConfigError;
    }

    // 确保 TEMP_PATH 存在
    if (!is_dir(TEMP_PATH)) {
        if (mkdir(TEMP_PATH, 0755) != 0 && errno != EEXIST) {
            FreeConfig(config);
            fclose(CPLFile);
            free(JsonGzip);
            free(PocketGzip);
            free(json_decomp);
            ReleaseLock();
            return CreateTempDirError;
        }
    }

    // 解压 pocket
    char pocket_temp_path[PATH_MAX];
    snprintf(pocket_temp_path, sizeof(pocket_temp_path), "%s/pocket", TEMP_PATH);
    if (DecompressPocketToDir(PocketGzip, Pocketsize, pocket_temp_path) != 0) {
        FreeConfig(config);
        fclose(CPLFile);
        free(JsonGzip);
        free(PocketGzip);
        free(json_decomp);
        ReleaseLock();
        return DecompressPocketError;
    }

    // 释放压缩数据（已解压完）
    free(JsonGzip);
    free(PocketGzip);
    fclose(CPLFile);

    // ------------------ 安装文件 ------------------
    printf("Installing files to system directories...\n");

    const char *lib_dsts[] = { "/usr/lib/x86_64-linux-gnu", NULL };
    const char *include_dsts[] = { "/usr/include/x86_64-linux-gnu", "/usr/include", NULL };

    InstallList installed;
    install_list_init(&installed);

    char libs_temp[PATH_MAX], include_temp[PATH_MAX];
    snprintf(libs_temp, sizeof(libs_temp), "%s/pocket/libs", TEMP_PATH);
    snprintf(include_temp, sizeof(include_temp), "%s/pocket/include", TEMP_PATH);

    int ret = 0;
    if (is_dir(libs_temp)) {
        printf("  Installing libraries to %s...\n", lib_dsts[0]);
        if (install_dir_to_multi(libs_temp, lib_dsts, 1, &installed) != 0) {
            ret = InstallLibsError;
            goto cleanup;
        }
    }
    if (is_dir(include_temp)) {
        printf("  Installing headers to %s and %s...\n", include_dsts[0], include_dsts[1]);
        if (install_dir_to_multi(include_temp, include_dsts, 2, &installed) != 0) {
            ret = InstallIncludeError;
            goto cleanup;
        }
    }

    // ------------------ 写入记录文件（按示例格式）------------------
    printf("Recording installation manifest...\n");
    char record_path[PATH_MAX];
    snprintf(record_path, sizeof(record_path), "%s/%s.json", WORK_DIR, config->PocketName);

    // 原始 JSON 字符串不再需要，提前释放
    free(json_decomp);
    json_decomp = NULL;

    FILE* rec = fopen(record_path, "w");
    if (!rec) {
        fprintf(stderr, "Failed to create manifest file %s\n", record_path);
        ret = CreateManifestError;
        goto cleanup;
    }

    // 写入 JSON 对象（按指定顺序，字段名与 Config 结构体匹配）
    fprintf(rec, "{\n");
    fprintf(rec, "  \"PocketName\": ");
    fprint_json_string(rec, config->PocketName);
    fprintf(rec, ",\n");

    fprintf(rec, "  \"version\": ");
    fprint_json_string(rec, config->version);
    fprintf(rec, ",\n");

    fprintf(rec, "  \"authors\": [\n");
    if (config->authors && config->author_count > 0) {
        for (int i = 0; i < config->author_count; i++) {
            fprintf(rec, "    ");
            fprint_json_string(rec, config->authors[i]);
            if (i < config->author_count - 1) fprintf(rec, ",");
            fprintf(rec, "\n");
        }
    }
    fprintf(rec, "  ],\n");

    fprintf(rec, "  \"license\": ");
    fprint_json_string(rec, config->license);
    fprintf(rec, ",\n");

    fprintf(rec, "  \"description\": ");
    fprint_json_string(rec, config->description);
    fprintf(rec, ",\n");

    fprintf(rec, "  \"homepage\": ");
    fprint_json_string(rec, config->homepage);
    fprintf(rec, ",\n");

    fprintf(rec, "  \"repository\": ");
    fprint_json_string(rec, config->repository);
    fprintf(rec, ",\n");

    fprintf(rec, "  \"installed_files\": [\n");
    if (installed.count > 0) {
        for (int i = 0; i < installed.count; i++) {
            fprintf(rec, "    ");
            fprint_json_string(rec, installed.paths[i]);
            if (i < installed.count - 1) fprintf(rec, ",");
            fprintf(rec, "\n");
        }
    }
    fprintf(rec, "  ]\n");
    fprintf(rec, "}\n");

    fclose(rec);
    printf("  Manifest saved to %s\n", record_path);

    // 清理临时目录
    printf("Cleaning up temporary files...\n");
    remove_directory(TEMP_PATH);
    printf("Cleanup done.\n");

    install_list_free(&installed);
    FreeConfig(config);
    printf("Package Install successfully\n");
    ReleaseLock();
    return Successful;

cleanup:
    fprintf(stderr, "Installation failed at step 8/9/10\n");
    if (json_decomp) free(json_decomp);
    install_list_free(&installed);
    FreeConfig(config);
    remove_directory(TEMP_PATH);
    ReleaseLock();
    return ret;
}
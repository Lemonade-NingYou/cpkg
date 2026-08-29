#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <limits.h>
#include <sys/stat.h>
#include <glob.h>
#include "openapi.h"
#include "outerror.h"
#include "utils.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

int build(char *BuildPath) {
    if (chdir(BuildPath) != 0) return ChangeDir;

    printf("reading config.txt... ");
    char *ConfigPath = "./config.txt";
    Config *config = ReadConfig(ConfigPath);
    if (config == NULL) return ReadConfigFile;
    printf("done.\n");

    printf("checking .cpkg directory... ");
    if (!is_dir(".cpkg")) {
        if (mkdir(".cpkg", 0755) != 0) { FreeConfig(config); return CreateCpkgDir; }
        printf("created.\n");
    } else printf("exists.\n");

    printf("creating config.json... ");
    FILE *ConfigFile = fopen(".cpkg/config.json", "w");
    if (ConfigFile == NULL) { FreeConfig(config); return CreateConfigJsonFile; }
    char *ConfFileInfo = ChangeStructToJson(config);
    if (ConfFileInfo == NULL) { fclose(ConfigFile); FreeConfig(config); return ParseConfigFormat; }
    fprintf(ConfigFile, "%s", ConfFileInfo);
    fflush(ConfigFile);
    free(ConfFileInfo);
    fclose(ConfigFile);
    printf("done.\n");

    // 复制库文件
    printf("copying library files to .cpkg/libs... ");
    if (!is_dir(".cpkg/libs")) {
        if (mkdir(".cpkg/libs", 0755) != 0) { FreeConfig(config); return CreateLibsDir; }
    }
    for (int i = 0; i < config->lib_count; i++) {
        char *pattern = config->lib_patterns[i];
        if (!pattern || strlen(pattern) == 0) continue;
        glob_t glob_result;
        memset(&glob_result, 0, sizeof(glob_result));
        int ret = glob(pattern, GLOB_NOCHECK | GLOB_TILDE, NULL, &glob_result);
        if (ret != 0) {
            fprintf(stderr, "Failed to expand pattern: %s\n", pattern);
            globfree(&glob_result);
            FreeConfig(config);
            return LibNotExist;
    }
        for (size_t j = 0; j < glob_result.gl_pathc; j++) {
            char *src = glob_result.gl_pathv[j];
            if (copy_path_incremental(src, ".cpkg/libs") != 0) {
                fprintf(stderr, "Failed to copy %s to .cpkg/libs\n", src);
                globfree(&glob_result);
                FreeConfig(config);
                return LibNotExist;
            }
        }
        globfree(&glob_result);
    }
    printf("done.\n");

    // 复制头文件
    printf("copying include files to .cpkg/include... ");
    if (!is_dir(".cpkg/include")) {
        if (mkdir(".cpkg/include", 0755) != 0) { FreeConfig(config); return CreateIncludeDir; }
    }
    for (int i = 0; i < config->include_count; i++) {
        char *pattern = config->include_patterns[i];
        if (!pattern || strlen(pattern) == 0) continue;
        glob_t glob_result;
        memset(&glob_result, 0, sizeof(glob_result));
        int ret = glob(pattern, GLOB_NOCHECK | GLOB_TILDE, NULL, &glob_result);
        if (ret != 0) {
            fprintf(stderr, "Failed to expand pattern: %s\n", pattern);
            globfree(&glob_result);
            FreeConfig(config);
            return IncludeNotExist;
    }
        for (size_t j = 0; j < glob_result.gl_pathc; j++) {
            char *src = glob_result.gl_pathv[j];
            if (copy_path_incremental(src, ".cpkg/include") != 0) {
                fprintf(stderr, "Failed to copy %s to .cpkg/include\n", src);
                globfree(&glob_result);
                FreeConfig(config);
                return IncludeNotExist;
            }
        }
        globfree(&glob_result);
    }
    printf("done.\n");

    // 压缩 config.json
    printf("compressing config.json... ");
    size_t jsonSize = 0;
    unsigned char *gzipConfig = GzipToMemory(".cpkg/config.json", &jsonSize);
    if (!gzipConfig) { FreeConfig(config); return GzipConfigFile; }
    printf("done.\n");

    // 压缩 libs 和 include
    printf("compressing libs and include directories... ");
    size_t pocketSize = 0;
    unsigned char *gzipPocket = GzipToMemoryDir(".cpkg/libs", ".cpkg/include", &pocketSize);
    if (!gzipPocket) { free(gzipConfig); FreeConfig(config); return GzipPocketFile; }
    printf("done.\n");

    // 打包
    size_t dataSize = sizeof(unsigned int) + jsonSize + sizeof(unsigned int) + pocketSize;
    unsigned char *dataBuf = (unsigned char*)malloc(dataSize);
    if (!dataBuf) { free(gzipConfig); free(gzipPocket); FreeConfig(config); return MemoryAllocError; }
    unsigned char *ptr = dataBuf;
    memcpy(ptr, &jsonSize, sizeof(unsigned int));
    ptr += sizeof(unsigned int);
    memcpy(ptr, gzipConfig, jsonSize);
    ptr += jsonSize;
    memcpy(ptr, &pocketSize, sizeof(unsigned int));
    ptr += sizeof(unsigned int);
    memcpy(ptr, gzipPocket, pocketSize);

    // 计算哈希
    unsigned char hash[32];
    unsigned int hashLen = 0;
    printf("calculating SHA-256 hash... ");
    if (ComputeSha256(dataBuf, dataSize, hash, &hashLen) != 0) {
        free(dataBuf); free(gzipConfig); free(gzipPocket); FreeConfig(config);
        return HashComputeError;
    }
    printf("done.\nSHA-256: ");
    for (unsigned int i = 0; i < hashLen; i++) printf("%02x", hash[i]);
    printf("\n");

    // 写入 .cpl 文件
    printf("creating final package file... ");
    char OutFileName[256];
    snprintf(OutFileName, sizeof(OutFileName), "%s-%s.cpl", config->PocketName, config->version);
    FILE *OutFile = fopen(OutFileName, "wb");
    if (OutFile == NULL) {
        free(dataBuf); free(gzipConfig); free(gzipPocket); FreeConfig(config);
        return CreateEndFile;
    }
    fwrite(MAGIC, sizeof(char), MAGIC_LEN, OutFile);
    fwrite(hash, 1, hashLen, OutFile);
    fwrite(dataBuf, 1, dataSize, OutFile);
    fclose(OutFile);
    free(dataBuf);
    free(gzipConfig);
    free(gzipPocket);
    FreeConfig(config);
    printf("done.\n");
    fprintf(stdout, "Package built successfully: %s\n", OutFileName);
    return Successful;
}
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <limits.h>
#include <sys/stat.h>      // for mkdir
#include "openapi.h"
#include "outerror.h"
#include "utils.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

int build(char *BuildPath)
{
    if (chdir(BuildPath) != 0) {
        return ChangeDir;
    }

    // 1. 读取 config.txt
    printf("reading config.txt...");
    char *ConfigPath = "./config.txt";
    Config *config = ReadConfig(ConfigPath);
    if (config == NULL) {
        return ReadConfigFile;
    }
    printf("done.\n");

    // 2. 创建 .cpkg 目录（若不存在）
    printf("finding .cpkg directory...");
    if (!is_dir(".cpkg")) {
        printf("Error\ncreating .cpkg directory...");
        if (mkdir(".cpkg", 0755) != 0) {
            FreeConfig(config);
            return CreateCpkgDir;
        }
    }
    printf("done.\n");

    // 3. 保存 config.json
    printf("creating config.json...");
    FILE *ConfigFile = fopen(".cpkg/config.json", "w");
    if (ConfigFile == NULL) {
        FreeConfig(config);
        return CreateConfigJsonFile;
    }
    char *ConfFileInfo = ChangeStructToJson(config);
    if (ConfFileInfo == NULL) {
        fclose(ConfigFile);
        FreeConfig(config);
        return ParseConfigFormat;
    }
    fprintf(ConfigFile, "%s", ConfFileInfo);
    fflush(ConfigFile);
    free(ConfFileInfo);
    fclose(ConfigFile);
    printf("done.\n");

    // 4. 复制库文件到 .cpkg/libs
    printf("copying libraries to .cpkg/libs...");
    if (!is_dir(".cpkg/libs")) {
        if (mkdir(".cpkg/libs", 0755) != 0) {
            FreeConfig(config);
            return CreateLibsDir;
        }
        fprintf(stderr, "Creating .cpkg/libs directory\n");   // 保留警告
    }
    for (int i = 0; i < config->libs; i++) {
        char *libName = config->libNames[i];
        char libPath[PATH_MAX];
        snprintf(libPath, sizeof(libPath), "%s", libName);
        if (is_dir(libPath)) {
            char cmd[PATH_MAX + 20];
            snprintf(cmd, sizeof(cmd), "cp -r %s .cpkg/libs/", libPath);
            if (system(cmd) != 0) {
                FreeConfig(config);
                return LibNotExist;
            }
        } else {
            FreeConfig(config);
            return LibNotExist;
        }
    }
    printf("done.\n");

    // 5. 复制头文件到 .cpkg/include
    printf("copying include files to .cpkg/include...");
    if (!is_dir(".cpkg/include")) {
        if (mkdir(".cpkg/include", 0755) != 0) {
            FreeConfig(config);
            return CreateIncludeDir;
        }
        fprintf(stderr, "Creating .cpkg/include directory\n"); // 保留警告
    }
    for (int i = 0; i < config->include; i++) {
        char *includeName = config->includeNames[i];
        char includePath[PATH_MAX];
        snprintf(includePath, sizeof(includePath), "%s", includeName);
        if (is_dir(includePath)) {
            char cmd[PATH_MAX + 20];
            snprintf(cmd, sizeof(cmd), "cp -r %s .cpkg/include/", includePath);
            if (system(cmd) != 0) {
                FreeConfig(config);
                return IncludeNotExist;
            }
        } else {
            FreeConfig(config);
            return IncludeNotExist;
        }
    }
    printf("done.\n");

    // 6. 压缩 config.json
    printf("compressing config.json...");
    size_t jsonSize = 0;
    unsigned char *gzipConfig = GzipToMemory(".cpkg/config.json", &jsonSize);
    if (!gzipConfig) {
        FreeConfig(config);
        return GzipConfigFile;
    }
    printf("done.\n");

    // 7. 压缩 libs 和 include 目录
    printf("compressing libs and include directories...");
    size_t pocketSize = 0;
    unsigned char *gzipPocket = GzipToMemoryDir(".cpkg/libs", ".cpkg/include", &pocketSize);
    if (!gzipPocket) {
        free(gzipConfig);
        FreeConfig(config);
        return GzipPocketFile;
    }
    printf("done.\n");

    // 8. 合并生成最终 .cpl 文件
    printf("creating final package file...");
    char OutFileName[256];
    snprintf(OutFileName, sizeof(OutFileName), "%s-%s.cpl", config->PocketName, config->version);
    FILE *OutFile = fopen(OutFileName, "wb");
    if (OutFile == NULL) {
        free(gzipConfig);
        free(gzipPocket);
        FreeConfig(config);
        return CreateEndFile;
    }

    const char *CPLHeader = "CPL";// c pocket library
    fwrite(CPLHeader, sizeof(char), 3, OutFile); // 写入文件头
    fwrite(&jsonSize, sizeof(unsigned int), 1, OutFile); // 写入 config.json 压缩数据大小
    fwrite(gzipConfig, sizeof(char), jsonSize, OutFile);// 写入 config.json 压缩数据
    fwrite(&pocketSize, sizeof(unsigned int), 1, OutFile);// 写入 libs 和 include 压缩数据大小
    fwrite(gzipPocket, sizeof(char), pocketSize, OutFile);// 写入 libs 和 include 压缩数据

    fclose(OutFile);

    // 释放资源
    free(gzipConfig);
    free(gzipPocket);
    FreeConfig(config);
    printf("done.\n");

    fprintf(stdout, "Package built successfully: %s\n", OutFileName);
    return Successful;
}
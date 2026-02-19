#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/sha.h>
#include "../include/help.h"
#include "../include/cpkg.h"

int install_package(const char *pkg_path)
{
    char abs_pkg_path[MAX_PATH_LEN];
    if (realpath(pkg_path, abs_pkg_path) == NULL) 
    {
        cpk_printf(ERROR, "Failed to get absolute path of package: %s\n", pkg_path);
        return 1;
    }
    cpk_printf(INFO, "Installing package: %s\n", abs_pkg_path);

    FILE *installed_package = fopen(abs_pkg_path, "rb");
    if (installed_package == NULL)
    {
        cpk_printf(ERROR, "Failed to open package file: %s\n", abs_pkg_path);
        return 1;
    }

    // 读取 CPK_Header
    CPK_Header header;
    if (fread(&header, sizeof(CPK_Header), 1, installed_package) != 1)
    {
        cpk_printf(ERROR, "Failed to read header: %s\n", abs_pkg_path);
        fclose(installed_package);
        return 1;
    }

    // 校验 CPK_Header
    if (memcmp(header.magic, CPKG_MAGIC, CPKG_MAGIC_LEN) != 0)
    {
        cpk_printf(ERROR, "Invalid package file (bad magic): %s\n", abs_pkg_path);
        fclose(installed_package);
        return 1;
    }

    // 打印头部信息
    cpk_printf(INFO, "CPK_Header size: %ld bytes\n", sizeof(CPK_Header));
    cpk_printf(INFO, "Package name: %s\n", header.name);
    cpk_printf(INFO, "Package version: %s\n", header.version);
    cpk_printf(INFO, "Package description: %s\n", header.description);
    cpk_printf(INFO, "Package author: %s\n", header.author);

    // 获取文件总大小
    struct stat st;
    if (fstat(fileno(installed_package), &st) != 0)
    {
        cpk_printf(ERROR, "Failed to get file size: %s\n", abs_pkg_path);
        fclose(installed_package);
        return 1;
    }
    cpk_printf(INFO, "Package size: %ld bytes\n", st.st_size);

    // 流式计算哈希值（避免一次性加载整个包到内存）
    size_t content_len = st.st_size - sizeof(CPK_Header);
    unsigned char hash_bytes[32];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);

    // 分块读取计算哈希
    char buffer[FILE_BUFFER_SIZE];
    size_t bytes_to_read = content_len;
    while (bytes_to_read > 0) {
        size_t read_size = (bytes_to_read > FILE_BUFFER_SIZE) ? FILE_BUFFER_SIZE : bytes_to_read;
        if (fread(buffer, 1, read_size, installed_package) != read_size) {
            cpk_printf(ERROR, "Failed to read package content: %s\n", abs_pkg_path);
            fclose(installed_package);
            return 1;
        }
        SHA256_Update(&ctx, (unsigned char*)buffer, read_size);
        bytes_to_read -= read_size;
    }
    SHA256_Final(hash_bytes, &ctx);

    // 转换为十六进制字符串
    char hash[SHA256_HEX_LEN + 1];
    for (int i = 0; i < 32; i++) {
        sprintf(hash + (i * 2), "%02x", hash_bytes[i]);
    }
    hash[SHA256_HEX_LEN] = '\0';

    // 比较哈希值
    if (strcmp(hash, header.hash) != 0)
    {
        cpk_printf(ERROR, "Hash mismatch: expected %s, got %s\n", header.hash, hash);
        fclose(installed_package);
        return 1;
    }
    cpk_printf(SUCCESS, "Hash verification passed\n");

    // 解压包
    char extract_path[MAX_PATH_LEN];
    snprintf(extract_path, MAX_PATH_LEN, "%s/%s", WORK_DIR_NAME, INSTALL_DIR);
    cpk_printf(INFO, "Extracting package to: %s\n", extract_path);
    if (mkdir_p(extract_path, 0755) != 0 && errno != EEXIST)
    {
        cpk_printf(ERROR, "Failed to create directory: %s\n", extract_path);
        fclose(installed_package);
        return 1;
    }

    // 文件指针已在末尾，重新定位到包数据开始处
    if (fseek(installed_package, sizeof(CPK_Header), SEEK_SET) != 0)
    {
        cpk_printf(ERROR, "Failed to seek to package data\n");
        fclose(installed_package);
        return 1;
    }

    // 解压
    if (extract_archive(installed_package, extract_path) != 0)
    {
        cpk_printf(ERROR, "Failed to extract package\n");
        fclose(installed_package);
        return 1;
    }

    fclose(installed_package);
    cpk_printf(SUCCESS, "Package installed successfully\n");

    // 列出解压后的文件（简单遍历）
    cpk_printf(INFO, "Package contents:\n");
    DIR *dir = opendir(extract_path);
    if (dir)
    {
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL)
        {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                continue;
            printf("  ├─ %s\n", entry->d_name);
        }
        closedir(dir);
    }
    else
    {
        cpk_printf(WARNING, "Cannot list contents of %s\n", extract_path);
    }

    return 0;
}
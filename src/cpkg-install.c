#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
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
    printf("Installing package: %s\n", abs_pkg_path);

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
    if (memcmp(header.magic, "CPKG", 4) != 0)
    {
        cpk_printf(ERROR, "Invalid package file (bad magic): %s\n", abs_pkg_path);
        fclose(installed_package);
        return 1;
    }
    
    // 获取文件总大小
    struct stat st;
    if (fstat(fileno(installed_package), &st) != 0)
    {
        cpk_printf(ERROR, "Failed to get file size: %s\n", abs_pkg_path);
        fclose(installed_package);
        return 1;
    }
    printf("Package size: %ld bytes\n", st.st_size);

    // 读取剩余内容（tar.gz 数据）
    size_t content_len = st.st_size - sizeof(CPK_Header);
    char *content = malloc(content_len);
    if (!content)
    {
        cpk_printf(ERROR, "Memory allocation failed\n");
        fclose(installed_package);
        return 1;
    }

    if (fread(content, content_len, 1, installed_package) != 1)
    {
        cpk_printf(ERROR, "Failed to read package content: %s\n", abs_pkg_path);
        free(content);
        fclose(installed_package);
        return 1;
    }

    // 校验哈希值
    char *hash = sha256_mem((unsigned char*)content, content_len);
    if (!hash)
    {
        cpk_printf(ERROR, "Failed to compute hash\n");
        free(content);
        fclose(installed_package);
        return 1;
    }

    if (strcmp(hash, header.hash) != 0)
    {
        cpk_printf(ERROR, "Hash mismatch: expected %s, got %s\n", header.hash, hash);
        free(hash);
        free(content);
        fclose(installed_package);
        return 1;
    }
    free(hash);
    // 此时 content 已完成使命，可释放（也可保留用于后续解压，但这里我们用文件流直接解压）
    free(content);

    if(tf_choose("Do you want to install this package?"))
    {
        fclose(installed_package);
        return 1;
    }

    // 解压包
    char extract_path[MAX_PATH_LEN];
    snprintf(extract_path, MAX_PATH_LEN, "%s/%s", WORK_DIR_NAME, INSTALL_DIR);
    printf("Extracting package to: %s\n", extract_path);
    if (mkdir_p(extract_path, 0755) != 0 && errno != EEXIST)
    {
        cpk_printf(ERROR, "Failed to create directory: %s\n", extract_path);
        fclose(installed_package);
        return 1;
    }

    // 将文件指针重新定位到头部之后（因为前面已读取 content，但未改变文件指针位置？注意 fread 已经移动了指针）
    // 实际上 fread 读取 content 后，文件指针已位于末尾。我们需要重新打开或重新定位到头部之后。
    fseek(installed_package, 0, SEEK_SET);
    // 跳过头部
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
    printf("Package installed successfully.\n");

    // 列出解压后的文件
    int includefiles = 0, libfiles = 0;
    char include_path[5*MAX_PATH_LEN], lib_path[5*MAX_PATH_LEN];
    char **includefile_list = NULL, **libfile_list = NULL;

    // 列出 include 文件
    snprintf(include_path, 5*MAX_PATH_LEN, "%s/%s/include", extract_path, header.name);
    includefile_list = collect_files(include_path, &includefiles);
    if (includefile_list == NULL)
    {
        cpk_printf(ERROR, "Failed to list include files\n");
        return 1;
    }
    // 列出 lib 文件
    snprintf(lib_path, 5*MAX_PATH_LEN, "%s/%s/lib", extract_path, header.name);
    libfile_list = collect_files(lib_path, &libfiles);
    if (libfile_list == NULL)
    {
        cpk_printf(ERROR, "Failed to list lib files\n");
        return 1;
    }

    // 打印文件列表
    printf("Include files:\n");
    for (int i = 0; i < includefiles; i++)
    {
        printf("%s\n", includefile_list[i]);
    }
    printf("Lib files:\n");
    for (int i = 0; i < libfiles; i++)
    {
        printf("%s\n", libfile_list[i]);
    }

    // 复制文件
    for (int i = 0; i < includefiles; i++)
    {
        if(cp_file(includefile_list[i], header.include_install_path) != 0)
        {
            cpk_printf(ERROR, "Failed to copy include file: %s\n", includefile_list[i]);
            return 1;
        }
    }

    for(int i = 0; i < libfiles; i++)
    {
        if(cp_file(libfile_list[i], header.lib_install_path) != 0)
        {
            cpk_printf(ERROR, "Failed to copy lib file: %s\n", libfile_list[i]);
            return 1;
        }
    }

    // 记录安装信息
    char install_info_path[MAX_PATH_LEN];
    snprintf(install_info_path, MAX_PATH_LEN, "%s/%s", WORK_DIR_NAME, "installed.txt");
    FILE *install_info = fopen(install_info_path, "a");
    if (install_info == NULL)
    {
        cpk_printf(ERROR, "Failed to open install info file: %s\n", install_info_path);
        return 1;
    }

    // 写入安装信息
    if(write_install_file(install_info, &header, includefiles,includefile_list, libfiles, libfile_list))
    {
        cpk_printf(ERROR, "Failed to write install info\n");
        fclose(install_info);
        return 1;
    }

        // 释放文件列表
    for (int i = 0; i < includefiles; i++)
    {
        free(includefile_list[i]);
    }
    free(includefile_list);
    for (int i = 0; i < libfiles; i++)
    {
        free(libfile_list[i]);
    }
    free(libfile_list);

    // 关闭安装信息文件
    fclose(install_info);
    return 0;
}
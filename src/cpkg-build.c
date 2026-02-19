#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "../include/cpkg.h"
#include "../include/help.h"

int make_build_package(const char *package_path_dir)
{
    // 复制路径并去掉末尾的 '/'
    char *package_path = strdup(package_path_dir);
    if (!package_path) {
        cpk_printf(ERROR, "Memory allocation failed.\n");
        return 1;
    }
    size_t len = strlen(package_path);
    if (len > 0 && package_path[len - 1] == '/')
        package_path[len - 1] = '\0';

    printf("the path is \"%s\"\n", package_path);
    printf("Is finding control file...\n");

    // 拼接 control 文件路径
    char *ctrl_file_path = NULL;
    if (asprintf(&ctrl_file_path, "%s/%s/control", package_path, META_DIR_NAME) == -1) {
        cpk_printf(ERROR, "Memory allocation failed.\n");
        free(package_path);
        return 1;
    }
    FILE *ctrl_file = fopen(ctrl_file_path, "r");
    if (!ctrl_file) {
        printf("control file not found.\n");
        free(ctrl_file_path);
        free(package_path);
        return 1;
    }

    Control_Info *ctrl_info = read_control_info(ctrl_file);
    if (!ctrl_info) {
        cpk_printf(ERROR, "Error: read control file failed.\n");
        fclose(ctrl_file);
        free(ctrl_file_path);
        free(package_path);
        return 1;
    }
    fclose(ctrl_file);

    printf("OK, I find the control file.\n");
    printf("and look at the info, it is true?\n\n");

    char cwd[1024];
    if (!getcwd(cwd, sizeof(cwd))) {
        cpk_printf(ERROR, "Error: get current working directory failed.\n");
        free(ctrl_file_path);
        free(package_path);
        free(ctrl_info);   // 需要实现此函数，或手动释放
        return 1;
    }
    printf_control_info(ctrl_info);

    if (tf_choose("If you want to build the package, please enter 'y', or enter 'n' to stop build the package.")) {
        printf("OK, I will stop build the package.\n");
        free(ctrl_file_path);
        free(package_path);
        free(ctrl_info);
        return 0;
    }

    printf("Is Building the package...\n");

    // 动态构建 build_path
    char *build_path = NULL;
    if (asprintf(&build_path, "%s/%s/%s", cwd, package_path, ctrl_info->name) == -1) {
        cpk_printf(ERROR, "Memory allocation failed.\n");
        free(ctrl_file_path);
        free(package_path);
        free(ctrl_info);
        return 1;
    }
    printf("build path is \"%s\"\n", build_path);

    if (mkdir_p(build_path, 0755)) {
        cpk_printf(ERROR, "Error: create build path failed.\n");
        free(build_path);
        free(ctrl_file_path);
        free(package_path);
        free(ctrl_info);
        return 1;
    }

    // 拷贝头文件
    printf("Is copying include files...\n");
    for (int i = 0; i < ctrl_info->include_file_count; i++) {
        char *dst_dir = NULL;
        if (asprintf(&dst_dir, "%s/include/", build_path) == -1) {
            cpk_printf(ERROR, "Memory allocation failed.\n");
            goto error;
        }
        if (mkdir_p(dst_dir, 0755)) {
            cpk_printf(ERROR, "Error: create include path failed.\n");
            free(dst_dir);
            goto error;
        }
        if (cp_file(ctrl_info->include_files[i], dst_dir)) {
            cpk_printf(ERROR, "Error: copy include file failed.\n");
            free(dst_dir);
            goto error;
        }
        free(dst_dir);
    }

    // 拷贝库文件
    printf("Is copying lib files...\n");
    for (int i = 0; i < ctrl_info->lib_file_count; i++) {
        char *dst_dir = NULL;
        if (asprintf(&dst_dir, "%s/lib/", build_path) == -1) {
            cpk_printf(ERROR, "Memory allocation failed.\n");
            goto error;
        }
        if (mkdir_p(dst_dir, 0755)) {
            cpk_printf(ERROR, "Error: create lib path failed.\n");
            free(dst_dir);
            goto error;
        }
        if (cp_file(ctrl_info->lib_files[i], dst_dir)) {
            cpk_printf(ERROR, "Error: copy lib file failed.\n");
            free(dst_dir);
            goto error;
        }
        free(dst_dir);
    }

    // 压缩
    printf("Is compressing the package...\n");
    size_t tgz_malloc_size = 0;
    char *tgz_malloc_file = archive_create_tgz(build_path, &tgz_malloc_size);
    if (!tgz_malloc_file) {
        cpk_printf(ERROR, "Error: create tgz file failed.\n");
        goto error;
    }
    printf("OK, I compress the package.\n");

    // 创建头部
    printf("Is making header file...\n");
    CPK_Header *header = make_Header(ctrl_info);
    if (!header) {
        cpk_printf(ERROR, "Error: make header failed.\n");
        free(tgz_malloc_file);
        goto error;
    }
    printf("OK, I make the header file.\n");

    // 计算哈希
    printf("Is calculating hash value...\n");
    char *hash = sha256_mem((const unsigned char *)tgz_malloc_file, tgz_malloc_size); // 强制转换
    if (!hash) {
        cpk_printf(ERROR, "Error: calculate hash failed.\n");
        free(header);
        free(tgz_malloc_file);
        goto error;
    }
    // 验证哈希值长度并安全复制
    if (strlen(hash) != 64) {
        cpk_printf(ERROR, "Error: invalid hash length (expected 64, got %zu).\n", strlen(hash));
        free(hash);
        free(header);
        free(tgz_malloc_file);
        goto error;
    }
    strncpy(header->hash, hash, sizeof(header->hash) - 1);
    header->hash[sizeof(header->hash) - 1] = '\0';

    // 写入 .cpk 文件
    printf("Is writing header file...\n");
    char *header_file_path = NULL;
    if (asprintf(&header_file_path, "%s/%s/%s-%s.cpk", cwd, package_path,
                 ctrl_info->name, ctrl_info->version) == -1) {
        cpk_printf(ERROR, "Memory allocation failed.\n");
        free(hash);
        free(header);
        free(tgz_malloc_file);
        goto error;
    }
    FILE *header_file = fopen(header_file_path, "wb");
    if (!header_file) {
        cpk_printf(ERROR, "Error: create header file failed.\n");
        free(header_file_path);
        free(hash);
        free(header);
        free(tgz_malloc_file);
        goto error;
    }
    if (fwrite(header, sizeof(CPK_Header), 1, header_file) != 1) {
        cpk_printf(ERROR, "Error: write header file failed.\n");
        fclose(header_file);
        free(header_file_path);
        free(hash);
        free(header);
        free(tgz_malloc_file);
        goto error;
    }
    if (fwrite(tgz_malloc_file, tgz_malloc_size, 1, header_file) != 1) {
        cpk_printf(ERROR, "Error: write header file failed.\n");
        fclose(header_file);
        free(header_file_path);
        free(hash);
        free(header);
        free(tgz_malloc_file);
        goto error;
    }
    fclose(header_file);
    printf("OK, I build the package.\n");
    printf("The package is saved in \"%s\"\n", header_file_path);
    printf("The hash value is \"%s\"\n", hash);

    // 清理临时构建目录
    if (rm_rf(build_path))
        cpk_printf(ERROR, "Error: remove build path failed.\n");

    // 释放所有资源
    free(header);
    free(hash);
    free(tgz_malloc_file);
    free(header_file_path);
    free(build_path);
    free(ctrl_file_path);
    free(package_path);
    free(ctrl_info);   // 请确保实现了此函数
    printf("Build package done.\n");
    return 0;

error:
    // 发生错误时清理已分配资源
    if (build_path) {
        rm_rf(build_path);   // 尝试删除已创建的目录
        free(build_path);
    }
    free(ctrl_file_path);
    free(package_path);
    if (ctrl_info)
        free(ctrl_info);
    return 1;
}
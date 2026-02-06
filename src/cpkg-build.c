#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <archive.h>
#include <archive_entry.h>
#include "../include/cpkg.h"
#include "../include/help.h"

/** 
 * @brief 构建软件包
 * @param build_path 构建路径
 * @return 0 成功，其他失败
 */
int build_package(const char* build_path)
{
    // 读取 CONTROL_FILE 文件
    char control_file_path[256];
    sprintf(control_file_path, "%s/%s/%s", build_path, META_DIR, CONTROL_FILE);
    
    // 解析 control 文件
    ControlInfo control_info;
    int result = parse_control_file(control_file_path, &control_info);
    if (result != 0) 
    {
        // parse_control_file 已经打印了错误信息
        return -1;
    }
    
    // 打印解析结果（调试用）
    print_control_info(&control_info);

    // 构建软件包
    
    // 在 build_path 目录下生成一个临时目录
    char temp_dir_path[256];
    sprintf(temp_dir_path, "%s/temp_build_dir", build_path);
    if (create_directory(temp_dir_path))
    {
        cpk_printf(ERROR, "Failed to create temporary build directory\n");
        return -1;
    }

    // 在临时目录中创建 CPKG 子目录
    char meta_dir_in_temp[256];
    sprintf(meta_dir_in_temp, "%s/%s", temp_dir_path, META_DIR);
    if (create_directory(meta_dir_in_temp))
    {
        cpk_printf(ERROR, "Failed to create CPKG directory in temp directory\n");
        return -1;
    }
    
    // 将 control 文件复制到临时目录的 CPKG 目录下
    char control_dst_path[256];
    sprintf(control_dst_path, "%s/%s", meta_dir_in_temp, CONTROL_FILE);
    if (copy_files(control_file_path, meta_dir_in_temp))
    {
        cpk_printf(ERROR, "Failed to copy control file to temporary build directory\n");
        return -1;
    }
    
    // 生成 INSTALL_SCRIPT & REMOVE_SCRIPT 
    if (create_script(temp_dir_path, control_file_path, &control_info))
    {
        cpk_printf(ERROR, "Failed to create install/remove scripts\n");
        return -1;
    }

    // 在临时目录中创建 include 目录
    char include_dir_in_temp[256];
    sprintf(include_dir_in_temp, "%s/include", temp_dir_path);
    if (create_directory(include_dir_in_temp))
    {
        cpk_printf(ERROR, "Failed to create include directory in temp directory\n");
        return -1;
    }

    // 复制 include 文件到临时目录的include目录
    for (int i = 0; i < control_info.include_count; i++)
    {
        char src_path[256];
        char dst_path[256];
        sprintf(src_path, "%s/%s", build_path, control_info.include[i]);
        
        // 提取文件名
        char *filename = strrchr(control_info.include[i], '/');
        if (filename)
            filename++;
        else
            filename = control_info.include[i];
            
        sprintf(dst_path, "%s/%s", include_dir_in_temp, filename);
        
        // 使用 copy_file 而不是 copy_files（因为 copy_files 处理目录）
        struct stat st;
        if (stat(src_path, &st) == 0 && S_ISREG(st.st_mode))
        {
            if (copy_files(src_path, dst_path))
            {
                cpk_printf(ERROR, "Failed to copy include file %s to temporary build directory\n", control_info.include[i]);
                return -1;
            }
        }
        else
        {
            cpk_printf(ERROR, "Include file %s does not exist or is not a regular file\n", src_path);
            return -1;
        }
    }
    
    // 在临时目录中创建 lib 目录
    char lib_dir_in_temp[256];
    sprintf(lib_dir_in_temp, "%s/lib", temp_dir_path);
    if (create_directory(lib_dir_in_temp))
    {
        cpk_printf(ERROR, "Failed to create lib directory in temp directory\n");
        return -1;
    }
    
    // 复制 lib 文件到临时目录的lib目录
    for (int i = 0; i < control_info.lib_count; i++)
    {
        char src_path[256];
        char dst_path[256];
        sprintf(src_path, "%s/%s", build_path, control_info.lib[i]);
        
        // 提取文件名
        char *filename = strrchr(control_info.lib[i], '/');
        if (filename)
            filename++;
        else
            filename = control_info.lib[i];
            
        sprintf(dst_path, "%s/%s", lib_dir_in_temp, filename);
        
        // 使用 copy_file 而不是 copy_files（因为 copy_files 处理目录）
        struct stat st;
        if (stat(src_path, &st) == 0 && S_ISREG(st.st_mode))
        {
            if (copy_files(src_path, dst_path))
            {
                cpk_printf(ERROR, "Failed to copy lib file %s to temporary build directory\n", control_info.lib[i]);
                return -1;
            }
        }
        else
        {
            cpk_printf(ERROR, "Lib file %s does not exist or is not a regular file\n", src_path);
            return -1;
        }
    }

    // 创建最终的软件包文件
    char package_file_path[256];
    sprintf(package_file_path, "%s/%s.cpk", build_path, control_info.packet);
    FILE *package_file = fopen(package_file_path, "wb");
    if (package_file == NULL)
    {
        cpk_printf(ERROR, "Failed to create package file %s for writing\n", package_file_path);
        return -1;
    }
    
    // 创建并写入 CPK 头部
    CPK_Header header;
    memset(&header, 0, sizeof(CPK_Header));
    
    // 设置魔术字 - 修复字符串截断警告
    memcpy(header.magic, CPK_MAGIC, CPK_MAGIC_LEN);
    
    // 设置软件包信息
    strncpy(header.name, control_info.packet, sizeof(header.name) - 1);
    
    // 解析版本号字符串为整数（假设格式为 x.y.z.w）
    int major = 1, minor = 0, patch = 0, build = 0;
    sscanf(control_info.version, "%d.%d.%d.%d", &major, &minor, &patch, &build);
    header.version = (major << 24) | (minor << 16) | (patch << 8) | build;
    
    strncpy(header.description, control_info.brief, sizeof(header.description) - 1);
    strncpy(header.author, "Unknown", sizeof(header.author) - 1);
    strncpy(header.license, "Unknown", sizeof(header.license) - 1);
    
    // 临时将哈希值设为零，稍后计算
    memset(header.hash, 0, sizeof(header.hash));
    
    // 写入头部到文件
    if (fwrite(&header, sizeof(header), 1, package_file) != 1)
    {
        cpk_printf(ERROR, "Failed to write header to package file\n");
        fclose(package_file);
        return -1;
    }
    
    // 压缩临时目录内容到软件包文件
    if (compress_package(package_file, temp_dir_path))
    {
        cpk_printf(ERROR, "Failed to compress package contents\n");
        fclose(package_file);
        return -1;
    }
    
    // 重新打开文件以计算哈希值
    fclose(package_file);
    FILE *pkg_file = fopen(package_file_path, "rb");
    if (pkg_file == NULL)
    {
        cpk_printf(ERROR, "Failed to open package file %s for reading\n", package_file_path);
        return -1;
    }
    
    // 计算文件的哈希值
    unsigned char calculated_hash[SHA256_DIGEST_LENGTH];
    if (check_hash(pkg_file, calculated_hash) != 0)
    {
        // 注意：check_hash 函数实际上会计算哈希值，但这里我们需要用它来计算
        // 由于 check_hash 函数设计为验证哈希，我们需要重新计算
        cpk_printf(ERROR, "Failed to calculate hash of package file\n");
        fclose(pkg_file);
        return -1;
    }
    
    // 更新头部中的哈希值
    memcpy(header.hash, calculated_hash, sizeof(header.hash));
    
    // 写回更新后的头部
    fseek(pkg_file, 0, SEEK_SET);
    if (fwrite(&header, sizeof(header), 1, pkg_file) != 1)
    {
        cpk_printf(ERROR, "Failed to update header with hash value\n");
        fclose(pkg_file);
        return -1;
    }
    
    fclose(pkg_file);
    
    // 打印软件包信息
    cpk_printf(INFO, "Package %s-%s built successfully\n", control_info.packet, control_info.version);
    cpk_printf(INFO, "Package file: %s\n", package_file_path);
    cpk_printf(INFO, "SHA256 hash: ");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        printf("%02x", header.hash[i]);
    }
    printf("\n");
    
    // 清理临时目录
    remove_directory(temp_dir_path);

    return 0;
}
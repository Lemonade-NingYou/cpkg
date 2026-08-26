#include "openapi.h"
#include "utils.h"
#include "outerror.h"

int install(char *InstallPath)
{
    // 检查工作目录是否存在，如果不存在则创建
    if(is_dir(WORK_DIR)) {
        printf("welcome to use cpkg!\n");
        InitCpkg();
    }

    // 1. 获取锁文件，防止同时安装多个包
    GetLock();

    // 2. 检查文件真实性
    
    // 2. 解压安装包到指定路径
    
    // 3. 读取 config.txt 文件，获取包信息
    // 4. 记录配置信息
    FILE *Configfile = fopen("UNO", "w");
    if(Configfile == NULL) {
        return CreateConfigFile;
    }
    // 5. 将库文件和头文件复制到系统目录或指定目录
    // 6. 生成 JSON 文件，记录安装信息

    // printf("Installing package from: %s\n", InstallPath);
    // 7. 释放锁文件
    ReleaseLock();

    return Successful;
}
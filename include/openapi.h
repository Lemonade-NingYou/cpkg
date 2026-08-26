#ifndef OPENAPI_H
#define OPENAPI_H

#include <stdbool.h>
#include <stdio.h>

/**
 * @brief 将项目构建为cpl包
 * @param BuildPath 构建路径
 * @return 成功:0 失败:非0
 */
int build(char *BuildPath);

/**
 * @brief 将cpl包安装到指定路径
 * @param InstallPath 安装路径
 * @return 成功:0 失败:非0
 */
int install(char *InstallPath);

#endif //OpenAPI.h

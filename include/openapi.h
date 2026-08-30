/**
 * @file openapi.h
 * @brief CPKG 工具对外暴露的公共接口。
 * 提供构建、安装、卸载三种主要操作的函数声明。
 */

#ifndef OPENAPI_H
#define OPENAPI_H

#include <stdbool.h>
#include <stdio.h>

/**
 * @brief 将项目构建为 .cpl 包文件。
 * @param BuildPath 包含 config.txt 的项目目录路径。
 * @return 成功返回 0，失败返回非零错误码（参见 outerror.h）。
 */
int CPKG_build(char *BuildPath);

/**
 * @brief 安装 .cpl 包到系统目录（/usr/lib/... 和 /usr/include/...）。
 * @param InstallPath .cpl 包文件的路径。
 * @return 成功返回 0，失败返回非零错误码。
 */
int CPKG_install(char *InstallPath);

/**
 * @brief 卸载已安装的包（根据记录文件删除已安装文件）。
 * @param PocketName 要卸载的包名（与记录文件名对应）。
 * @return 成功返回 0，失败返回非零错误码。
 */
int CPKG_remove(char *PocketName);

/**
 * @brief 列出所有已安装的包。
 * @return 成功返回 Successful (0)，失败返回错误码（如目录打开失败）。
 */
int CPKG_list(void);
#endif // OPENAPI_H
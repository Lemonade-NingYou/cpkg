/*
 * Copyright (C) 2026 Lemonade-NingYou
 *
 * This file is part of cpkg.
 *
 * cpkg is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * cpkg is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with cpkg. If not, see <https://www.gnu.org/licenses/>.
 */
#ifndef OUTERROR_H
#define OUTERROR_H

/**
 * @brief 所有错误码枚举，按功能模块分组。
 */
typedef enum ErrorInfo {
    Successful = 0,                      ///< 操作成功

    // -------- build 阶段错误 (1~15) --------
    ReadConfigFile = 1,                  ///< 无法读取 config.txt
    ChangeDir,                           ///< 切换目录失败
    CreateCpkgDir,                       ///< 无法创建 .cpkg 目录
    CreateConfigJsonFile,                ///< 无法创建 .cpkg/config.json
    CreateLibsDir,                       ///< 无法创建 .cpkg/libs 目录
    LibNotExist,                         ///< 库文件不存在或匹配失败
    CreateIncludeDir,                    ///< 无法创建 .cpkg/include 目录
    IncludeNotExist,                     ///< 头文件不存在或匹配失败
    GzipConfigFile,                      ///< 压缩 config.json 失败
    MemoryAllocError,                    ///< 内存分配失败
    HashComputeError,                    ///< SHA‑256 计算失败
    GzipPocketFile,                      ///< 压缩 libs/include 目录失败
    ParseConfigFormat,                   ///< 解析配置文件格式错误
    CreateEndFile,                       ///< 创建最终 .cpl 文件失败

    // -------- install 阶段错误 (16~32) --------
    OpenCPLFile,                         ///< 无法打开 .cpl 包文件
    ReadHashError,                       ///< 读取包内哈希值失败
    InvalidMagicError,                   ///< 魔术字不匹配，非有效 .cpl 包
    ReadJsonSizeError,                   ///< 读取 JSON 数据块大小失败
    ReadJsonMemoryError,                 ///< 读取压缩的 JSON 数据失败
    ReadPocketSizeError,                 ///< 读取 Pocket 数据块大小失败
    ReadPocketMemoryError,               ///< 读取压缩的 Pocket 数据失败
    HashMismatchError,                   ///< 哈希校验不通过（包损坏或被篡改）
    DecompressJsonError,                 ///< 解压 config.json 失败
    WriteTempConfigError,                ///< 写入临时配置文件失败
    ParseConfigError,                    ///< 解析 config.json 内容失败（JSON 无效）
    DecompressPocketError,               ///< 解压 Pocket 数据到临时目录失败
    InstallLibsError,                    ///< 安装库文件失败
    InstallIncludeError,                 ///< 安装头文件失败
    CreateManifestError,                 ///< 创建安装记录文件失败
    CreateTempDirError,                  ///< 创建临时目录失败
    ReadRecordInformationError,          ///< 读取安装记录文件失败

    // remove
    RemoveFilesError,                    ///< 删除文件失败（卸载时）
} ErrorInfo;

/**
 * @brief 根据错误码输出对应的错误信息到 stderr。
 * @param errorCode 错误码（ErrorInfo 枚举值）。
 */
void ErrorArg(int errorCode);

#endif // OUTERROR_H
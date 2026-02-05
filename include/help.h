/*
 * Copyright (C) 2025 lemonade_NingYou
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef HELP_H
#define HELP_H

// 帮助信息字符串声明
extern const char *help_message; // 帮助信息字符串

// 彩色输出定义
#define CPKG_NAME "\033[1;37mcpkg:\033[0m"    // 软件包管理器名称
#define ERROR "\033[1;31mERROR:\033[0m"        // 错误标识
#define WARNING "\033[1;33mWARNING:\033[0m"      // 警告标识
#define INFO "\033[1;32mINFORMATION:\033[0m"         // 信息标识
#define VISION "class 0.0.0.1"         // 版本标识

// 架构信息定义，用于判断系统架构
#if defined(__amd64__) || defined(__x86_64__) || defined(_M_X64) || defined(_M_AMD64)
#define ARCH "amd64"
#elif defined(__i386__) || defined(__i386) || defined(_M_IX86)
#define ARCH "i386"
#elif defined(__arm__) || defined(__arm) || defined(_M_ARM)
#define ARCH "arm"
#elif defined(__aarch64__) || defined(__aarch64) || defined(_M_ARM64)
#define ARCH "aarch64"
#else
#define ARCH "unknown"
#endif


// 彩色打印宏
// 正确的 cpk_printf 宏定义
#define cpk_printf(level, format, ...) \
    do { \
        printf("%s %s " format, CPKG_NAME, level, ##__VA_ARGS__); \
    } while (0)

/**
 * @brief 夹带私货，赞美帝皇
 */
#define For_the_Emporer() printf("010001100110111101110010001000000111010001101000011001010010000001000101011011010111000001100101011100100110111101110010\n")

// 简要帮助信息宏
#define less_info_cpkg() \
    printf(\
    "\n"\
    "Type cpkg --help for help about installing and removing packages [*]; \n" \
    "Use capt for a friendly package management interface;\n" \
    "Type cpkg -Dhelp for a list of dpkg debugging flag values;\n" \
    "Type cpkg --force-help for a list of all forcing options;\n" \
    "Type cpkg-deb --help for help about manipulating *.deb files;\n" \
    "\nOptions marked [*] produce a lot of output - pipe it through 'less' or 'more' ! \n")

#define full_info_cpkg() \
    for(int idx = 0; help_message[idx] != '\0'; idx++) { \
        putchar(help_message[idx]); \
    }

#define cpkg_version() \
    printf("Cpkg Package Management ProgramVersion %s(amd64).\n"\
        "This program is free software; for copying conditions, see the GNU General Public License \n"\
        "version 3 or later. This program comes with ABSOLUTELY NO WARRANTY.\n", VISION, ARCH);

#endif // HELP_H
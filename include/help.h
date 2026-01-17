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
    "输入 dpkg --help 可获得安装和卸载软件包的有关帮助 [*]; \n" \
    "使用 apt 或是 aptitude 就能在友好的界面下管理软件包；\n" \
    "输入 dpkg -Dhelp 可看到 dpkg 除错标志的值的列表；\n" \
    "输入 dpkg --force-help 可获得所有强制操作选项的列表；\n" \
    "输入 dpkg-deb --help 可获得有关操作 *.deb 文件的帮助；\n" \
    "\n带有 [*] 的选项将会输出较大篇幅的文字 - 可使用管道将其输出连接到 less 或 more ! \n")

#define full_info_cpkg() \
    for(int idx = 0; help_message[idx] != '\0'; idx++) { \
        putchar(help_message[idx]); \
    }

#endif // HELP_H
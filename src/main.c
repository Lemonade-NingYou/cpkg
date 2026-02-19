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

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include "../include/cpkg.h"
#include "../include/param.h"
#include "../include/help.h"

/**
 * @brief cpkg 一个优秀的c包管底层
 */
int main(int argc, char *argv[])
{
    int opt; // 选项
    int option_index = 0; // 选项索引

    // 处理命令行参数
    if(argc < 2)
    {
        cpk_printf(ERROR, "No command specified.\n");
        less_info_cpkg();
        return 1;
    }

    // 解析命令行参数
    // 将选项字符串修改为 "hvi:r:m:"，表示 i, r, m 需要参数
while((opt = getopt_long(argc, argv, "hvi:r:m:", long_options, &option_index)) != -1)
{
    switch(opt)
    {
        case 'h':
            full_info_cpkg();
            return 0;

        case 'v':
            cpkg_version();
            return 0;

        case 'i':
            if(check_sudo_privileges() != 0) {
                cpk_printf(ERROR, "This operation requires sudo privileges.\n");
                return 1;
            }
            if (optarg) {
                install_package(optarg);
            } else {
                cpk_printf(ERROR, "--install requires at least one package file as an argument\n");
                less_info_cpkg();
                return 1;
            }
            break;

        case 'r':
            if(check_sudo_privileges() != 0) {
                cpk_printf(ERROR, "This operation requires sudo privileges.\n");
                return 1;
            }
            if (optarg) {
                remove_package(optarg);
            } else {
                cpk_printf(ERROR, "--remove needs at least one package name argument\n");
                less_info_cpkg();
                return 1;
            }
            break;

        case 'm':
            if (optarg) {
                make_build_package(optarg);
            } else {
                cpk_printf(ERROR, "--make-build requires at least one directory name argument\n");
                less_info_cpkg();
                return 1;
            }
            break;
            
        default:
            cpk_printf(ERROR, "Invalid option: -%c\n", opt);
            less_info_cpkg();
            return 1;
    }
}

// 处理非选项参数（备用方案）
if (optind < argc) {
    // 如果有非选项参数，可以作为命令处理
    cpk_printf(INFO, "Non-option argument: %s\n", argv[optind]);
}
    return 0;
}
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
#include "../include/help.h"

int main(int argc, char *argv[])
{
    int opt; // 选项
    int option_index = 0; // 选项索引
    int opterr = 0; // 错误信息

    // 处理命令行参数
    if(argc < 2)
    {
        cpk_printf(ERROR, "No command specified. Use -h or --help for help.\n");
        less_info_cpkg();
        return 1;
    }

    // 解析命令行参数
    while((opt = getopt_long(argc, argv, "hvir", NULL, &option_index)) != -1)
    {
        switch(opt)
        {
            case 'h': // 帮助信息
                full_info_cpkg();
                return 0;
            case 'v': // 版本信息
                cpkg_version();
                return 0;
            case 'i': // 安装包
                install_package(optarg);
                break;
            case 'r': // 卸载包
                remove_package(optarg);
                break;
            default:
                cpk_printf(ERROR, "Invalid option %c.\n", opt);
                less_info_cpkg();
                return 1;
    
        }
    }
    return 0;
}
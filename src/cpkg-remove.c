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
#include <string.h>
#include "../include/cpkg.h"
#include "../include/help.h"

/**
 * @brief 移除单个软件包
 * @param pkg_name 软件包名称
 * @return 0 表示成功，非0表示失败
 */
int remove_package(const char *pkg_name) 
{
    (void)pkg_name;  // 标记参数为已使用，消除编译警告
    return 0;
}
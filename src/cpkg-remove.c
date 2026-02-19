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
#include <dirent.h>
#include <unistd.h>
#include <errno.h>
#include "../include/cpkg.h"
#include "../include/help.h"

/**
 * @brief 移除单个软件包
 * @param pkg_name 软件包名称
 * @return 0 表示成功，非0表示失败
 */
int remove_package(const char *pkg_name)
{
    if (!pkg_name || pkg_name[0] == '\0') {
        cpk_printf(ERROR, "Invalid package name.\n");
        return 1;
    }

    char installed_path[MAX_PATH_LEN];
    snprintf(installed_path, sizeof(installed_path), "%s/installed.txt", WORK_DIR_NAME);

    // 读取所有已安装包记录
    FILE *fp = fopen(installed_path, "rb");
    if (!fp) {
        cpk_printf(ERROR, "Cannot open installed packages database: %s\n", strerror(errno));
        return 1;
    }

    // 用于存储所有记录的结构
    typedef struct {
        CPK_Header header;
        int inc_count;
        int lib_count;
        char **inc_list;
        char **lib_list;
    } PackageRecord;

    PackageRecord *records = NULL;
    int record_count = 0;

    while (1) {
        CPK_Header hdr;
        int inc_cnt, lib_cnt;
        char **inc_lst = NULL, **lib_lst = NULL;
        int ret = read_install_file(fp, &hdr, &inc_cnt, &inc_lst, &lib_cnt, &lib_lst);
        if (ret != 0) {
            if (feof(fp)) break;
            cpk_printf(ERROR, "Error reading database: %s\n", strerror(errno));
            goto cleanup;
        }

        // 扩展数组
        PackageRecord *new_rec = realloc(records, (record_count + 1) * sizeof(PackageRecord));
        if (!new_rec) {
            cpk_printf(ERROR, "Out of memory.\n");
            // 释放当前读出的列表
            for (int i = 0; i < inc_cnt; i++) free(inc_lst[i]);
            free(inc_lst);
            for (int i = 0; i < lib_cnt; i++) free(lib_lst[i]);
            free(lib_lst);
            goto cleanup;
        }
        records = new_rec;
        PackageRecord *r = &records[record_count];
        r->header = hdr;
        r->inc_count = inc_cnt;
        r->lib_count = lib_cnt;
        r->inc_list = inc_lst;
        r->lib_list = lib_lst;
        record_count++;
    }
    fclose(fp);
    fp = NULL;

    // 查找匹配的包
    int match_idx = -1;
    for (int i = 0; i < record_count; i++) {
        if (strcmp(records[i].header.name, pkg_name) == 0) {
            match_idx = i;
            break;
        }
    }

    if (match_idx == -1) {
        cpk_printf(ERROR, "Package '%s' is not installed.\n", pkg_name);
        goto cleanup;
    }

    PackageRecord *pkg = &records[match_idx];

    // 用户确认
    char msg[512];
    snprintf(msg, sizeof(msg), "Do you want to remove package '%s' and its files?", pkg_name);
    if (tf_choose(msg) == 1) {
        printf("Removal cancelled.\n");
        goto cleanup;
    }

    // 用户确认后，开始删除文件
    int remove_failed = 0;

        // 删除 include 文件
    for (int i = 0; i < pkg->inc_count; i++) {
        const char *full = pkg->inc_list[i];
        const char *rel = strstr(full, "/include/");
        if (rel) {
            rel += 9; // 跳过 "/include/"
        } else {
            rel = strrchr(full, '/');
            rel = rel ? rel + 1 : full;
        }
        char target[5 * MAX_PATH_LEN]; // 增大缓冲区，足以容纳 include_install_path + '/' + rel
        int needed = snprintf(target, sizeof(target), "%s/%s",
                              pkg->header.include_install_path, rel);
        if (needed < 0 || (size_t)needed >= sizeof(target)) {
            cpk_printf(ERROR, "Path too long: %s/%s\n",
                       pkg->header.include_install_path, rel);
            remove_failed = 1;
            continue;
        }
        if (remove(target) != 0 && errno != ENOENT) {
            cpk_printf(WARNING, "Failed to remove %s: %s\n",
                       target, strerror(errno));
            remove_failed = 1;
        } else {
            printf("Removed: %s\n", target);
        }
    }

    // 删除 lib 文件
    for (int i = 0; i < pkg->lib_count; i++) {
        const char *full = pkg->lib_list[i];
        const char *rel = strstr(full, "/lib/");
        if (rel) {
            rel += 5; // 跳过 "/lib/"
        } else {
            rel = strrchr(full, '/');
            rel = rel ? rel + 1 : full;
        }
        char target[5 * MAX_PATH_LEN];
        int needed = snprintf(target, sizeof(target), "%s/%s",
                              pkg->header.lib_install_path, rel);
        if (needed < 0 || (size_t)needed >= sizeof(target)) {
            cpk_printf(ERROR, "Path too long: %s/%s\n",
                       pkg->header.lib_install_path, rel);
            remove_failed = 1;
            continue;
        }
        if (remove(target) != 0 && errno != ENOENT) {
            cpk_printf(WARNING, "Failed to remove %s: %s\n",
                       target, strerror(errno));
            remove_failed = 1;
        } else {
            printf("Removed: %s\n", target);
        }
    }

    // 将除匹配记录外的其他记录写回数据库
    char tmp_path[MAX_PATH_LEN];
    snprintf(tmp_path, sizeof(tmp_path), "%s/installed.txt.tmp", WORK_DIR_NAME);
    FILE *tmp_fp = fopen(tmp_path, "wb");
    if (!tmp_fp) {
        cpk_printf(ERROR, "Failed to create temporary file: %s\n", strerror(errno));
        goto cleanup;
    }

    for (int i = 0; i < record_count; i++) {
        if (i == match_idx) continue;
        PackageRecord *r = &records[i];
        if (write_install_file(tmp_fp, &r->header,
                               r->inc_count, r->inc_list,
                               r->lib_count, r->lib_list) != 0) {
            cpk_printf(ERROR, "Failed to write temporary file.\n");
            fclose(tmp_fp);
            remove(tmp_path);
            goto cleanup;
        }
    }
    fclose(tmp_fp);

    if (rename(tmp_path, installed_path) != 0) {
        cpk_printf(ERROR, "Failed to update database: %s\n", strerror(errno));
        remove(tmp_path);
        goto cleanup;
    }

    if (remove_failed) {
        cpk_printf(WARNING, "Some files could not be removed. Package may be partially removed.\n");
    } else {
        printf("Package '%s' removed successfully.\n", pkg_name);
    }

    // 释放内存
    for (int i = 0; i < record_count; i++) {
        PackageRecord *r = &records[i];
        for (int j = 0; j < r->inc_count; j++) free(r->inc_list[j]);
        free(r->inc_list);
        for (int j = 0; j < r->lib_count; j++) free(r->lib_list[j]);
        free(r->lib_list);
    }
    free(records);
    return 0;

cleanup:
    if (fp) fclose(fp);
    if (records) {
        for (int i = 0; i < record_count; i++) {
            PackageRecord *r = &records[i];
            for (int j = 0; j < r->inc_count; j++) free(r->inc_list[j]);
            free(r->inc_list);
            for (int j = 0; j < r->lib_count; j++) free(r->lib_list[j]);
            free(r->lib_list);
        }
        free(records);
    }
    return 1;
}
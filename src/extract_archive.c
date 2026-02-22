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

#include <archive.h>
#include <archive_entry.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <stdio.h>
#include "../include/cpkg.h"

/**
 * 从已打开的 FILE* 流中解压剩余数据到目标目录
 * @param fp     已打开的文件流（当前位置为压缩数据开始处）
 * @param dest   目标目录（必须存在）
 * @return 0 成功，-1 失败
 */
int extract_archive(FILE *fp, const char *dest) {
    struct archive *a = archive_read_new();
    struct archive *ext = archive_write_disk_new();
    int r;

    // 设置解压选项：保留权限、时间等
    archive_write_disk_set_options(ext,
        ARCHIVE_EXTRACT_TIME | ARCHIVE_EXTRACT_PERM |
        ARCHIVE_EXTRACT_ACL | ARCHIVE_EXTRACT_FFLAGS);
    // 支持所有压缩和格式
    archive_read_support_filter_all(a);
    archive_read_support_format_all(a);

    // 从 FILE* 打开（从当前位置开始读）
    if (archive_read_open_FILE(a, fp) != ARCHIVE_OK) {
        archive_read_free(a);
        archive_write_free(ext);
        return -1;
    }

    struct archive_entry *entry;
    while ((r = archive_read_next_header(a, &entry)) == ARCHIVE_OK) {
        const char *entry_name = archive_entry_pathname(entry);
        // 拼接目标完整路径
        char full_path[MAX_PATH_LEN];
        snprintf(full_path, sizeof(full_path), "%s/%s", dest, entry_name);
        archive_entry_set_pathname(entry, full_path);

        // 写入头部（创建文件/目录）
        r = archive_write_header(ext, entry);
        if (r != ARCHIVE_OK) {
            fprintf(stderr, "archive_write_header failed: %s\n", archive_error_string(ext));
            break;
        }

        // 如果是普通文件，复制数据
        if (archive_entry_size(entry) > 0) {
            char buff[8192];
            ssize_t size;
            while ((size = archive_read_data(a, buff, sizeof(buff))) > 0) {
                ssize_t written = archive_write_data(ext, buff, size);
                if (written != size) {
                    fprintf(stderr, "archive_write_data failed: %s\n", archive_error_string(ext));
                    r = ARCHIVE_FATAL;
                    break;
                }
            }
            if (size < 0) { // 读取错误
                fprintf(stderr, "archive_read_data failed: %s\n", archive_error_string(a));
                r = ARCHIVE_FATAL;
                break;
            }
        }

        // 完成当前条目的写入
        r = archive_write_finish_entry(ext);
        if (r != ARCHIVE_OK) {
            fprintf(stderr, "archive_write_finish_entry failed: %s\n", archive_error_string(ext));
            break;
        }
    }

    // 清理
    archive_read_close(a);
    archive_read_free(a);
    archive_write_close(ext);
    archive_write_free(ext);

    // 如果正常结束（读到文件尾），返回 0
    return (r == ARCHIVE_EOF) ? 0 : -1;
}
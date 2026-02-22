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

#define _XOPEN_SOURCE 700

#include <archive.h>
#include <archive_entry.h>
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "../include/cpkg.h"

/* 用于在 nftw 回调中传递数据的全局变量（单线程安全） */
static struct archive *g_archive = NULL;
static char *g_base = NULL;          // 顶级目录名（用于归档路径）
static char *g_dir_path = NULL;      // 源目录的绝对路径
static size_t g_prefix_len = 0;      // g_dir_path 的长度
static int g_has_trailing_slash = 0; // g_dir_path 是否以 '/' 结尾

/* 内存写入回调所需的结构体 */
struct mem_data {
    char *buf;
    size_t size;
    size_t capacity;
};

/* 内存写入回调：打开（分配初始缓冲区） */
static int mem_open(struct archive *a, void *client_data) {
    (void)a;
    struct mem_data *md = (struct mem_data *)client_data;
    md->size = 0;
    md->capacity = 1024;
    md->buf = (char *)malloc(md->capacity);
    return md->buf ? ARCHIVE_OK : ARCHIVE_FATAL;
}

/* 内存写入回调：写入数据（动态扩展缓冲区） */
static la_ssize_t mem_write(struct archive *a, void *client_data,
                            const void *buffer, size_t length) {
    (void)a;
    struct mem_data *md = (struct mem_data *)client_data;
    if (md->size + length > md->capacity) {
        size_t new_cap = md->capacity * 2;
        while (new_cap < md->size + length)
            new_cap *= 2;
        char *new_buf = (char *)realloc(md->buf, new_cap);
        if (!new_buf)
            return -1;
        md->buf = new_buf;
        md->capacity = new_cap;
    }
    memcpy(md->buf + md->size, buffer, length);
    md->size += length;
    return (la_ssize_t)length;
}

/* 内存写入回调：关闭（无需操作） */
static int mem_close(struct archive *a, void *client_data) {
    (void)a;
    (void)client_data;
    return ARCHIVE_OK;
}

/* nftw 遍历回调：将单个文件/目录添加到归档中 */
static int add_entry(const char *fpath, const struct stat *sb,
                     int typeflag, struct FTW *ftwbuf) {
    (void)typeflag;
    (void)ftwbuf;

    /* 计算相对路径（以顶级目录名为根） */
    const char *relative;
    if (strcmp(fpath, g_dir_path) == 0) {
        relative = ""; // 顶级目录本身
    } else {
        if (g_has_trailing_slash) {
            relative = fpath + g_prefix_len;      // 跳过包括结尾 '/'
        } else {
            relative = fpath + g_prefix_len + 1;   // 跳过目录和下一个 '/'
        }
    }

    /* 构建归档内的路径：顶级目录名 + 相对路径 */
    char *entry_path;
    if (relative[0] == '\0') {
        entry_path = strdup(g_base);
    } else {
        size_t len = strlen(g_base) + 1 + strlen(relative) + 1;
        entry_path = (char *)malloc(len);
        if (entry_path)
            snprintf(entry_path, len, "%s/%s", g_base, relative);
    }
    if (!entry_path)
        return -1;

    /* 创建归档条目并复制 stat 信息 */
    struct archive_entry *entry = archive_entry_new();
    archive_entry_set_pathname(entry, entry_path);
    archive_entry_copy_stat(entry, sb);

    /* 只处理普通文件和目录，其他类型（符号链接、设备等）忽略 */
    if (!S_ISREG(sb->st_mode) && !S_ISDIR(sb->st_mode)) {
        archive_entry_free(entry);
        free(entry_path);
        return 0;
    }

    /* 写入头部 */
    int r = archive_write_header(g_archive, entry);
    if (r != ARCHIVE_OK) {
        archive_entry_free(entry);
        free(entry_path);
        return -1;
    }

    /* 如果是普通文件，写入数据 */
    if (S_ISREG(sb->st_mode)) {
        int fd = open(fpath, O_RDONLY);
        if (fd < 0) {
            archive_entry_free(entry);
            free(entry_path);
            return -1;
        }
        char buf[8192];
        ssize_t bytes_read;
        while ((bytes_read = read(fd, buf, sizeof(buf))) > 0) {
            ssize_t written = archive_write_data(g_archive, buf, bytes_read);
            if (written != bytes_read) {
                close(fd);
                archive_entry_free(entry);
                free(entry_path);
                return -1;
            }
        }
        close(fd);
    }

    archive_entry_free(entry);
    free(entry_path);
    return 0;
}

/**
 * @brief 压缩目录为 tar.gz 文件, 并返回压缩文件内容，调用者需自己释放内存
 * @param src_dir 要压缩的目录路径
 * @return 成功时返回压缩文件内容的指针，失败时返回 NULL
 *
 * @note 返回的指针指向 malloc 分配的内存，使用后需 free。
 * @note 由于未返回长度，调用者必须通过其他方式确定数据大小。
 * @note 需要链接 libarchive (-larchive) 和 POSIX 标准库。
 */
char *archive_create_tgz(const char *src_dir, size_t *out_len) 
{
    if (!src_dir || !out_len)
        return NULL;

    *out_len = 0;  // 初始化

    /* 获取源目录的绝对路径 */
    char *abs_path = realpath(src_dir, NULL);
    if (!abs_path)
        return NULL;

    /* 计算路径信息 */
    g_dir_path = abs_path;
    g_prefix_len = strlen(g_dir_path);
    g_has_trailing_slash = (g_prefix_len > 0 && g_dir_path[g_prefix_len - 1] == '/');

    /* 提取顶级目录名 */
    char *base = strrchr(g_dir_path, '/');
    if (base) {
        base++;
        if (*base == '\0')
            g_base = strdup(".");
        else
            g_base = strdup(base);
    } else {
        g_base = strdup(g_dir_path);
    }
    if (!g_base) {
        free(g_dir_path);
        return NULL;
    }

    /* 初始化内存写入结构 */
    struct mem_data md = {0};

    /* 创建写入归档对象 */
    struct archive *a = archive_write_new();
    if (!a) {
        free(g_dir_path);
        free(g_base);
        return NULL;
    }
    g_archive = a;

    /* 设置 gzip 压缩和 tar 格式 */
    if (archive_write_add_filter_gzip(a) != ARCHIVE_OK ||
        archive_write_set_format_pax_restricted(a) != ARCHIVE_OK) {
        archive_write_free(a);
        free(g_dir_path);
        free(g_base);
        return NULL;
    }

    /* 打开内存写入 */
    if (archive_write_open(a, &md, mem_open, mem_write, mem_close) != ARCHIVE_OK) {
        archive_write_free(a);
        free(g_dir_path);
        free(g_base);
        return NULL;
    }

    /* 遍历目录树，添加所有条目 */
    int flags = FTW_PHYS;
    if (nftw(g_dir_path, add_entry, 20, flags) != 0) {
        archive_write_close(a);
        archive_write_free(a);
        free(md.buf);
        free(g_dir_path);
        free(g_base);
        return NULL;
    }

    /* 完成归档 */
    archive_write_close(a);
    archive_write_free(a);
    free(g_dir_path);
    free(g_base);

    /* 设置输出长度并返回数据指针 */
    *out_len = md.size;
    return md.buf;  // 调用者负责 free
}
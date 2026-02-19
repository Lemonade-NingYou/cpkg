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

/**
 * @brief nftw 遍历回调：将单个文件/目录添加到归档中
 * @note 使用线程本地存储（TLS）来实现线程安全。
 *       当前实现使用静态变量，适合单线程或互斥锁保护的多线程场景。
 */
typedef struct {
    struct archive *archive;
    char *base;
    char *dir_path;
    size_t prefix_len;
    int has_trailing_slash;
} ArchiveContext;

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

/* 线程本地存储的上下文（使用 __thread 实现） */
static __thread ArchiveContext *tls_ctx = NULL;

/* nftw 遍历回调：将单个文件/目录添加到归档中 */
static int add_entry(const char *fpath, const struct stat *sb,
                     int typeflag, struct FTW *ftwbuf) {
    (void)typeflag;
    (void)ftwbuf;

    if (!tls_ctx)
        return -1;

    ArchiveContext *ctx = tls_ctx;

    /* 计算相对路径（以顶级目录名为根） */
    const char *relative;
    if (strcmp(fpath, ctx->dir_path) == 0) {
        relative = "";  // 顶级目录本身
    } else {
        if (ctx->has_trailing_slash) {
            relative = fpath + ctx->prefix_len;      // 跳过包括结尾 '/'
        } else {
            relative = fpath + ctx->prefix_len + 1;   // 跳过目录和下一个 '/'
        }
    }

    /* 构建归档内的路径：顶级目录名 + 相对路径 */
    char *entry_path;
    if (relative[0] == '\0') {
        entry_path = strdup(ctx->base);
    } else {
        size_t len = strlen(ctx->base) + 1 + strlen(relative) + 1;
        entry_path = (char *)malloc(len);
        if (entry_path)
            snprintf(entry_path, len, "%s/%s", ctx->base, relative);
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
    int r = archive_write_header(ctx->archive, entry);
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
        char buf[FILE_BUFFER_SIZE];
        ssize_t bytes_read;
        while ((bytes_read = read(fd, buf, sizeof(buf))) > 0) {
            ssize_t written = archive_write_data(ctx->archive, buf, bytes_read);
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
 * @brief 压缩目录为 tar.gz 文件，返回压缩文件内容，调用者需自己释放内存
 * @param src_dir 要压缩的目录路径
 * @param out_len 输出参数：压缩文件的大小
 * @return 成功时返回压缩文件内容的指针，失败时返回 NULL
 *
 * @note 返回的指针指向 malloc 分配的内存，使用后需 free。
 * @note 该函数线程安全，使用 __thread 关键字实现线程本地存储。
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

    /* 初始化上下文结构体 */
    ArchiveContext ctx = {0};
    ctx.dir_path = abs_path;
    ctx.prefix_len = strlen(ctx.dir_path);
    ctx.has_trailing_slash = (ctx.prefix_len > 0 && ctx.dir_path[ctx.prefix_len - 1] == '/');

    /* 提取顶级目录名 */
    char *base = strrchr(ctx.dir_path, '/');
    if (base) {
        base++;
        if (*base == '\0')
            ctx.base = strdup(".");
        else
            ctx.base = strdup(base);
    } else {
        ctx.base = strdup(ctx.dir_path);
    }
    if (!ctx.base) {
        free(ctx.dir_path);
        return NULL;
    }

    /* 初始化内存写入结构 */
    struct mem_data md = {0};

    /* 创建写入归档对象 */
    struct archive *a = archive_write_new();
    if (!a) {
        free(ctx.dir_path);
        free(ctx.base);
        return NULL;
    }
    ctx.archive = a;

    /* 设置 gzip 压缩和 tar 格式 */
    if (archive_write_add_filter_gzip(a) != ARCHIVE_OK ||
        archive_write_set_format_pax_restricted(a) != ARCHIVE_OK) {
        archive_write_free(a);
        free(ctx.dir_path);
        free(ctx.base);
        return NULL;
    }

    /* 打开内存写入 */
    if (archive_write_open(a, &md, mem_open, mem_write, mem_close) != ARCHIVE_OK) {
        archive_write_free(a);
        free(ctx.dir_path);
        free(ctx.base);
        return NULL;
    }

    /* 设置线程本地存储指针，供 nftw 回调使用 */
    tls_ctx = &ctx;

    /* 遍历目录树，添加所有条目 */
    int flags = FTW_PHYS;
    if (nftw(ctx.dir_path, add_entry, 20, flags) != 0) {
        tls_ctx = NULL;  // 清空 TLS 指针
        archive_write_close(a);
        archive_write_free(a);
        free(md.buf);
        free(ctx.dir_path);
        free(ctx.base);
        return NULL;
    }

    /* 清空 TLS 指针 */
    tls_ctx = NULL;

    /* 完成归档 */
    archive_write_close(a);
    archive_write_free(a);
    free(ctx.dir_path);
    free(ctx.base);

    /* 设置输出长度并返回数据指针 */
    *out_len = md.size;
    return md.buf;  // 调用者负责 free
}
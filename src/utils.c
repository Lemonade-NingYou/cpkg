#define _XOPEN_SOURCE 500

#include "utils.h"

#include <archive.h>
#include <archive_entry.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ---------- 全局变量 ---------- */
static int lock_fd = -1; /* 锁文件描述符，-1 表示未持有 */

/* ---------- 内部辅助函数 ---------- */

/**
 * trim - 去除字符串首尾空白字符（空格、制表、换行、回车）
 */
static void trim(char* str) {
    if (!str) return;
    char* p = str;
    while (*p == ' ' || *p == '\t') p++;
    if (p != str) memmove(str, p, strlen(p) + 1);

    size_t len = strlen(str);
    while (len > 0 && (str[len - 1] == ' ' || str[len - 1] == '\t' ||
                       str[len - 1] == '\n' || str[len - 1] == '\r')) {
        str[--len] = '\0';
    }
}

/**
 * split_csv - 将逗号分隔的字符串解析为字符串数组
 * @str: 输入字符串（会被修改内部拷贝，原串不变）
 * @count: 输出数组元素个数
 * 返回: 动态分配的字符串数组，使用后需逐个 free 并 free 数组本身
 */
static char** split_csv(const char* str, int* count) {
    if (!str || !count) return NULL;
    *count = 0;

    char* dup = strdup(str);
    if (!dup) return NULL;

    /* 第一遍：统计有效 token 数量 */
    char* saveptr = NULL;
    char* token = strtok_r(dup, ",", &saveptr);
    int n = 0;
    while (token) {
        trim(token);
        if (strlen(token) > 0) n++;
        token = strtok_r(NULL, ",", &saveptr);
    }
    if (n == 0) {
        free(dup);
        return NULL;
    }

    /* 分配指针数组 */
    char** arr = malloc(sizeof(char*) * n);
    if (!arr) {
        free(dup);
        return NULL;
    }

    /* 第二遍：复制有效 token */
    strcpy(dup, str);  // 重置为原始字符串
    saveptr = NULL;
    token = strtok_r(dup, ",", &saveptr);
    int idx = 0;
    while (token && idx < n) {
        trim(token);
        if (strlen(token) > 0) {
            arr[idx] = strdup(token);
            if (!arr[idx]) {
                for (int i = 0; i < idx; i++) free(arr[i]);
                free(arr);
                free(dup);
                return NULL;
            }
            idx++;
        }
        token = strtok_r(NULL, ",", &saveptr);
    }
    *count = n;
    free(dup);
    return arr;
}

/**
 * add_directory_to_archive - 递归将目录内容添加到归档中
 * @a: 归档写入对象
 * @path: 源目录路径
 * @base: 归档内的基础路径前缀（可为 NULL）
 * 返回: 0 成功，-1 失败
 */
static int add_directory_to_archive(struct archive* a, const char* path,
                                    const char* base) {
    DIR* dir = opendir(path);
    if (!dir) {
        fprintf(stderr, "Failed to open directory %s: %s\n", path, strerror(errno));
        return -1;
    }

    struct dirent* entry;
    char fullpath[PATH_MAX];
    char entry_name[PATH_MAX];

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        snprintf(fullpath, sizeof(fullpath), "%s/%s", path, entry->d_name);
        if (base) {
            snprintf(entry_name, sizeof(entry_name), "%s/%s", base, entry->d_name);
        } else {
            strncpy(entry_name, entry->d_name, sizeof(entry_name) - 1);
            entry_name[sizeof(entry_name) - 1] = '\0';
        }

        struct stat st;
        if (lstat(fullpath, &st) != 0) {
            fprintf(stderr, "Cannot stat %s: %s\n", fullpath, strerror(errno));
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            struct archive_entry* ae = archive_entry_new();
            if (!ae) {
                closedir(dir);
                return -1;
            }
            archive_entry_set_pathname(ae, entry_name);
            archive_entry_set_mode(ae, S_IFDIR | 0755);
            archive_entry_set_size(ae, 0);
            if (archive_write_header(a, ae) != ARCHIVE_OK) {
                fprintf(stderr, "Error writing directory header: %s\n",
                        archive_error_string(a));
                archive_entry_free(ae);
                closedir(dir);
                return -1;
            }
            archive_entry_free(ae);

            if (add_directory_to_archive(a, fullpath, entry_name) != 0) {
                closedir(dir);
                return -1;
            }
        } else if (S_ISREG(st.st_mode)) {
            struct archive_entry* ae = archive_entry_new();
            if (!ae) {
                closedir(dir);
                return -1;
            }
            archive_entry_set_pathname(ae, entry_name);
            archive_entry_set_mode(ae, st.st_mode);
            archive_entry_set_size(ae, st.st_size);
            archive_entry_set_mtime(ae, st.st_mtime, 0);

            if (archive_write_header(a, ae) != ARCHIVE_OK) {
                fprintf(stderr, "Error writing file header: %s\n",
                        archive_error_string(a));
                archive_entry_free(ae);
                closedir(dir);
                return -1;
            }
            archive_entry_free(ae);

            FILE* f = fopen(fullpath, "rb");
            if (!f) {
                fprintf(stderr, "Cannot open %s: %s\n", fullpath, strerror(errno));
                closedir(dir);
                return -1;
            }
            char buffer[8192];
            size_t nread;
            while ((nread = fread(buffer, 1, sizeof(buffer), f)) > 0) {
                if (archive_write_data(a, buffer, nread) != (ssize_t)nread) {
                    fprintf(stderr, "Error writing data: %s\n",
                            archive_error_string(a));
                    fclose(f);
                    closedir(dir);
                    return -1;
                }
            }
            fclose(f);
        }
    }
    closedir(dir);
    return 0;
}

/* ---------- 内存写入回调（用于压缩） ---------- */

typedef struct {
    unsigned char* data;
    size_t capacity;
    size_t used;
} mem_write_ctx;

static ssize_t mem_write_callback(struct archive* a, void* client_data,
                                  const void* buffer, size_t length) {
    (void)a;
    mem_write_ctx* ctx = (mem_write_ctx*)client_data;
    if (ctx->used + length > ctx->capacity) {
        size_t new_cap = ctx->capacity ? ctx->capacity * 2 : 4096;
        while (new_cap < ctx->used + length) new_cap *= 2;
        unsigned char* new_data = realloc(ctx->data, new_cap);
        if (!new_data) return -1;
        ctx->data = new_data;
        ctx->capacity = new_cap;
    }
    memcpy(ctx->data + ctx->used, buffer, length);
    ctx->used += length;
    return (ssize_t)length;
}

static int mem_close_callback(struct archive* a, void* client_data) {
    (void)a;
    mem_write_ctx* ctx = (mem_write_ctx*)client_data;
    if (ctx->used < ctx->capacity) {
        unsigned char* new_data = realloc(ctx->data, ctx->used);
        if (new_data) {
            ctx->data = new_data;
            ctx->capacity = ctx->used;
        }
    }
    return ARCHIVE_OK;
}

/* ---------- 公共 API 实现 ---------- */

/**
 * InitCpkg - 初始化工作目录（若不存在则创建，若存在则检查是否为目录）
 * 失败时直接退出进程（生产级设计）
 */
void InitCpkg(void) {
    struct stat st;
    if (stat(WORK_DIR, &st) == 0) {
        if (!S_ISDIR(st.st_mode)) {
            fprintf(stderr, "Error: %s exists but is not a directory\n", WORK_DIR);
            exit(EXIT_FAILURE);
        }
        return; /* 目录已存在且有效 */
    }
    if (mkdir(WORK_DIR, 0755) != 0) {
        fprintf(stderr, "Failed to create directory %s: %s\n",
                WORK_DIR, strerror(errno));
        exit(EXIT_FAILURE);
    }
}

/**
 * is_dir - 检查路径是否为目录
 */
bool is_dir(const char* path) {
    struct stat st;
    return (stat(path, &st) == 0 && S_ISDIR(st.st_mode));
}

/**
 * get_file_size - 获取普通文件大小（使用 lstat，不跟随符号链接）
 */
bool get_file_size(const char* path, uint64_t* size) {
    struct stat st;
    if (lstat(path, &st) != 0 || !S_ISREG(st.st_mode))
        return false;
    *size = (uint64_t)st.st_size;
    return true;
}

/* 用于 nftw 的全局累加器（单线程安全） */
static uint64_t dir_size_total = 0;

static int nftw_size_cb(const char* fpath, const struct stat* sb,
                        int typeflag, struct FTW* ftwbuf) {
    (void)fpath;
    (void)ftwbuf;
    if (typeflag == FTW_F)
        dir_size_total += (uint64_t)sb->st_size;
    return 0;
}

/**
 * get_directory_size - 计算目录下所有文件的总大小（不跟随符号链接）
 */
bool get_directory_size(const char* path, uint64_t* total) {
    if (!is_dir(path)) return false;
    dir_size_total = 0;
    if (nftw(path, nftw_size_cb, 20, FTW_PHYS) == 0) {
        *total = dir_size_total;
        return true;
    }
    return false;
}

/**
 * ReadConfig - 从文件读取配置，返回 Config 结构体
 * 调用者需使用 FreeConfig 释放
 */
Config* ReadConfig(const char* ConfigPath) {
    FILE* file = fopen(ConfigPath, "r");
    if (!file) {
        fprintf(stderr, "Failed to open config file '%s': %s\n",
                ConfigPath, strerror(errno));
        return NULL;
    }

    Config* config = calloc(1, sizeof(Config));
    if (!config) {
        fprintf(stderr, "Memory allocation failed for Config\n");
        fclose(file);
        return NULL;
    }

    char line[512];
    while (fgets(line, sizeof(line), file)) {
        char* p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == '\0')
            continue;

        char* delim = strchr(p, ':');
        if (!delim) continue;
        *delim = '\0';
        char* key = p;
        char* value = delim + 1;
        trim(key);
        trim(value);
        if (strlen(key) == 0 || strlen(value) == 0)
            continue;

        if (strcmp(key, "PocketName") == 0) {
            strncpy(config->PocketName, value, sizeof(config->PocketName) - 1);
            config->PocketName[sizeof(config->PocketName) - 1] = '\0';
        } else if (strcmp(key, "version") == 0) {
            strncpy(config->version, value, sizeof(config->version) - 1);
            config->version[sizeof(config->version) - 1] = '\0';
        } else if (strcmp(key, "authors") == 0) {
            strncpy(config->authors, value, sizeof(config->authors) - 1);
            config->authors[sizeof(config->authors) - 1] = '\0';
        } else if (strcmp(key, "license") == 0) {
            strncpy(config->license, value, sizeof(config->license) - 1);
            config->license[sizeof(config->license) - 1] = '\0';
        } else if (strcmp(key, "description") == 0) {
            strncpy(config->description, value, sizeof(config->description) - 1);
            config->description[sizeof(config->description) - 1] = '\0';
        } else if (strcmp(key, "libs") == 0) {
            config->libs = atoi(value);
        } else if (strcmp(key, "libNames") == 0) {
            if (config->libNames) {
                for (int i = 0; i < config->libs; i++) free(config->libNames[i]);
                free(config->libNames);
                config->libNames = NULL;
                config->libs = 0;
            }
            config->libNames = split_csv(value, &config->libs);
            if (!config->libNames) config->libs = 0;
        } else if (strcmp(key, "include") == 0) {
            config->include = atoi(value);
        } else if (strcmp(key, "includeNames") == 0) {
            if (config->includeNames) {
                for (int i = 0; i < config->include; i++) free(config->includeNames[i]);
                free(config->includeNames);
                config->includeNames = NULL;
                config->include = 0;
            }
            config->includeNames = split_csv(value, &config->include);
            if (!config->includeNames) config->include = 0;
        }
    }
    fclose(file);
    return config;
}

/**
 * FreeConfig - 释放 Config 结构体及其内部动态分配的内存
 */
void FreeConfig(Config* config) {
    if (!config) return;
    if (config->libNames) {
        for (int i = 0; i < config->libs; i++) free(config->libNames[i]);
        free(config->libNames);
    }
    if (config->includeNames) {
        for (int i = 0; i < config->include; i++) free(config->includeNames[i]);
        free(config->includeNames);
    }
    free(config);
}

/**
 * ChangeStructToJson - 将 Config 转换为 JSON 字符串
 * 返回动态分配的字符串，调用者需 free
 */
char* ChangeStructToJson(const Config* config) {
    if (!config) return NULL;

    char libs_str[1024] = "";
    char inc_str[1024] = "";

    if (config->libs > 0 && config->libNames) {
        strcat(libs_str, "[");
        for (int i = 0; i < config->libs; i++) {
            if (i > 0) strcat(libs_str, ",");
            strcat(libs_str, "\"");
            char* p = config->libNames[i];
            while (*p) {
                if (*p == '"' || *p == '\\') strcat(libs_str, "\\");
                char tmp[2] = {*p, '\0'};
                strcat(libs_str, tmp);
                p++;
            }
            strcat(libs_str, "\"");
        }
        strcat(libs_str, "]");
    } else {
        strcpy(libs_str, "[]");
    }

    if (config->include > 0 && config->includeNames) {
        strcat(inc_str, "[");
        for (int i = 0; i < config->include; i++) {
            if (i > 0) strcat(inc_str, ",");
            strcat(inc_str, "\"");
            char* p = config->includeNames[i];
            while (*p) {
                if (*p == '"' || *p == '\\') strcat(inc_str, "\\");
                char tmp[2] = {*p, '\0'};
                strcat(inc_str, tmp);
                p++;
            }
            strcat(inc_str, "\"");
        }
        strcat(inc_str, "]");
    } else {
        strcpy(inc_str, "[]");
    }

    int len = snprintf(NULL, 0,
                       "{ \"PocketName\": \"%s\", \"version\": \"%s\", "
                       "\"authors\": \"%s\", \"license\": \"%s\", "
                       "\"description\": \"%s\", \"libs\": %d, "
                       "\"libNames\": %s, \"include\": %d, \"includeNames\": %s }",
                       config->PocketName, config->version, config->authors,
                       config->license, config->description, config->libs,
                       libs_str, config->include, inc_str);
    if (len < 0) return NULL;

    char* json = malloc(len + 1);
    if (!json) {
        fprintf(stderr, "Memory allocation failed for JSON string\n");
        return NULL;
    }
    snprintf(json, len + 1,
             "{ \"PocketName\": \"%s\", \"version\": \"%s\", "
             "\"authors\": \"%s\", \"license\": \"%s\", "
             "\"description\": \"%s\", \"libs\": %d, "
             "\"libNames\": %s, \"include\": %d, \"includeNames\": %s }",
             config->PocketName, config->version, config->authors,
             config->license, config->description, config->libs,
             libs_str, config->include, inc_str);
    return json;
}

/**
 * GzipToMemory - 将单个文件压缩为 gzip 格式并存入内存
 * @outSize: 输出数据长度
 * 返回: 动态分配的缓冲区，调用者需 free
 */
unsigned char* GzipToMemory(const char* filePath, size_t* outSize) {
    if (!filePath || !outSize) return NULL;
    *outSize = 0;

    struct stat st;
    if (stat(filePath, &st) != 0 || !S_ISREG(st.st_mode)) {
        fprintf(stderr, "Invalid file: %s\n", filePath);
        return NULL;
    }

    struct archive* a = archive_write_new();
    if (!a) {
        fprintf(stderr, "Failed to create archive writer\n");
        return NULL;
    }

    if (archive_write_add_filter_gzip(a) != ARCHIVE_OK) {
        fprintf(stderr, "Failed to add gzip filter: %s\n", archive_error_string(a));
        archive_write_free(a);
        return NULL;
    }
    archive_write_set_format_gnutar(a);

    mem_write_ctx ctx = {.data = NULL, .capacity = 0, .used = 0};
    if (archive_write_open(a, &ctx, NULL, mem_write_callback, mem_close_callback) != ARCHIVE_OK) {
        fprintf(stderr, "Failed to open archive: %s\n", archive_error_string(a));
        archive_write_free(a);
        free(ctx.data);
        return NULL;
    }

    struct archive_entry* ae = archive_entry_new();
    if (!ae) {
        fprintf(stderr, "Failed to create archive entry\n");
        archive_write_free(a);
        free(ctx.data);
        return NULL;
    }
    const char* base = strrchr(filePath, '/');
    base = base ? base + 1 : filePath;
    archive_entry_set_pathname(ae, base);
    archive_entry_set_mode(ae, st.st_mode);
    archive_entry_set_size(ae, st.st_size);
    archive_entry_set_mtime(ae, st.st_mtime, 0);

    if (archive_write_header(a, ae) != ARCHIVE_OK) {
        fprintf(stderr, "Error writing header: %s\n", archive_error_string(a));
        archive_entry_free(ae);
        archive_write_free(a);
        free(ctx.data);
        return NULL;
    }
    archive_entry_free(ae);

    FILE* f = fopen(filePath, "rb");
    if (!f) {
        fprintf(stderr, "Cannot open %s: %s\n", filePath, strerror(errno));
        archive_write_free(a);
        free(ctx.data);
        return NULL;
    }
    char buf[8192];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        if (archive_write_data(a, buf, n) != (ssize_t)n) {
            fprintf(stderr, "Error writing data: %s\n", archive_error_string(a));
            fclose(f);
            archive_write_free(a);
            free(ctx.data);
            return NULL;
        }
    }
    fclose(f);

    if (archive_write_close(a) != ARCHIVE_OK) {
        fprintf(stderr, "Error closing archive: %s\n", archive_error_string(a));
        archive_write_free(a);
        free(ctx.data);
        return NULL;
    }
    archive_write_free(a);

    *outSize = ctx.used;
    return ctx.data;
}

/**
 * GzipToMemoryDir - 将 libs 和 include 两个目录打包压缩为 gzip 内存数据
 * 归档内目录结构为 "libs/" 和 "include/"
 */
unsigned char* GzipToMemoryDir(const char* libsPath, const char* includePath,
                               size_t* outSize) {
    if (!libsPath || !includePath || !outSize) return NULL;
    *outSize = 0;

    if (!is_dir(libsPath) || !is_dir(includePath)) {
        fprintf(stderr, "One of the directories is invalid\n");
        return NULL;
    }

    struct archive* a = archive_write_new();
    if (!a) {
        fprintf(stderr, "Failed to create archive writer\n");
        return NULL;
    }

    if (archive_write_add_filter_gzip(a) != ARCHIVE_OK) {
        fprintf(stderr, "Failed to add gzip filter: %s\n", archive_error_string(a));
        archive_write_free(a);
        return NULL;
    }
    archive_write_set_format_gnutar(a);

    mem_write_ctx ctx = {.data = NULL, .capacity = 0, .used = 0};
    if (archive_write_open(a, &ctx, NULL, mem_write_callback, mem_close_callback) != ARCHIVE_OK) {
        fprintf(stderr, "Failed to open archive: %s\n", archive_error_string(a));
        archive_write_free(a);
        free(ctx.data);
        return NULL;
    }

    if (add_directory_to_archive(a, libsPath, "libs") != 0 ||
        add_directory_to_archive(a, includePath, "include") != 0) {
        archive_write_free(a);
        free(ctx.data);
        return NULL;
    }

    if (archive_write_close(a) != ARCHIVE_OK) {
        fprintf(stderr, "Error closing archive: %s\n", archive_error_string(a));
        archive_write_free(a);
        free(ctx.data);
        return NULL;
    }
    archive_write_free(a);

    *outSize = ctx.used;
    return ctx.data;
}

/**
 * GetLock - 使用 fcntl 获取全局排他锁（类 dpkg 实现）
 * 阻塞直到获得锁，失败则退出进程
 */
void GetLock(void) {
    if (!is_dir(WORK_DIR)) {
        InitCpkg();
    }

    lock_fd = open(LOCKFILE_PATH, O_CREAT | O_RDWR, 0644);
    if (lock_fd == -1) {
        fprintf(stderr, "Failed to open/create lock file %s: %s\n",
                LOCKFILE_PATH, strerror(errno));
        exit(EXIT_FAILURE);
    }

    struct flock fl;
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0; /* 锁整个文件 */

    while (fcntl(lock_fd, F_SETLKW, &fl) == -1) {
        if (errno == EINTR) continue;
        fprintf(stderr, "Failed to acquire lock on %s: %s\n",
                LOCKFILE_PATH, strerror(errno));
        close(lock_fd);
        lock_fd = -1;
        exit(EXIT_FAILURE);
    }

    /* 写入当前 PID 便于调试（忽略失败） */
    if (ftruncate(lock_fd, 0) != 0) {
        fprintf(stderr, "Warning: could not truncate lock file\n");
    } else {
        char pid_buf[32];
        int len = snprintf(pid_buf, sizeof(pid_buf), "%d\n", getpid());
        if (len > 0 && write(lock_fd, pid_buf, len) != len) {
            fprintf(stderr, "Warning: could not write PID to lock file\n");
        }
    }
    fsync(lock_fd);

    printf("Lock acquired (PID: %d)\n", getpid());
}

/**
 * ReleaseLock - 释放之前持有的锁
 */
void ReleaseLock(void) {
    if (lock_fd != -1) {
        struct flock fl;
        fl.l_type = F_UNLCK;
        fl.l_whence = SEEK_SET;
        fl.l_start = 0;
        fl.l_len = 0;

        if (fcntl(lock_fd, F_SETLK, &fl) == -1) {
            fprintf(stderr, "Warning: failed to unlock %s: %s\n",
                    LOCKFILE_PATH, strerror(errno));
        }
        close(lock_fd);
        lock_fd = -1;
        printf("Lock released\n");
    }
}
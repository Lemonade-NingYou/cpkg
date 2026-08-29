#define _GNU_SOURCE
#define _XOPEN_SOURCE 500
#include "utils.h"
#include "outerror.h"

#include <cjson/cJSON.h>
#include <archive.h>
#include <archive_entry.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <glob.h>
#include <limits.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <yaml.h>
#include <libgen.h>

/* ---------- 全局变量 ---------- */
static int lock_fd = -1;
static const char **g_dst_bases;
static int g_dst_count;
static InstallList *g_install_list;

/* ---------- 内部辅助函数 ---------- */
static void free_str_array(char** arr, int count) {
    if (!arr) return;
    for (int i = 0; i < count; i++) free(arr[i]);
    free(arr);
}

static void safe_strcpy(char* dest, const char* src, size_t dest_size) {
    if (!dest || !src) return;
    strncpy(dest, src, dest_size - 1);
    dest[dest_size - 1] = '\0';
    }

static const char* scalar_value(yaml_document_t* doc, yaml_node_t* node) {
    if (!node || node->type != YAML_SCALAR_NODE) return NULL;
    return (const char*)node->data.scalar.value;
}

static char** parse_sequence(yaml_document_t* doc, yaml_node_t* seq_node, int* out_count) {
    if (!seq_node || seq_node->type != YAML_SEQUENCE_NODE) {
        *out_count = 0;
        return NULL;
    }
    int count = seq_node->data.sequence.items.top - seq_node->data.sequence.items.start;
    if (count == 0) {
        *out_count = 0;
        return NULL;
    }
    char** arr = malloc(sizeof(char*) * count);
    if (!arr) {
        *out_count = 0;
        return NULL;
    }
    int idx = 0;
    yaml_node_item_t* item;
    for (item = seq_node->data.sequence.items.start; item < seq_node->data.sequence.items.top; item++, idx++) {
        yaml_node_t* elem = yaml_document_get_node(doc, *item);
        if (elem && elem->type == YAML_SCALAR_NODE) {
            arr[idx] = strdup((const char*)elem->data.scalar.value);
            if (!arr[idx]) {
                for (int i = 0; i < idx; i++) free(arr[i]);
                free(arr);
                *out_count = 0;
                return NULL;
            }
        } else {
            arr[idx] = strdup("");
        }
    }
    *out_count = count;
    return arr;
}

static bool parse_bool(const char* str) {
    if (!str) return false;
    if (strcmp(str, "true") == 0 || strcmp(str, "yes") == 0 ||
        strcmp(str, "on") == 0 || strcmp(str, "1") == 0) {
        return true;
    }
    return false;
}

/* ---------- ChangeStructToJson 辅助 ---------- */
static void fwrite_json_string(FILE* f, const char* s) {
    if (!s) return;
    fputc('"', f);
    while (*s) {
        unsigned char ch = *s++;
        switch (ch) {
            case '"':  fputs("\\\"", f); break;
            case '\\': fputs("\\\\", f); break;
            case '\b': fputs("\\b", f);  break;
            case '\f': fputs("\\f", f);  break;
            case '\n': fputs("\\n", f);  break;
            case '\r': fputs("\\r", f);  break;
            case '\t': fputs("\\t", f);  break;
            default:
                if (ch < 0x20) fprintf(f, "\\u%04x", ch);
                else fputc(ch, f);
                break;
        }
    }
    fputc('"', f);
}

static void fwrite_json_array(FILE* f, char** arr, int count, int indent_level) {
    if (count == 0 || !arr) { fputs("[]", f); return; }
    fputs("[\n", f);
    for (int i = 0; i < count; i++) {
        for (int j = 0; j < indent_level + 2; j++) fputc(' ', f);
        fwrite_json_string(f, arr[i]);
        if (i < count - 1) fputc(',', f);
        fputc('\n', f);
    }
    for (int j = 0; j < indent_level; j++) fputc(' ', f);
    fputc(']', f);
}

/* ---------- 公共 API ---------- */
Config* ReadConfig(const char* ConfigPath) {
    FILE* fh = fopen(ConfigPath, "rb");
    if (!fh) {
        fprintf(stderr, "Failed to open config file '%s': %s\n", ConfigPath, strerror(errno));
        return NULL;
    }
    Config* cfg = calloc(1, sizeof(Config));
    if (!cfg) { fclose(fh); fprintf(stderr, "Memory allocation failed\n"); return NULL; }
    safe_strcpy(cfg->default_libs_dir, "libs", sizeof(cfg->default_libs_dir));
    safe_strcpy(cfg->default_include_dir, "include", sizeof(cfg->default_include_dir));
    cfg->ignore_hidden = true;
    cfg->follow_symlinks = false;

    yaml_parser_t parser;
    yaml_document_t document;
    yaml_parser_initialize(&parser);
    yaml_parser_set_input_file(&parser, fh);
    if (!yaml_parser_load(&parser, &document)) {
        fprintf(stderr, "Failed to parse YAML file: %s\n", ConfigPath);
        yaml_parser_delete(&parser);
        fclose(fh);
        free(cfg);
        return NULL;
    }
    yaml_node_t* root = yaml_document_get_root_node(&document);
    if (!root || root->type != YAML_MAPPING_NODE) {
        fprintf(stderr, "Root node is not a mapping\n");
        yaml_document_delete(&document);
        yaml_parser_delete(&parser);
        fclose(fh);
        free(cfg);
        return NULL;
    }
    yaml_node_pair_t* pair;
    for (pair = root->data.mapping.pairs.start; pair < root->data.mapping.pairs.top; pair++) {
        yaml_node_t* key_node = yaml_document_get_node(&document, pair->key);
        yaml_node_t* val_node = yaml_document_get_node(&document, pair->value);
        if (!key_node || key_node->type != YAML_SCALAR_NODE) continue;
        const char* key = (const char*)key_node->data.scalar.value;

        if (strcmp(key, "PocketName") == 0) {
            const char* v = scalar_value(&document, val_node);
            if (v) safe_strcpy(cfg->PocketName, v, sizeof(cfg->PocketName));
        } else if (strcmp(key, "version") == 0) {
            const char* v = scalar_value(&document, val_node);
            if (v) safe_strcpy(cfg->version, v, sizeof(cfg->version));
        } else if (strcmp(key, "authors") == 0) {
            cfg->authors = parse_sequence(&document, val_node, &cfg->author_count);
        } else if (strcmp(key, "license") == 0) {
            const char* v = scalar_value(&document, val_node);
            if (v) safe_strcpy(cfg->license, v, sizeof(cfg->license));
        } else if (strcmp(key, "description") == 0) {
            const char* v = scalar_value(&document, val_node);
            if (v) safe_strcpy(cfg->description, v, sizeof(cfg->description));
        } else if (strcmp(key, "homepage") == 0) {
            const char* v = scalar_value(&document, val_node);
            if (v) safe_strcpy(cfg->homepage, v, sizeof(cfg->homepage));
        } else if (strcmp(key, "repository") == 0) {
            const char* v = scalar_value(&document, val_node);
            if (v) safe_strcpy(cfg->repository, v, sizeof(cfg->repository));
        } else if (strcmp(key, "files") == 0) {
            if (val_node->type == YAML_MAPPING_NODE) {
                yaml_node_pair_t* fp;
                for (fp = val_node->data.mapping.pairs.start; fp < val_node->data.mapping.pairs.top; fp++) {
                    yaml_node_t* fkey_node = yaml_document_get_node(&document, fp->key);
                    yaml_node_t* fval_node = yaml_document_get_node(&document, fp->value);
                    if (!fkey_node || fkey_node->type != YAML_SCALAR_NODE) continue;
                    const char* fkey = (const char*)fkey_node->data.scalar.value;
                    if (strcmp(fkey, "include") == 0)
                        cfg->include_patterns = parse_sequence(&document, fval_node, &cfg->include_count);
                    else if (strcmp(fkey, "libs") == 0)
                        cfg->lib_patterns = parse_sequence(&document, fval_node, &cfg->lib_count);
                    else if (strcmp(fkey, "exclude") == 0)
                        cfg->exclude_patterns = parse_sequence(&document, fval_node, &cfg->exclude_count);
                    else if (strcmp(fkey, "special") == 0)
                        cfg->special_files = parse_sequence(&document, fval_node, &cfg->special_count);
                }
            }
        } else if (strcmp(key, "default_dirs") == 0) {
            if (val_node->type == YAML_MAPPING_NODE) {
                yaml_node_pair_t* dp;
                for (dp = val_node->data.mapping.pairs.start; dp < val_node->data.mapping.pairs.top; dp++) {
                    yaml_node_t* dkey_node = yaml_document_get_node(&document, dp->key);
                    yaml_node_t* dval_node = yaml_document_get_node(&document, dp->value);
                    if (!dkey_node || dkey_node->type != YAML_SCALAR_NODE) continue;
                    const char* dkey = (const char*)dkey_node->data.scalar.value;
                    const char* dval = scalar_value(&document, dval_node);
                    if (!dval) continue;
                    if (strcmp(dkey, "libs") == 0)
                        safe_strcpy(cfg->default_libs_dir, dval, sizeof(cfg->default_libs_dir));
                    else if (strcmp(dkey, "include") == 0)
                        safe_strcpy(cfg->default_include_dir, dval, sizeof(cfg->default_include_dir));
                }
            }
        } else if (strcmp(key, "strict") == 0) {
            const char* v = scalar_value(&document, val_node);
            if (v) cfg->strict = parse_bool(v);
        } else if (strcmp(key, "flatten") == 0) {
            const char* v = scalar_value(&document, val_node);
            if (v) cfg->flatten = parse_bool(v);
        } else if (strcmp(key, "ignore_hidden") == 0) {
            const char* v = scalar_value(&document, val_node);
            if (v) cfg->ignore_hidden = parse_bool(v);
        } else if (strcmp(key, "follow_symlinks") == 0) {
            const char* v = scalar_value(&document, val_node);
            if (v) cfg->follow_symlinks = parse_bool(v);
        }
    }
    if (cfg->PocketName[0] == '\0' || cfg->version[0] == '\0') {
        fprintf(stderr, "Missing required fields: PocketName and/or version\n");
        FreeConfig(cfg);
        cfg = NULL;
    }
    yaml_document_delete(&document);
    yaml_parser_delete(&parser);
    fclose(fh);
    return cfg;
            }

void FreeConfig(Config* config) {
    if (!config) return;
    free_str_array(config->authors, config->author_count);
    free_str_array(config->include_patterns, config->include_count);
    free_str_array(config->lib_patterns, config->lib_count);
    free_str_array(config->exclude_patterns, config->exclude_count);
    free_str_array(config->special_files, config->special_count);
    free(config);
}

char* ChangeStructToJson(const Config* cfg) {
    if (!cfg) return NULL;
    char** include_installed = NULL;
    int include_installed_count = 0;
    char** lib_installed = NULL;
    int lib_installed_count = 0;

    #define EXPAND_AND_CONVERT(patterns, count, dest_array, dest_count, default_dir, sys_prefix) \
        do { \
            if (count > 0 && patterns) { \
                int total_files = 0; \
                for (int i = 0; i < count; i++) { \
                    glob_t gbuf; \
                    if (glob(patterns[i], GLOB_NOSORT, NULL, &gbuf) == 0) { \
                        total_files += gbuf.gl_pathc; \
                        globfree(&gbuf); \
                    } \
                } \
                if (total_files > 0) { \
                    dest_array = malloc(sizeof(char*) * total_files); \
                    if (!dest_array) goto error; \
                    int idx = 0; \
                    for (int i = 0; i < count; i++) { \
                        glob_t gbuf; \
                        if (glob(patterns[i], GLOB_NOSORT, NULL, &gbuf) == 0) { \
                            for (size_t j = 0; j < gbuf.gl_pathc; j++) { \
                                const char* src = gbuf.gl_pathv[j]; \
                                char installed[PATH_MAX]; \
                                if (src[0] == '/') { \
                                    strncpy(installed, src, sizeof(installed)-1); \
                                    installed[sizeof(installed)-1] = '\0'; \
                                } else if (strncmp(src, default_dir, strlen(default_dir)) == 0) { \
                                    const char* rel = src + strlen(default_dir); \
                                    if (*rel == '/') rel++; \
                                    snprintf(installed, sizeof(installed), "%s/%s", sys_prefix, rel); \
                                } else { \
                                    snprintf(installed, sizeof(installed), "%s/%s", sys_prefix, src); \
                                } \
                                dest_array[idx] = strdup(installed); \
                                if (!dest_array[idx]) { \
                                    for (int k = 0; k < idx; k++) free(dest_array[k]); \
                                    free(dest_array); \
                                    dest_array = NULL; \
                                    globfree(&gbuf); \
                                    goto error; \
                                } \
                                idx++; \
                            } \
                            globfree(&gbuf); \
                        } \
                    } \
                    dest_count = idx; \
                } \
            } \
        } while (0)

    EXPAND_AND_CONVERT(cfg->include_patterns, cfg->include_count,
                       include_installed, include_installed_count,
                       cfg->default_include_dir, "/usr/include/x86_64-linux-gnu");
    EXPAND_AND_CONVERT(cfg->lib_patterns, cfg->lib_count,
                       lib_installed, lib_installed_count,
                       cfg->default_libs_dir, "/usr/lib/x86_64-linux-gnu");
    #undef EXPAND_AND_CONVERT

    char* buf = NULL;
    size_t size = 0;
    FILE* f = open_memstream(&buf, &size);
    if (!f) { fprintf(stderr, "open_memstream failed\n"); goto error; }

    fprintf(f, "{\n");
    fprintf(f, "  \"PocketName\": "); fwrite_json_string(f, cfg->PocketName); fprintf(f, ",\n");
    fprintf(f, "  \"version\": "); fwrite_json_string(f, cfg->version); fprintf(f, ",\n");
    fprintf(f, "  \"authors\": "); fwrite_json_array(f, cfg->authors, cfg->author_count, 2); fprintf(f, ",\n");
    fprintf(f, "  \"license\": "); fwrite_json_string(f, cfg->license); fprintf(f, ",\n");
    fprintf(f, "  \"description\": "); fwrite_json_string(f, cfg->description); fprintf(f, ",\n");
    fprintf(f, "  \"homepage\": "); fwrite_json_string(f, cfg->homepage); fprintf(f, ",\n");
    fprintf(f, "  \"repository\": "); fwrite_json_string(f, cfg->repository); fprintf(f, ",\n");
    fprintf(f, "  \"include_patterns\": "); fwrite_json_array(f, include_installed, include_installed_count, 2); fprintf(f, ",\n");
    fprintf(f, "  \"lib_patterns\": "); fwrite_json_array(f, lib_installed, lib_installed_count, 2); fprintf(f, ",\n");
    fprintf(f, "  \"exclude_patterns\": "); fwrite_json_array(f, cfg->exclude_patterns, cfg->exclude_count, 2); fprintf(f, ",\n");
    fprintf(f, "  \"special_files\": "); fwrite_json_array(f, cfg->special_files, cfg->special_count, 2); fprintf(f, ",\n");
    fprintf(f, "  \"default_libs_dir\": "); fwrite_json_string(f, cfg->default_libs_dir); fprintf(f, ",\n");
    fprintf(f, "  \"default_include_dir\": "); fwrite_json_string(f, cfg->default_include_dir); fprintf(f, ",\n");
    fprintf(f, "  \"strict\": %s,\n", cfg->strict ? "true" : "false");
    fprintf(f, "  \"flatten\": %s,\n", cfg->flatten ? "true" : "false");
    fprintf(f, "  \"ignore_hidden\": %s,\n", cfg->ignore_hidden ? "true" : "false");
    fprintf(f, "  \"follow_symlinks\": %s\n", cfg->follow_symlinks ? "true" : "false");
    fprintf(f, "}\n");
                    fclose(f);

    if (include_installed) {
        for (int i = 0; i < include_installed_count; i++) free(include_installed[i]);
        free(include_installed);
    }
    if (lib_installed) {
        for (int i = 0; i < lib_installed_count; i++) free(lib_installed[i]);
        free(lib_installed);
    }
    return buf;

error:
    if (include_installed) {
        for (int i = 0; i < include_installed_count; i++) free(include_installed[i]);
        free(include_installed);
        }
    if (lib_installed) {
        for (int i = 0; i < lib_installed_count; i++) free(lib_installed[i]);
        free(lib_installed);
    }
    return NULL;
}

/* ---------- 基础工具函数 ---------- */
bool is_dir(const char* path) {
    struct stat st;
    return (stat(path, &st) == 0 && S_ISDIR(st.st_mode));
}

bool get_file_size(const char* path, uint64_t* size) {
    struct stat st;
    if (lstat(path, &st) != 0 || !S_ISREG(st.st_mode)) return false;
    *size = (uint64_t)st.st_size;
    return true;
}

static uint64_t dir_size_total = 0;
static int nftw_size_cb(const char* fpath, const struct stat* sb, int typeflag, struct FTW* ftwbuf) {
    (void)fpath; (void)ftwbuf;
    if (typeflag == FTW_F) dir_size_total += (uint64_t)sb->st_size;
    return 0;
}
bool get_directory_size(const char* path, uint64_t* total) {
    if (!is_dir(path)) return false;
    dir_size_total = 0;
    if (nftw(path, nftw_size_cb, 20, FTW_PHYS) == 0) {
        *total = dir_size_total;
        return true;
    }
    return false;
}

/* ---------- 压缩（libarchive） ---------- */
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
        if (new_data) { ctx->data = new_data; ctx->capacity = ctx->used; }
    }
    return ARCHIVE_OK;
}

static int add_directory_to_archive(struct archive* a, const char* path, const char* base) {
    DIR* dir = opendir(path);
    if (!dir) { fprintf(stderr, "Failed to open %s: %s\n", path, strerror(errno)); return -1; }
    struct dirent* entry;
    char fullpath[PATH_MAX], entry_name[PATH_MAX];
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        snprintf(fullpath, sizeof(fullpath), "%s/%s", path, entry->d_name);
        if (base) snprintf(entry_name, sizeof(entry_name), "%s/%s", base, entry->d_name);
        else { strncpy(entry_name, entry->d_name, sizeof(entry_name)-1); entry_name[sizeof(entry_name)-1] = '\0'; }
    struct stat st;
        if (lstat(fullpath, &st) != 0) { fprintf(stderr, "Cannot stat %s\n", fullpath); continue; }
        if (S_ISDIR(st.st_mode)) {
            struct archive_entry* ae = archive_entry_new();
            if (!ae) { closedir(dir); return -1; }
            archive_entry_set_pathname(ae, entry_name);
            archive_entry_set_mode(ae, S_IFDIR | 0755);
            archive_entry_set_size(ae, 0);
            if (archive_write_header(a, ae) != ARCHIVE_OK) {
                fprintf(stderr, "Error writing dir header: %s\n", archive_error_string(a));
                archive_entry_free(ae);
                closedir(dir);
                return -1;
            }
            archive_entry_free(ae);
            if (add_directory_to_archive(a, fullpath, entry_name) != 0) { closedir(dir); return -1; }
        } else if (S_ISREG(st.st_mode)) {
            struct archive_entry* ae = archive_entry_new();
            if (!ae) { closedir(dir); return -1; }
            archive_entry_set_pathname(ae, entry_name);
            archive_entry_set_mode(ae, st.st_mode);
            archive_entry_set_size(ae, st.st_size);
            archive_entry_set_mtime(ae, st.st_mtime, 0);
            if (archive_write_header(a, ae) != ARCHIVE_OK) {
                fprintf(stderr, "Error writing file header: %s\n", archive_error_string(a));
                archive_entry_free(ae);
                closedir(dir);
                return -1;
            }
            archive_entry_free(ae);
            FILE* f = fopen(fullpath, "rb");
            if (!f) { fprintf(stderr, "Cannot open %s\n", fullpath); closedir(dir); return -1; }
            char buffer[8192];
            size_t nread;
            while ((nread = fread(buffer, 1, sizeof(buffer), f)) > 0) {
                if (archive_write_data(a, buffer, nread) != (ssize_t)nread) {
                    fprintf(stderr, "Error writing data: %s\n", archive_error_string(a));
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

unsigned char* GzipToMemory(const char* filePath, size_t* outSize) {
    if (!filePath || !outSize) return NULL;
    *outSize = 0;
    struct stat st;
    if (stat(filePath, &st) != 0 || !S_ISREG(st.st_mode)) {
        fprintf(stderr, "Invalid file: %s\n", filePath);
        return NULL;
    }
    struct archive* a = archive_write_new();
    if (!a) { fprintf(stderr, "Failed to create archive writer\n"); return NULL; }
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

unsigned char* GzipToMemoryDir(const char* libsPath, const char* includePath, size_t* outSize) {
    if (!libsPath || !includePath || !outSize) return NULL;
    *outSize = 0;
    if (!is_dir(libsPath) || !is_dir(includePath)) {
        fprintf(stderr, "One of the directories is invalid\n");
        return NULL;
    }
    struct archive* a = archive_write_new();
    if (!a) { fprintf(stderr, "Failed to create archive writer\n"); return NULL; }
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

/* ---------- SHA256 ---------- */
int ComputeSha256(const unsigned char* data, size_t len, unsigned char* digest, unsigned int* digest_len) {
    int ret = -1;
    EVP_MD_CTX* ctx = NULL;
    if (data == NULL && len != 0) { fprintf(stderr, "ComputeSha256: invalid input\n"); return -1; }
    if (digest == NULL || digest_len == NULL) { fprintf(stderr, "ComputeSha256: null output\n"); return -1; }
    ctx = EVP_MD_CTX_new();
    if (!ctx) { fprintf(stderr, "EVP_MD_CTX_new failed\n"); goto cleanup; }
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) { fprintf(stderr, "EVP_DigestInit_ex failed\n"); goto cleanup; }
    if (EVP_DigestUpdate(ctx, data, len) != 1) { fprintf(stderr, "EVP_DigestUpdate failed\n"); goto cleanup; }
    if (EVP_DigestFinal_ex(ctx, digest, digest_len) != 1) { fprintf(stderr, "EVP_DigestFinal_ex failed\n"); goto cleanup; }
    ret = 0;
cleanup:
    if (ctx) EVP_MD_CTX_free(ctx);
    return ret;
}

/* ---------- 锁和初始化 ---------- */
void InitCpkg(void) {
    struct stat st;
    if (stat(WORK_DIR, &st) == 0) {
        if (!S_ISDIR(st.st_mode)) {
            fprintf(stderr, "Error: %s exists but is not a directory\n", WORK_DIR);
            exit(EXIT_FAILURE);
        }
        return;
    }
    if (mkdir(WORK_DIR, 0755) != 0) {
        fprintf(stderr, "Failed to create directory %s: %s\n", WORK_DIR, strerror(errno));
        exit(EXIT_FAILURE);
    }
}

void GetLock(void) {
    if (!is_dir(WORK_DIR)) InitCpkg();
    lock_fd = open(LOCKFILE_PATH, O_CREAT | O_RDWR, 0644);
    if (lock_fd == -1) {
        fprintf(stderr, "Failed to open/create lock file %s: %s\n", LOCKFILE_PATH, strerror(errno));
        exit(EXIT_FAILURE);
    }
    struct flock fl;
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;
    while (fcntl(lock_fd, F_SETLKW, &fl) == -1) {
        if (errno == EINTR) continue;
        fprintf(stderr, "Failed to acquire lock: %s\n", strerror(errno));
        close(lock_fd);
        lock_fd = -1;
        exit(EXIT_FAILURE);
    }
    if (ftruncate(lock_fd, 0) != 0) fprintf(stderr, "Warning: could not truncate lock file\n");
    else {
        char pid_buf[32];
        int len = snprintf(pid_buf, sizeof(pid_buf), "%d\n", getpid());
        if (len > 0 && write(lock_fd, pid_buf, len) != len)
            fprintf(stderr, "Warning: could not write PID to lock file\n");
    }
    fsync(lock_fd);
    printf("Lock acquired (PID: %d)\n", getpid());
}

void ReleaseLock(void) {
    if (lock_fd != -1) {
        struct flock fl;
        fl.l_type = F_UNLCK;
        fl.l_whence = SEEK_SET;
        fl.l_start = 0;
        fl.l_len = 0;
        if (fcntl(lock_fd, F_SETLK, &fl) == -1)
            fprintf(stderr, "Warning: failed to unlock %s: %s\n", LOCKFILE_PATH, strerror(errno));
        close(lock_fd);
        lock_fd = -1;
        printf("Lock released\n");
    }
}

/* ---------- 增量复制 ---------- */
static int copy_file_incremental(const char* src, const char* dst) {
    struct stat st_src, st_dst;
    if (stat(src, &st_src) != 0) { fprintf(stderr, "Cannot stat src: %s\n", src); return -1; }
    if (!S_ISREG(st_src.st_mode)) { fprintf(stderr, "Not a regular file: %s\n", src); return -1; }
    if (stat(dst, &st_dst) == 0 && st_dst.st_mtime >= st_src.st_mtime && st_dst.st_size == st_src.st_size)
        return 0;
    char* dir = strdup(dst);
    char* last_slash = strrchr(dir, '/');
    if (last_slash) { *last_slash = '\0'; mkdir(dir, 0755); }
    free(dir);
    FILE* fsrc = fopen(src, "rb");
    if (!fsrc) { perror("fopen src"); return -1; }
    FILE* fdst = fopen(dst, "wb");
    if (!fdst) { perror("fopen dst"); fclose(fsrc); return -1; }
    char buffer[8192];
    size_t n;
    while ((n = fread(buffer, 1, sizeof(buffer), fsrc)) > 0) {
        if (fwrite(buffer, 1, n, fdst) != n) { perror("fwrite"); fclose(fsrc); fclose(fdst); return -1; }
    }
    fclose(fsrc); fclose(fdst);
    chmod(dst, st_src.st_mode & 0777);
    return 0;
}
static int copy_dir_incremental(const char* src_dir, const char* dst_dir) {
    DIR* dir = opendir(src_dir);
    if (!dir) { perror("opendir src_dir"); return -1; }
    if (mkdir(dst_dir, 0755) != 0 && errno != EEXIST) { perror("mkdir dst_dir"); closedir(dir); return -1; }
    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        char src_path[PATH_MAX], dst_path[PATH_MAX];
        snprintf(src_path, sizeof(src_path), "%s/%s", src_dir, entry->d_name);
        snprintf(dst_path, sizeof(dst_path), "%s/%s", dst_dir, entry->d_name);
        struct stat st;
        if (lstat(src_path, &st) != 0) { fprintf(stderr, "Cannot stat %s\n", src_path); continue; }
        if (S_ISDIR(st.st_mode)) copy_dir_incremental(src_path, dst_path);
        else if (S_ISREG(st.st_mode)) copy_file_incremental(src_path, dst_path);
    }
    closedir(dir);
    return 0;
}
int copy_path_incremental(const char* src, const char* dst_base) {
    struct stat st;
    if (stat(src, &st) != 0) { fprintf(stderr, "Cannot stat %s\n", src); return -1; }
    const char* base = strrchr(src, '/');
    base = base ? base + 1 : src;
    char dst_path[PATH_MAX];
    snprintf(dst_path, sizeof(dst_path), "%s/%s", dst_base, base);
    if (S_ISDIR(st.st_mode)) return copy_dir_incremental(src, dst_path);
    else if (S_ISREG(st.st_mode)) return copy_file_incremental(src, dst_path);
    else { fprintf(stderr, "Unsupported file type: %s\n", src); return -1; }
}

/* ---------- 魔术字 ---------- */
int VerifyMagic(FILE* stream) {
    unsigned char magic[MAGIC_LEN];
    if (fread(magic, 1, MAGIC_LEN, stream) != MAGIC_LEN || memcmp(magic, MAGIC, MAGIC_LEN) != 0) {
        fclose(stream);
        return InvalidMagicError;
    }
    return Successful;
}

/* ---------- 解压 ---------- */
unsigned char* DecompressGzipToMemory(const unsigned char* compressed_data,
                                      size_t compressed_len,
                                      size_t* out_len) {
    if (!compressed_data || compressed_len == 0 || !out_len) return NULL;
    *out_len = 0;

    struct archive* a = archive_read_new();
    if (!a) return NULL;

    archive_read_support_filter_gzip(a);
    // 同时支持 tar 和 raw（raw 用于纯 gzip 流，tar 用于 tar.gz）
    archive_read_support_format_tar(a);
    archive_read_support_format_raw(a);

    if (archive_read_open_memory(a, compressed_data, compressed_len) != ARCHIVE_OK) {
        archive_read_free(a);
        return NULL;
    }

    struct archive_entry* entry;
    int r = archive_read_next_header(a, &entry);
    if (r != ARCHIVE_OK) {
        archive_read_close(a);
        archive_read_free(a);
        return NULL;
    }

    unsigned char* out_buf = NULL;
    size_t total_len = 0, cap = 0;
    const void* buff;
    size_t size;
    int64_t offset;

    while ((r = archive_read_data_block(a, &buff, &size, &offset)) == ARCHIVE_OK) {
        if (total_len + size > cap) {
            size_t new_cap = total_len + size + 4096;
            unsigned char* new_buf = realloc(out_buf, new_cap);
            if (!new_buf) {
                free(out_buf);
                archive_read_close(a);
                archive_read_free(a);
                return NULL;
            }
            out_buf = new_buf;
            cap = new_cap;
        }
        memcpy(out_buf + total_len, buff, size);
        total_len += size;
    }

    if (r != ARCHIVE_EOF) {
        free(out_buf);
        archive_read_close(a);
        archive_read_free(a);
        return NULL;
    }

    archive_read_close(a);
    archive_read_free(a);

    if (total_len > 0) {
        unsigned char* new_buf = realloc(out_buf, total_len);
        if (new_buf) out_buf = new_buf;
    } else {
        free(out_buf);
        out_buf = NULL;
    }
    *out_len = total_len;
    return out_buf;
}

int DecompressPocketToDir(const unsigned char* pocket_gzip,
                          size_t pocket_len,
                          const char* dest_dir) {
    if (!pocket_gzip || pocket_len == 0 || !dest_dir) return -1;
    if (mkdir(dest_dir, 0755) != 0 && errno != EEXIST) {
        perror("mkdir dest_dir");
        return -1;
    }
    struct archive* a = archive_read_new();
    if (!a) return -1;
    archive_read_support_filter_gzip(a);
    archive_read_support_format_tar(a);
    if (archive_read_open_memory(a, pocket_gzip, pocket_len) != ARCHIVE_OK) {
        archive_read_free(a);
        return -1;
    }
    struct archive_entry* entry;
    int r;
    while ((r = archive_read_next_header(a, &entry)) == ARCHIVE_OK) {
        const char* pathname = archive_entry_pathname(entry);
        if (!pathname) continue;
        char dest_path[PATH_MAX];
        snprintf(dest_path, sizeof(dest_path), "%s/%s", dest_dir, pathname);

        if (archive_entry_filetype(entry) == AE_IFDIR) {
            if (mkdir(dest_path, 0755) != 0 && errno != EEXIST) {
                fprintf(stderr, "Failed to create dir %s: %s\n", dest_path, strerror(errno));
                archive_read_close(a);
                archive_read_free(a);
                return -1;
            }
            continue;
        }
        if (archive_entry_filetype(entry) == AE_IFREG) {
            char* dir = strdup(dest_path);
            char* last_slash = strrchr(dir, '/');
            if (last_slash) { *last_slash = '\0'; mkdir(dir, 0755); }
            free(dir);
            FILE* f = fopen(dest_path, "wb");
            if (!f) {
                fprintf(stderr, "Failed to open %s: %s\n", dest_path, strerror(errno));
                archive_read_close(a);
                archive_read_free(a);
                return -1;
            }
            const void* buff;
            size_t size;
            int64_t offset;
            while ((r = archive_read_data_block(a, &buff, &size, &offset)) == ARCHIVE_OK) {
                if (fwrite(buff, 1, size, f) != size) {
                    fprintf(stderr, "Write error to %s\n", dest_path);
                    fclose(f);
                    archive_read_close(a);
                    archive_read_free(a);
                    return -1;
                }
            }
            fclose(f);
            if (r != ARCHIVE_EOF) {
                fprintf(stderr, "Error reading data for %s\n", dest_path);
                archive_read_close(a);
                archive_read_free(a);
                return -1;
            }
            mode_t mode = archive_entry_mode(entry) & 0777;
            chmod(dest_path, mode);
        }
    }
    if (r != ARCHIVE_EOF) {
        fprintf(stderr, "Error reading archive header\n");
        archive_read_close(a);
        archive_read_free(a);
        return -1;
    }
    archive_read_close(a);
    archive_read_free(a);
    return 0;
}

/* ---------- JSON 解析 ---------- */
Config* ParseConfigFromJson(const char* json_str) {
    if (!json_str) return NULL;
    cJSON* root = cJSON_Parse(json_str);
    if (!root) {
        fprintf(stderr, "Failed to parse JSON: %s\n", cJSON_GetErrorPtr());
        return NULL;
    }
    Config* cfg = calloc(1, sizeof(Config));
    if (!cfg) { cJSON_Delete(root); return NULL; }
    cJSON* item = NULL;
    #define GET_STRING(field, json_key) \
        item = cJSON_GetObjectItem(root, json_key); \
        if (cJSON_IsString(item)) safe_strcpy(cfg->field, item->valuestring, sizeof(cfg->field));
    GET_STRING(PocketName, "PocketName");
    GET_STRING(version, "version");
    GET_STRING(license, "license");
    GET_STRING(description, "description");
    GET_STRING(homepage, "homepage");
    GET_STRING(repository, "repository");
    GET_STRING(default_libs_dir, "default_libs_dir");
    GET_STRING(default_include_dir, "default_include_dir");
    item = cJSON_GetObjectItem(root, "strict");
    if (cJSON_IsBool(item)) cfg->strict = item->valueint != 0;
    item = cJSON_GetObjectItem(root, "flatten");
    if (cJSON_IsBool(item)) cfg->flatten = item->valueint != 0;
    item = cJSON_GetObjectItem(root, "ignore_hidden");
    if (cJSON_IsBool(item)) cfg->ignore_hidden = item->valueint != 0;
    item = cJSON_GetObjectItem(root, "follow_symlinks");
    if (cJSON_IsBool(item)) cfg->follow_symlinks = item->valueint != 0;
    #define PARSE_ARRAY(dest_count, dest_array, json_key) \
        item = cJSON_GetObjectItem(root, json_key); \
        if (cJSON_IsArray(item)) { \
            int count = cJSON_GetArraySize(item); \
            if (count > 0) { \
                cfg->dest_array = malloc(sizeof(char*) * count); \
                if (!cfg->dest_array) goto error; \
                for (int i = 0; i < count; i++) { \
                    cJSON* elem = cJSON_GetArrayItem(item, i); \
                    if (cJSON_IsString(elem)) { \
                        cfg->dest_array[i] = strdup(elem->valuestring); \
                        if (!cfg->dest_array[i]) { \
                            for (int j = 0; j < i; j++) free(cfg->dest_array[j]); \
                            free(cfg->dest_array); \
                            cfg->dest_array = NULL; \
                            goto error; \
                        } \
                    } else { cfg->dest_array[i] = strdup(""); } \
                } \
                cfg->dest_count = count; \
            } \
        }
    PARSE_ARRAY(author_count, authors, "authors");
    PARSE_ARRAY(include_count, include_patterns, "include_patterns");
    PARSE_ARRAY(lib_count, lib_patterns, "lib_patterns");
    PARSE_ARRAY(exclude_count, exclude_patterns, "exclude_patterns");
    PARSE_ARRAY(special_count, special_files, "special_files");
    cJSON_Delete(root);
    return cfg;
error:
    cJSON_Delete(root);
    FreeConfig(cfg);
    return NULL;
}

bool VerifyHash(const unsigned char* expected_hash, const unsigned char* data, size_t data_len) {
    unsigned char computed_hash[32];
    unsigned int hash_len = 0;
    if (ComputeSha256(data, data_len, computed_hash, &hash_len) != 0 || hash_len != 32) return false;
    return memcmp(expected_hash, computed_hash, 32) == 0;
}

/* ---------- 安装辅助函数 ---------- */
int copy_file_simple(const char *src, const char *dst) {
    FILE *fsrc = fopen(src, "rb");
    if (!fsrc) return -1;
    FILE *fdst = fopen(dst, "wb");
    if (!fdst) { fclose(fsrc); return -1; }
    char buf[CHUNK_SIZE];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), fsrc)) > 0) {
        if (fwrite(buf, 1, n, fdst) != n) { fclose(fsrc); fclose(fdst); return -1; }
    }
    fclose(fsrc); fclose(fdst);
    struct stat st;
    if (stat(src, &st) == 0) chmod(dst, st.st_mode & 0777);
    return 0;
}

int remove_directory(const char *path) {
    DIR *dir = opendir(path);
    if (!dir) return -1;
    struct dirent *entry;
    char fullpath[PATH_MAX];
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        snprintf(fullpath, sizeof(fullpath), "%s/%s", path, entry->d_name);
        struct stat st;
        if (lstat(fullpath, &st) == 0) {
            if (S_ISDIR(st.st_mode)) remove_directory(fullpath);
            else unlink(fullpath);
        }
    }
    closedir(dir);
    return rmdir(path);
}

void install_list_init(InstallList *list) {
    if (!list) return;
    list->paths = NULL;
    list->count = 0;
    list->capacity = 0;
}
int install_list_add(InstallList *list, const char *path) {
    if (!list || !path) return -1;
    if (list->count >= list->capacity) {
        int new_cap = list->capacity ? list->capacity * 2 : 16;
        char **new_paths = realloc(list->paths, sizeof(char*) * new_cap);
        if (!new_paths) return -1;
        list->paths = new_paths;
        list->capacity = new_cap;
    }
    list->paths[list->count] = strdup(path);
    if (!list->paths[list->count]) return -1;
    list->count++;
    return 0;
}
void install_list_free(InstallList *list) {
    if (!list) return;
    for (int i = 0; i < list->count; i++) free(list->paths[i]);
    free(list->paths);
    list->paths = NULL;
    list->count = 0;
    list->capacity = 0;
}

static int nftw_install_cb(const char *fpath, const struct stat *sb,
                           int typeflag, struct FTW *ftwbuf) {
    (void)sb;
    if (typeflag == FTW_F) {
        const char *rel_path = fpath + ftwbuf->base;
        if (*rel_path == '/') rel_path++;
        for (int i = 0; i < g_dst_count; i++) {
            if (!g_dst_bases[i]) continue;
            char dst_path[PATH_MAX];
            snprintf(dst_path, sizeof(dst_path), "%s/%s", g_dst_bases[i], rel_path);
            char *dir = strdup(dst_path);
            char *dirpart = dirname(dir);
            mkdir(dirpart, 0755);
            free(dir);
            if (copy_file_simple(fpath, dst_path) != 0) {
                fprintf(stderr, "Failed to copy %s to %s\n", fpath, dst_path);
                return -1;
            }
            if (install_list_add(g_install_list, dst_path) != 0) {
                fprintf(stderr, "Failed to record installation path\n");
                return -1;
            }
        }
    } else if (typeflag == FTW_D) {
        const char *rel_path = fpath + ftwbuf->base;
        if (*rel_path == '/') rel_path++;
        for (int i = 0; i < g_dst_count; i++) {
            if (!g_dst_bases[i]) continue;
            char dst_path[PATH_MAX];
            snprintf(dst_path, sizeof(dst_path), "%s/%s", g_dst_bases[i], rel_path);
            mkdir(dst_path, 0755);
        }
    }
    return 0;
}

int install_dir_to_multi(const char *src_dir, const char **dst_bases,
                         int dst_count, InstallList *list) {
    if (!src_dir || !dst_bases || dst_count <= 0 || !list) return -1;
    g_dst_bases = dst_bases;
    g_dst_count = dst_count;
    g_install_list = list;
    if (nftw(src_dir, nftw_install_cb, 20, FTW_PHYS) != 0) {
        fprintf(stderr, "nftw traversal failed for %s\n", src_dir);
        return -1;
    }
    return 0;
}
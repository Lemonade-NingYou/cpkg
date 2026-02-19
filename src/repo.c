#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "../include/repo.h"
#include "../include/network.h"
#include "../include/cpkg.h"
#include "../include/help.h"
#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/sha.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>

/* 简单的索引格式（每行一条记录）:
 * name|version|url|sha256
 */

static const char *default_index_url = "https://example.com/cpkg/index.txt";

/* 从索引数据中查找第一个匹配 name 的记录，返回动态分配的 url（需要 free）和 hash（需要 free） */
static int find_from_index(const char *index_data, const char *name, char **out_url, char **out_hash)
{
    if (!index_data || !name) return 1;
    char *data = strdup(index_data);
    if (!data) return 2;
    char *line = NULL;
    char *saveptr = NULL;
    line = strtok_r(data, "\n", &saveptr);
    while (line) {
        char *p = strdup(line);
        if (!p) { free(data); return 2; }
        char *tok = NULL;
        char *save = NULL;
        tok = strtok_r(p, "|", &save); // name
        if (tok && strcmp(tok, name) == 0) {
            // match
            (void)strtok_r(NULL, "|", &save); /* skip version field */
            char *url = strtok_r(NULL, "|", &save);
            char *hash = strtok_r(NULL, "|", &save);
            if (url) *out_url = strdup(url);
            if (hash) *out_hash = strdup(hash);
            free(p);
            free(data);
            return 0;
        }
        free(p);
        line = strtok_r(NULL, "\n", &saveptr);
    }
    free(data);
    return 3; // not found
}

int repo_search(const char *query)
{
    char *index = NULL;
    size_t len = 0;
    const char *url = getenv("CPKG_INDEX_URL");
    if (!url) url = default_index_url;
    if (repo_download_to_memory(url, &index, &len) != 0) {
        cpk_printf(ERROR, "Failed to download index from %s\n", url);
        return 1;
    }
    // 简单字符串匹配，打印包含 query 的行
    char *line = NULL;
    char *saveptr = NULL;
    line = strtok_r(index, "\n", &saveptr);
    while (line) {
        if (strstr(line, query)) {
            // 输出解析后的字段
            char *copy = strdup(line);
            char *tok = NULL;
            char *s = NULL;
            tok = strtok_r(copy, "|", &s); // name
            char *name = tok ? tok : "";
            tok = strtok_r(NULL, "|", &s); // version
            char *ver = tok ? tok : "";
            tok = strtok_r(NULL, "|", &s); // url
            char *pkgurl = tok ? tok : "";
            printf("%s\t%s\t%s\n", name, ver, pkgurl);
            free(copy);
        }
        line = strtok_r(NULL, "\n", &saveptr);
    }
    free(index);
    return 0;
}

int repo_fetch_package_by_name(const char *name, const char *dest_path)
{
    if (!name || !dest_path) return 1;
    char *index = NULL;
    size_t len = 0;
    const char *url = getenv("CPKG_INDEX_URL");
    if (!url) url = default_index_url;
    if (repo_download_to_memory(url, &index, &len) != 0) {
        cpk_printf(ERROR, "Failed to download index from %s\n", url);
        return 2;
    }
    char *pkg_url = NULL;
    char *pkg_hash = NULL;
    int r = find_from_index(index, name, &pkg_url, &pkg_hash);
    free(index);
    if (r != 0) {
        cpk_printf(ERROR, "Package not found in index: %s\n", name);
        return 3;
    }
    cpk_printf(DEBUG, "Index returned url='%s' hash='%s' (len=%zu)\n", pkg_url ? pkg_url : "", pkg_hash ? pkg_hash : "", pkg_hash ? strlen(pkg_hash) : 0);
    cpk_printf(INFO, "Downloading %s from %s\n", name, pkg_url);
    int dl = repo_download_to_file(pkg_url, dest_path);
    if (dl != 0) {
        cpk_printf(ERROR, "Download failed (code %d)\n", dl);
        free(pkg_url);
        free(pkg_hash);
        return 4;
    }
    /* 验证文件哈希（如果索引中提供了哈希） */
    if (pkg_hash) {
        /* 修剪前后空白（包括换行） */
        char *start = pkg_hash;
        while (*start && isspace((unsigned char)*start)) start++;
        char *end = pkg_hash + strlen(pkg_hash) - 1;
        while (end > start && isspace((unsigned char)*end)) { *end = '\0'; end--; }
        size_t phlen = strlen(start);
        if (phlen >= 64) {
            /* 使用前 64 字符作为期望哈希 */
            char expected[65];
            memcpy(expected, start, 64);
            expected[64] = '\0';
            /* 计算文件哈希 */
            FILE *fp = fopen(dest_path, "rb");
            if (!fp) {
                cpk_printf(ERROR, "Failed to open downloaded file for hashing: %s\n", dest_path);
                free(pkg_url);
                free(pkg_hash);
                return 5;
            }
            SHA256_CTX ctx;
            unsigned char buf[FILE_BUFFER_SIZE];
            unsigned char hashbin[SHA256_DIGEST_LENGTH];
            if (!SHA256_Init(&ctx)) {
                fclose(fp);
                free(pkg_url);
                free(pkg_hash);
                return 6;
            }
            size_t n = 0;
            while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
                SHA256_Update(&ctx, buf, n);
            }
            SHA256_Final(hashbin, &ctx);
            fclose(fp);

            char actual_hash[SHA256_DIGEST_LENGTH * 2 + 1];
            for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
                sprintf(actual_hash + i * 2, "%02x", hashbin[i]);
            actual_hash[SHA256_DIGEST_LENGTH * 2] = '\0';

            if (strcmp(actual_hash, expected) != 0) {
                cpk_printf(ERROR, "Hash mismatch: expected %s, got %s\n", expected, actual_hash);
                /* 删除损坏的下载文件 */
                unlink(dest_path);
                free(pkg_url);
                free(pkg_hash);
                return 7;
            }
            cpk_printf(SUCCESS, "Hash verification passed for %s\n", name);
        }
    }

    free(pkg_url);
    free(pkg_hash);
    return 0;
}

int repo_install_by_name(const char *name)
{
    if (!name) return 1;
    char tmpfile[] = "/tmp/cpkg_download_XXXXXX.cpk";
    int fd = mkstemps(tmpfile, 4); // 保留 .cpk 后缀
    if (fd == -1) {
        cpk_printf(ERROR, "Failed to create temp file: %s\n", strerror(errno));
        return 2;
    }
    close(fd);
    int r = repo_fetch_package_by_name(name, tmpfile);
    if (r != 0) {
        unlink(tmpfile);
        return 3;
    }
    // 调用已有安装逻辑
    r = install_package(tmpfile);
    unlink(tmpfile);
    return r;
}

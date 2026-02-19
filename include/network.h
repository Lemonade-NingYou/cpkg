/* network.h - minimal network utilities for cpkg
 * 使用 libcurl 实现简单的下载功能
 */
#ifndef NETWORK_H
#define NETWORK_H

#include <stddef.h>

/* 下载 URL 到内存，调用方负责 free(*out_data) */
int repo_download_to_memory(const char *url, char **out_data, size_t *out_len);

/* 下载 URL 到本地文件，覆盖已存在文件 */
int repo_download_to_file(const char *url, const char *dest_path);

#endif /* NETWORK_H */

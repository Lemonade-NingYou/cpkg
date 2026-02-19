#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include "../include/network.h"

struct mem_buffer {
    char *data;
    size_t size;
};

static size_t write_to_mem(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    size_t realsize = size * nmemb;
    struct mem_buffer *mem = (struct mem_buffer *)userdata;
    char *tmp = realloc(mem->data, mem->size + realsize + 1);
    if (!tmp) return 0;
    mem->data = tmp;
    memcpy(&(mem->data[mem->size]), ptr, realsize);
    mem->size += realsize;
    mem->data[mem->size] = '\0';
    return realsize;
}

static size_t write_to_file(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    FILE *fp = (FILE *)userdata;
    return fwrite(ptr, size, nmemb, fp);
}

int repo_download_to_memory(const char *url, char **out_data, size_t *out_len)
{
    if (!url || !out_data || !out_len) return 1;
    CURL *curl = NULL;
    CURLcode res;
    struct mem_buffer mem = {0};

    curl = curl_easy_init();
    if (!curl) return 2;

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_to_mem);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&mem);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "cpkg/0.1");

    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        if (mem.data) free(mem.data);
        return 3;
    }

    *out_data = mem.data;
    *out_len = mem.size;
    return 0;
}

int repo_download_to_file(const char *url, const char *dest_path)
{
    if (!url || !dest_path) return 1;
    CURL *curl = NULL;
    CURLcode res;
    FILE *fp = NULL;

    fp = fopen(dest_path, "wb");
    if (!fp) return 2;

    curl = curl_easy_init();
    if (!curl) { fclose(fp); return 3; }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_to_file);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "cpkg/0.1");

    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    fclose(fp);

    if (res != CURLE_OK) {
        return 4;
    }
    return 0;
}

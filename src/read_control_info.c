#define _GNU_SOURCE   // 启用 GNU 扩展，包括 glob_t

#include <ctype.h>
#include <glob.h>
#include "../include/cpkg.h"

/**
 * @brief 解析花括号内的列表字符串（逗号分隔），每个项必须用双引号括起来
 * @param list_str 花括号内的内容（已去除首尾空白）
 * @param count 输出参数：列表项个数
 * @param err 输出参数：解析是否出错（非0表示出错）
 * @return 成功返回动态分配的字符串数组，失败返回NULL
 */
static char **parse_list(const char *list_str, int *count, int *err)
{
    char *list_buf, *token;
    char **items = NULL;
    int cnt = 0;
    size_t len;

    *err = 0;
    len = strlen(list_str);
    list_buf = (char *)malloc(len + 1);
    if (list_buf == NULL)
    {
        *err = 1;
        return NULL;
    }
    strcpy(list_buf, list_str);

    token = strtok(list_buf, ",");
    while (token != NULL)
    {
        char *item = token;
        // 去除项的首尾空白
        while (isspace((unsigned char)*item))
            item++;
        if (*item == '\0')
        {
            token = strtok(NULL, ",");
            continue;
        }
        char *end = item + strlen(item) - 1;
        while (end > item && isspace((unsigned char)*end))
        {
            *end = '\0';
            end--;
        }

        // 【修复】去除尾部空白后再次检查是否为空
        if (*item == '\0')
        {
            token = strtok(NULL, ",");
            continue;
        }

        // 检查是否用双引号括起来
        if (item[0] != '"' || item[strlen(item)-1] != '"')
        {
            *err = 1;
            goto error;
        }
        // 去除引号
        item[strlen(item)-1] = '\0';
        item++;

        if (*item == '\0')
        {
            token = strtok(NULL, ",");
            continue;
        }

        cnt++;
        items = (char **)realloc(items, cnt * sizeof(char *));
        if (items == NULL)
        {
            *err = 1;
            goto error;
        }
        items[cnt-1] = strdup(item);
        if (items[cnt-1] == NULL)
        {
            *err = 1;
            goto error;
        }

        token = strtok(NULL, ",");
    }

    free(list_buf);
    *count = cnt;
    return items;

error:
    for (int i = 0; i < cnt; i++)
        free(items[i]);
    free(items);
    free(list_buf);
    return NULL;
}

/**
 * @brief 对包含通配符的模式进行 glob 展开
 * @param pattern 模式字符串（已去除引号）
 * @param count 输出参数：匹配的文件个数
 * @param err 输出参数：解析是否出错（非0表示出错）
 * @return 成功返回动态分配的字符串数组，失败返回NULL
 */
static char **expand_wildcard(const char *pattern, int *count, int *err)
{
    glob_t globbuf;
    char **files = NULL;
    int ret;

    *err = 0;
    ret = glob(pattern, GLOB_TILDE, NULL, &globbuf);
    if (ret != 0 && ret != GLOB_NOMATCH)
    {
        *err = 1;
        return NULL;
    }
    if (ret == GLOB_NOMATCH || globbuf.gl_pathc == 0)
    {
        globfree(&globbuf);
        *count = 0;
        return NULL;
    }

    *count = globbuf.gl_pathc;
    files = (char **)malloc(*count * sizeof(char *));
    if (files == NULL)
    {
        *err = 1;
        globfree(&globbuf);
        return NULL;
    }

    for (int i = 0; i < *count; i++)
    {
        files[i] = strdup(globbuf.gl_pathv[i]);
        if (files[i] == NULL)
        {
            for (int j = 0; j < i; j++)
                free(files[j]);
            free(files);
            *err = 1;
            globfree(&globbuf);
            return NULL;
        }
    }

    globfree(&globbuf);
    return files;
}

/**
 * @brief 读取控制信息
 * @note 读取控制信息文件，并解析其中的键值对，填充 Control_Info 结构体
 *       支持行内注释（# 后的内容忽略），支持键值对中的列表（花括号包围），
 *       支持 include 和 lib 字段中的通配符展开（使用 glob）
 * @param fp 控制信息文件指针
 * @return 成功时返回 Control_Info 结构体指针，失败时返回 NULL
 */
Control_Info *read_control_info(FILE *fp)
{
    Control_Info *info;
    char line[4096];

    info = (Control_Info *)malloc(sizeof(Control_Info));
    if (info == NULL)
        return NULL;
    memset(info, 0, sizeof(Control_Info));

    while (fgets(line, sizeof(line), fp) != NULL)
    {
        char *p, *colon, *key, *value, *comment;
        size_t len;

        // 去除行尾换行符
        len = strlen(line);
        if (len > 0 && line[len-1] == '\n')
            line[len-1] = '\0';

        // 去除行内注释（第一个 '#' 之后的内容）
        comment = strchr(line, '#');
        if (comment != NULL)
            *comment = '\0';

        // 跳过空行
        p = line;
        while (isspace((unsigned char)*p))
            p++;
        if (*p == '\0')
            continue;

        // 查找第一个冒号
        colon = strchr(line, ':');
        if (colon == NULL)
            continue;

        // 分割键和值
        *colon = '\0';
        key = line;
        value = colon + 1;

        // 去除键的首尾空白
        while (isspace((unsigned char)*key))
            key++;
        p = key + strlen(key) - 1;
        while (p > key && isspace((unsigned char)*p))
        {
            *p = '\0';
            p--;
        }

        // 去除值的前导空白
        while (isspace((unsigned char)*value))
            value++;
        // 去除值的尾部空白
        char *end_val = value + strlen(value) - 1;
        while (end_val >= value && isspace((unsigned char)*end_val))
            *end_val-- = '\0';

        // 处理值：可能是列表（以 '{' 开头）或简单字符串
        if (value[0] == '{')
        {
            // 列表格式：{ item1, item2, ... }
            char *brace_end, *list_start, *list_end_trim;
            char **items = NULL;
            int count = 0;
            int err = 0;

            brace_end = strchr(value, '}');
            if (brace_end == NULL)
                continue;   // 缺少右花括号，忽略此行

            // 提取花括号内的内容，去除首尾空白
            list_start = value + 1;
            while (isspace((unsigned char)*list_start) && list_start < brace_end)
                list_start++;
            list_end_trim = brace_end - 1;
            while (list_end_trim >= list_start && isspace((unsigned char)*list_end_trim))
                list_end_trim--;

            if (list_start > list_end_trim)
            {
                // 空列表，清空对应字段
                if (strcmp(key, "include") == 0)
                {
                    if (info->include_files != NULL)
                    {
                        for (int i = 0; i < info->include_file_count; i++)
                            free(info->include_files[i]);
                        free(info->include_files);
                        info->include_files = NULL;
                        info->include_file_count = 0;
                    }
                }
                else if (strcmp(key, "lib") == 0)
                {
                    if (info->lib_files != NULL)
                    {
                        for (int i = 0; i < info->lib_file_count; i++)
                            free(info->lib_files[i]);
                        free(info->lib_files);
                        info->lib_files = NULL;
                        info->lib_file_count = 0;
                    }
                }
                continue;
            }

            // 解析列表内容
            len = list_end_trim - list_start + 1;
            char *list_buf = (char *)malloc(len + 1);
            if (list_buf == NULL)
                goto error;
            strncpy(list_buf, list_start, len);
            list_buf[len] = '\0';

            items = parse_list(list_buf, &count, &err);
            free(list_buf);
            if (err)
                goto error;

            // 根据键名赋值
            if (strcmp(key, "include") == 0)
            {
                if (info->include_files != NULL)
                {
                    for (int i = 0; i < info->include_file_count; i++)
                        free(info->include_files[i]);
                    free(info->include_files);
                }
                info->include_files = items;
                info->include_file_count = count;
            }
            else if (strcmp(key, "lib") == 0)
            {
                if (info->lib_files != NULL)
                {
                    for (int i = 0; i < info->lib_file_count; i++)
                        free(info->lib_files[i]);
                    free(info->lib_files);
                }
                info->lib_files = items;
                info->lib_file_count = count;
            }
            else
            {
                // 未知键，释放列表
                for (int i = 0; i < count; i++)
                    free(items[i]);
                free(items);
            }
        }
        else
        {
            // 简单字符串值
            // 对于路径相关字段，检查是否用双引号括起来
            int need_quote = (strcmp(key, "include") == 0 || strcmp(key, "lib") == 0 ||
                              strcmp(key, "include_path") == 0 || strcmp(key, "lib_path") == 0);

            if (need_quote)
            {
                // 检查引号（此时 value 已去除尾部空白，确保最后一个字符正确）
                if (value[0] != '"' || value[strlen(value)-1] != '"')
                    goto error;
                // 去除引号
                value[strlen(value)-1] = '\0';
                value++;
            }
            else
            {
                // 其他字段可选引号，如果有则去除
                if (value[0] == '"' && value[strlen(value)-1] == '"')
                {
                    value[strlen(value)-1] = '\0';
                    value++;
                }
            }

            // 根据键名填充对应的字段
            if (strcmp(key, "packet") == 0)
            {
                strncpy(info->name, value, MAX_PATH_LEN - 1);
                info->name[MAX_PATH_LEN - 1] = '\0';
            }
            else if (strcmp(key, "version") == 0)
            {
                strncpy(info->version, value, MAX_PATH_LEN - 1);
                info->version[MAX_PATH_LEN - 1] = '\0';
            }
            else if (strcmp(key, "description") == 0)
            {
                strncpy(info->description, value, MAX_PATH_LEN - 1);
                info->description[MAX_PATH_LEN - 1] = '\0';
            }
            else if (strcmp(key, "author") == 0)
            {
                strncpy(info->author, value, MAX_PATH_LEN - 1);
                info->author[MAX_PATH_LEN - 1] = '\0';
            }
            else if (strcmp(key, "homepage") == 0)
            {
                strncpy(info->homepage, value, MAX_PATH_LEN - 1);
                info->homepage[MAX_PATH_LEN - 1] = '\0';
            }
            else if (strcmp(key, "license") == 0)
            {
                strncpy(info->license, value, MAX_PATH_LEN - 1);
                info->license[MAX_PATH_LEN - 1] = '\0';
            }
            else if (strcmp(key, "include_path") == 0)
            {
                strncpy(info->include_install_path, value, MAX_PATH_LEN - 1);
                info->include_install_path[MAX_PATH_LEN - 1] = '\0';
            }
            else if (strcmp(key, "lib_path") == 0)
            {
                strncpy(info->lib_install_path, value, MAX_PATH_LEN - 1);
                info->lib_install_path[MAX_PATH_LEN - 1] = '\0';
            }
            else if (strcmp(key, "include") == 0 || strcmp(key, "lib") == 0)
            {
                char **files = NULL;
                int count = 0;
                int err = 0;

                // 检查是否包含通配符
                if (strpbrk(value, "*?[") != NULL)
                {
                    files = expand_wildcard(value, &count, &err);
                    if (err)
                        goto error;
                }
                else
                {
                    // 无通配符，作为单个文件
                    count = 1;
                    files = (char **)malloc(count * sizeof(char *));
                    if (files == NULL)
                        goto error;
                    files[0] = strdup(value);
                    if (files[0] == NULL)
                    {
                        free(files);
                        goto error;
                    }
                }

                // 赋值
                if (strcmp(key, "include") == 0)
                {
                    if (info->include_files != NULL)
                    {
                        for (int i = 0; i < info->include_file_count; i++)
                            free(info->include_files[i]);
                        free(info->include_files);
                    }
                    info->include_files = files;
                    info->include_file_count = count;
                }
                else // lib
                {
                    if (info->lib_files != NULL)
                    {
                        for (int i = 0; i < info->lib_file_count; i++)
                            free(info->lib_files[i]);
                        free(info->lib_files);
                    }
                    info->lib_files = files;
                    info->lib_file_count = count;
                }
            }
            // 其他未知键忽略
        }
    }

    return info;

error:
    // 发生错误时，释放已分配的所有资源
    if (info->include_files != NULL)
    {
        for (int i = 0; i < info->include_file_count; i++)
            free(info->include_files[i]);
        free(info->include_files);
    }
    if (info->lib_files != NULL)
    {
        for (int i = 0; i < info->lib_file_count; i++)
            free(info->lib_files[i]);
        free(info->lib_files);
    }
    free(info);
    return NULL;
}
/*
 * Copyright (C) 2026 Lemonade-NingYou
 *
 * This file is part of cpkg.
 *
 * cpkg is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * cpkg is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with cpkg. If not, see <https://www.gnu.org/licenses/>.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <limits.h>

#include "openapi.h"
#include "outerror.h"
#include "utils.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static void highlight_c_line(const char* line) {
        const char* p = line;
        int in_string = 0;
        int in_char = 0;
        int in_angle = 0;
        int is_include_line = 0;

        const char* tmp = line;
        while (*tmp == ' ' || *tmp == '\t') tmp++;
        if (*tmp == '#' && strncmp(tmp, "#include", 8) == 0) {
            is_include_line = 1;
        }

        #define VS_COMMENT  "\033[38;5;71m"
        #define VS_PREPROC  "\033[38;5;176m"
        #define VS_TYPE     "\033[38;5;74m"
        #define VS_STMT     "\033[38;5;176m"
        #define VS_STRING   "\033[38;5;173m"
        #define VS_NUMBER   "\033[38;5;151m"
        #define VS_FUNC     "\033[38;5;187m"
        #define VS_VAR      "\033[38;5;117m"
        #define VS_RESET    "\033[0m"

    const char* stmt_kw[] = {
        "if", "else", "for", "while", "do", "switch", "case", "default",
        "break", "continue", "return", "goto", NULL};

    const char* type_kw[] = {
        "int", "char", "void", "float", "double", "long", "short",
        "signed", "unsigned", "struct", "union", "enum", "typedef",
        "const", "static", "extern", "register", "volatile", "inline",
        "sizeof", "_Bool", "_Complex", "_Imaginary", "restrict",
        "_Alignas", "_Alignof", "_Atomic", "_Thread_local", "_Noreturn",
        "_Static_assert", "_Generic", "auto", NULL};

    const char* preproc_kw[] = {
        "include", "define", "ifdef", "ifndef", "endif", "pragma",
        "error", "warning", "undef", "if", "else", "elif", "line", NULL};

    while (*p) {
        if (!in_string && !in_char && !in_angle && *p == '/' && *(p + 1) == '/') {
            printf(VS_COMMENT "%s" VS_RESET, p);
            break;
        }
        if (!in_string && !in_char && !in_angle && *p == '/' && *(p + 1) == '*') {
            const char* end = strstr(p + 2, "*/");
            if (end) {
                printf(VS_COMMENT "%.*s" VS_RESET, (int)(end - p + 2), p);
                p = end + 2;
                continue;
            } else {
                printf(VS_COMMENT "%s" VS_RESET, p);
                break;
            }
        }
        if (*p == '"' && !in_char && !in_angle) {
            in_string = !in_string;
            if (in_string) {
                printf(VS_STRING "%c", *p);
            } else {
                printf(VS_STRING "%c" VS_RESET, *p);
            }
            p++;
            continue;
        }
        if (in_string) {
            if (*p == '\\' && *(p + 1) != '\0') {
                printf(VS_STRING "%c%c", *p, *(p + 1));
                p += 2;
                continue;
            }
            printf(VS_STRING "%c", *p);
            p++;
            continue;
        }
        if (*p == '\'' && !in_string && !in_angle) {
            in_char = !in_char;
            if (in_char) {
                printf(VS_STRING "%c", *p);
            } else {
                printf(VS_STRING "%c" VS_RESET, *p);
            }
            p++;
            continue;
        }
        if (in_char) {
            if (*p == '\\' && *(p + 1) != '\0') {
                printf(VS_STRING "%c%c", *p, *(p + 1));
                p += 2;
                continue;
            }
            printf(VS_STRING "%c", *p);
            p++;
            continue;
        }
        if (is_include_line && *p == '<' && !in_string && !in_char) {
            in_angle = 1;
            printf(VS_STRING "%c", *p);
            p++;
            continue;
        }
        if (is_include_line && *p == '>' && in_angle) {
            in_angle = 0;
            printf(VS_STRING "%c" VS_RESET, *p);
            p++;
            continue;
        }
        if (in_angle) {
            printf(VS_STRING "%c", *p);
            p++;
            continue;
        }
        if (p == line && *p == '#') {
            printf(VS_PREPROC "%c" VS_RESET, *p);
            p++;
            continue;
        }
        if (isdigit((unsigned char)*p)) {
            printf(VS_NUMBER);
            while (isdigit((unsigned char)*p) || *p == '.') {
                printf("%c", *p);
                p++;
            }
            printf(VS_RESET);
            continue;
        }
        if (isalpha((unsigned char)*p) || *p == '_') {
            const char* start = p;
            while (isalnum((unsigned char)*p) || *p == '_') {
                p++;
            }
            int len = p - start;
            char word[64];
            if (len < (int)sizeof(word)) {
                strncpy(word, start, len);
                word[len] = '\0';

                int is_stmt = 0, is_type = 0, is_preproc = 0;
                for (int i = 0; preproc_kw[i]; i++) {
                    if (strcmp(word, preproc_kw[i]) == 0) { is_preproc = 1; break; }
                }
                if (!is_preproc) {
                    for (int i = 0; stmt_kw[i]; i++) {
                        if (strcmp(word, stmt_kw[i]) == 0) { is_stmt = 1; break; }
                    }
                }
                if (!is_preproc && !is_stmt) {
                    for (int i = 0; type_kw[i]; i++) {
                        if (strcmp(word, type_kw[i]) == 0) { is_type = 1; break; }
                    }
                }

                if (is_preproc) {
                    printf(VS_PREPROC "%s" VS_RESET, word);
                } else if (is_stmt) {
                    printf(VS_STMT "%s" VS_RESET, word);
                } else if (is_type) {
                    printf(VS_TYPE "%s" VS_RESET, word);
                } else {
                    const char* lookahead = p;
                    while (*lookahead == ' ' || *lookahead == '\t') lookahead++;
                    if (*lookahead == '(') {
                        printf(VS_FUNC "%s" VS_RESET, word);
                    } else {
                        printf(VS_VAR "%s" VS_RESET, word);
                    }
                }
            } else {
                printf("%.*s", len, start);
            }
            continue;
        }
        printf("%c", *p);
        p++;
    }
        printf("\n");

        #undef VS_COMMENT
        #undef VS_PREPROC
        #undef VS_TYPE
        #undef VS_STMT
        #undef VS_STRING
        #undef VS_NUMBER
        #undef VS_FUNC
        #undef VS_VAR
        #undef VS_RESET
}

/* ---------- 行内 Markdown 渲染 ---------- */
static void render_inline_text(const char* line) {
    const char* p = line;

    #define INLINE_CODE   "\033[38;5;245m"
    #define INLINE_BOLD   "\033[1m"
    #define INLINE_ITALIC "\033[3m"
    #define INLINE_STRIKE "\033[9m"
    #define INLINE_LINK   "\033[4;38;5;39m"
    #define INLINE_URL    "\033[38;5;245m"
    #define INLINE_RESET  "\033[0m"

    while (*p) {
        if (*p == '\\' && *(p + 1) != '\0') {
            putchar(*(p + 1));
            p += 2;
            continue;
        }

        if (*p == '`') {
            const char* end = strchr(p + 1, '`');
            if (end) {
                printf(INLINE_CODE "%.*s" INLINE_RESET,
                       (int)(end - p - 1), p + 1);
                p = end + 1;
                continue;
            }
            putchar(*p++);
            continue;
        }

        if (*p == '*' && *(p + 1) == '*') {
            const char* end = strstr(p + 2, "**");
            if (end) {
                printf(INLINE_BOLD "%.*s" INLINE_RESET,
                       (int)(end - p - 2), p + 2);
                p = end + 2;
                continue;
            }
        }

        if (*p == '~' && *(p + 1) == '~') {
            const char* end = strstr(p + 2, "~~");
            if (end) {
                printf(INLINE_STRIKE "%.*s" INLINE_RESET,
                       (int)(end - p - 2), p + 2);
                p = end + 2;
                continue;
            }
        }

        if ((*p == '*' || *p == '_') &&
            !( *p == '*' && *(p + 1) == '*' )) {
            char marker = *p;
            const char* end = strchr(p + 1, marker);
            if (end && end > p + 1) {
                printf(INLINE_ITALIC "%.*s" INLINE_RESET,
                       (int)(end - p - 1), p + 1);
                p = end + 1;
                continue;
            }
        }

        if (*p == '[') {
            const char* close_bracket = strchr(p + 1, ']');
            if (close_bracket && *(close_bracket + 1) == '(') {
                const char* close_paren = strchr(close_bracket + 2, ')');
                if (close_paren) {
                    printf(INLINE_LINK "%.*s" INLINE_RESET,
                           (int)(close_bracket - p - 1), p + 1);
                    printf(" (" INLINE_URL "%.*s" INLINE_RESET ")",
                           (int)(close_paren - close_bracket - 2),
                           close_bracket + 2);
                    p = close_paren + 1;
                    continue;
                }
            }
        }

        putchar(*p++);
    }

    #undef INLINE_CODE
    #undef INLINE_BOLD
    #undef INLINE_ITALIC
    #undef INLINE_STRIKE
    #undef INLINE_LINK
    #undef INLINE_URL
    #undef INLINE_RESET
}

/*char *node 先不支持*/
int CPKG_manual(const char* PocketName, char* node) {
    (void)node;

    // 拼接 /usr/share/cpkg/manual/<PocketName>
    char manual_dir[PATH_MAX];
    snprintf(manual_dir, sizeof(manual_dir), "%s%s", MANUAL_PATH, PocketName);

    if (!is_dir(manual_dir)) {
        return NoTranslationManual;
    }

    char manual_path[PATH_MAX];
    snprintf(manual_path, sizeof(manual_path), "%s/manual.txt", manual_dir);

    FILE* manual_fp = fopen(manual_path, "r");
    if (manual_fp == NULL) {
        return CantOpenManual;
    }

    char line[1024];
    int in_code_block = 0;

    while (fgets(line, sizeof(line), manual_fp)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[--len] = '\0';
        }

        char* trimmed = line;
        while (*trimmed == ' ' || *trimmed == '\t') trimmed++;

        if (!in_code_block) {
            if (strncmp(trimmed, "```", 3) == 0) {
                in_code_block = 1;
                continue;
            }
        } else {
            if (strcmp(trimmed, "```") == 0) {
                in_code_block = 0;
                continue;
            }
        }

        if (in_code_block) {
            highlight_c_line(line);
        } else {
            char* p = line;
            while (*p == ' ' || *p == '\t') p++;

            int heading_level = 0;
            char* h = p;
            while (h[heading_level] == '#' && heading_level < 6) heading_level++;

            if (heading_level > 0 &&
                (h[heading_level] == ' ' || h[heading_level] == '\t' || h[heading_level] == '\0')) {
                char* text = h + heading_level;
                while (*text == ' ' || *text == '\t') text++;

                size_t tlen = strlen(text);
                while (tlen > 0 && (text[tlen - 1] == ' ' || text[tlen - 1] == '\t')) {
                    text[--tlen] = '\0';
                }
                if (tlen >= 2 && text[tlen - 1] == '#' &&
                    (text[tlen - 2] == ' ' || text[tlen - 2] == '\t')) {
                    while (tlen > 0 &&
                           (text[tlen - 1] == '#' || text[tlen - 1] == ' ' || text[tlen - 1] == '\t')) {
                        text[--tlen] = '\0';
                    }
                }

                switch (heading_level) {
                    case 1:
                        printf("\n\033[1;4;38;5;44m%s\033[0m\n", text);
                        break;
                    case 2:
                        printf("\033[1;38;5;39m%s\033[0m\n", text);
                        break;
                    case 3:
                        printf("\033[1;38;5;176m%s\033[0m\n", text);
                        break;
                    case 4:
                        printf("\033[1;38;5;180m%s\033[0m\n", text);
                        break;
                    case 5:
                        printf("\033[1;38;5;114m%s\033[0m\n", text);
                        break;
                    case 6:
                    default:
                        printf("\033[1;38;5;245m%s\033[0m\n", text);
                        break;
                }
            } else {
                render_inline_text(line);
                printf("\n");
            }
        }
    }

    fclose(manual_fp);
    return Successful;
}
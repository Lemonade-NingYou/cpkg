#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>

#include "openapi.h"   // 假设其中声明了 build() 和 install()
#include "outerror.h"  // 假设其中声明了 ErrorInfo 枚举和 ErrorArg()

char* version_string = "1.0.0";  // 版本号字符串

static struct option long_options[] = {
    {"install", required_argument, 0, 'i'},  // 新增 --install
    {"build", required_argument, 0, 'b'},
    {"help", no_argument, 0, 'h'},
    {"version", no_argument, 0, 'V'},
    {0, 0, 0, 0}};

int main(int argc, char* argv[]) {
    int opt;
    int option_index = 0;
    char* filename = NULL;

    while ((opt = getopt_long(argc, argv, "r:i:b:hV", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'i': {
                filename = optarg;
                int install_result = install(filename);
                if (install_result != 0) {
                    ErrorArg(install_result);
                    return 1;
                }
                break;
            }
            case 'r': {
                filename = optarg;
                int install_result = install(filename);
                if (install_result != 0) {
                    ErrorArg(install_result);
                    return 1;
                }
                break;
            }
            case 'b': {
                filename = optarg;
                int build_result = build(filename);
                if (build_result != 0) {
                    ErrorArg(build_result);
                    return 1;
                }
                break;
            }
            case 'h':
                printf("Usage: %s -i <filename> | -b <filename> [-h] [-V]\n", argv[0]);
                printf("  -i, --install <file>   Install package\n");
                printf("  -b, --build <file>     Build package\n");
                printf("  -h, --help             Show this help\n");
                printf("  -V, --version          Show version\n");
                return 0;
            case 'V':
                printf("Version %s\n", version_string);
                return 0;
            case '?':  // 未知选项或缺少参数
                fprintf(stderr, "Usage: %s -i <filename> | -b <filename> [-h] [-V]\n", argv[0]);
                return 1;
            default:
                fprintf(stderr, "cpkg: internal error: impossible condition detected (but here we are)\n");
                fprintf(stderr, "This is a bug. Please report it to <bug-cpkg@UFO.org>.\n");
                fprintf(stderr, "Attach a screenshot of your face at the exact moment of failure.\n");
                fprintf(stderr, "Aborted (core dumped, probably into your keyboard)\n");
                return 1;
        }
    }

    // 处理剩余非选项参数（如果有）
    if (optind < argc) {
        fprintf(stderr, "Warning: extra arguments ignored\n");
    }

    return 0;
}
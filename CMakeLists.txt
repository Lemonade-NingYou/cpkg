cmake_minimum_required(VERSION 3.12)
project(Cpkg VERSION 1.0 LANGUAGES C)

# ===================== 编译选项 =====================
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)          # 严格使用标准 C，不启用 GNU 扩展

# ===================== 头文件搜索路径 =====================
# 项目自身的 include 目录（全局）
include_directories(${CMAKE_SOURCE_DIR}/include)

# ===================== 源文件列表 =====================
set(SOURCES
    src/main.c
    src/build.c
    src/outerror.c
    src/utils.c
    src/install.c
)

# ===================== 生成可执行文件 =====================
add_executable(cpkg ${SOURCES})

# ===================== 依赖 libarchive =====================
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBARCHIVE REQUIRED libarchive)

# 将 libarchive 的头文件路径和库链接到目标 cpkg
target_include_directories(cpkg PRIVATE ${LIBARCHIVE_INCLUDE_DIRS})
target_link_libraries(cpkg ${LIBARCHIVE_LIBRARIES})

# 如果 libarchive 提供了编译定义（如 _LARGEFILE64_SOURCE），可追加
# target_compile_definitions(cpkg PRIVATE ${LIBARCHIVE_CFLAGS_OTHER})

# ===================== 可选：安装规则 =====================
install(TARGETS cpkg DESTINATION bin)

# ===================== 可选：测试 =====================
enable_testing()
add_test(NAME SimpleCreate COMMAND cpkg -c -f test.my cpkg)
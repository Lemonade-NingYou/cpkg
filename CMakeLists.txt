cmake_minimum_required(VERSION 3.12)
project(Cpkg VERSION 1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

include_directories(${CMAKE_SOURCE_DIR}/include)

set(SOURCES
    src/main.c
    src/build.c
    src/outerror.c
    src/utils.c
    src/install.c
    src/remove.c
    src/list.c
)

add_executable(cpkg ${SOURCES})

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBARCHIVE REQUIRED libarchive)
pkg_check_modules(LIBYAML REQUIRED yaml-0.1)
pkg_check_modules(OPENSSL REQUIRED openssl)

# ------ 查找 cJSON 库（手动方式，因为 pkg-config 可能无 .pc） ------
# 先尝试 pkg-config（某些发行版可能提供）
pkg_check_modules(CJSON QUIET cjson)
if(NOT CJSON_FOUND)
    # 尝试查找头文件和库
    find_path(CJSON_INCLUDE_DIR
        NAMES cjson/cJSON.h cJSON.h
        PATHS /usr/include /usr/local/include
    )
    find_library(CJSON_LIBRARY
        NAMES cjson cJSON
        PATHS /usr/lib /usr/local/lib
    )
    if(CJSON_INCLUDE_DIR AND CJSON_LIBRARY)
        set(CJSON_INCLUDE_DIRS ${CJSON_INCLUDE_DIR})
        set(CJSON_LIBRARIES ${CJSON_LIBRARY})
        set(CJSON_FOUND TRUE)
    else()
        message(FATAL_ERROR "cJSON library not found. Please install libcjson-dev (e.g., sudo apt install libcjson-dev).")
    endif()
endif()
# ------------------------------------------------------

target_include_directories(cpkg PRIVATE
    ${LIBARCHIVE_INCLUDE_DIRS}
    ${LIBYAML_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIRS}
    ${CJSON_INCLUDE_DIRS}
)

target_link_libraries(cpkg
    ${LIBARCHIVE_LIBRARIES}
    ${LIBYAML_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${CJSON_LIBRARIES}
)

install(TARGETS cpkg DESTINATION bin)

# ===================== 可选：测试 =====================
enable_testing()
add_test(NAME SimpleCreate COMMAND cpkg -c -f test.my cpkg)
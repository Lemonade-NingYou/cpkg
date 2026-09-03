# Copyright (C) 2026 Lemonade-NingYou
#
# This file is part of cpkg.
#
# cpkg is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# cpkg is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with cpkg. If not, see <https://www.gnu.org/licenses/>.
cmake_minimum_required(VERSION 3.12)
project(Cpkg VERSION 2.0.0 LANGUAGES C)   # 更新版本号与 README 一致

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# 引入标准安装目录变量（如 CMAKE_INSTALL_BINDIR, CMAKE_INSTALL_DATADIR 等）
include(GNUInstallDirs)

# 自定义文档安装目录（share/doc/cpkg）
set(CMAKE_INSTALL_DOCDIR ${CMAKE_INSTALL_DATADIR}/doc/${PROJECT_NAME}
    CACHE PATH "Documentation installation directory")

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

# ------ 查找依赖（保持不变） ------
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBARCHIVE REQUIRED libarchive)
pkg_check_modules(LIBYAML REQUIRED yaml-0.1)
pkg_check_modules(OPENSSL REQUIRED openssl)

# 查找 cJSON（手动回退）
pkg_check_modules(CJSON QUIET cjson)
if(NOT CJSON_FOUND)
    find_path(CJSON_INCLUDE_DIR NAMES cjson/cJSON.h cJSON.h
        PATHS /usr/include /usr/local/include)
    find_library(CJSON_LIBRARY NAMES cjson cJSON
        PATHS /usr/lib /usr/local/lib)
    if(CJSON_INCLUDE_DIR AND CJSON_LIBRARY)
        set(CJSON_INCLUDE_DIRS ${CJSON_INCLUDE_DIR})
        set(CJSON_LIBRARIES ${CJSON_LIBRARY})
        set(CJSON_FOUND TRUE)
    else()
        message(FATAL_ERROR "cJSON library not found. Please install libcjson-dev.")
    endif()
endif()

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

# ===================== 安装规则 =====================
# 1. 可执行文件
install(TARGETS cpkg
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# 2. 文档（README 和 LICENSE）
install(FILES
    ${CMAKE_SOURCE_DIR}/README.md
    ${CMAKE_SOURCE_DIR}/LICENSE
    DESTINATION ${CMAKE_INSTALL_DOCDIR}
)

# 3. （可选）安装示例配置文件（如果项目包含 config.txt 示例）
# install(FILES ${CMAKE_SOURCE_DIR}/config.txt.example
#         DESTINATION ${CMAKE_INSTALL_DOCDIR}/examples
#         RENAME config.txt)

# ===================== CPack 打包支持（可选） =====================
# ===================== CPack 打包 =====================
set(CPACK_GENERATOR "DEB;RPM;TGZ")   # 选择您需要的格式

set(CPACK_PACKAGE_NAME "${PROJECT_NAME}")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "A lightweight C package manager")
set(CPACK_PACKAGE_VENDOR "Lemonade-NingYou")
set(CPACK_PACKAGE_CONTACT "your-email@example.com")
set(CPACK_PACKAGE_LICENSE "GPLv3")

# 依赖信息（对 DEB/RPM 有效）
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libarchive-dev, libyaml-dev, libssl-dev, libcjson-dev")
set(CPACK_RPM_PACKAGE_REQUIRES "libarchive-devel, libyaml-devel, openssl-devel, cjson-devel")

# 让包文件名更清晰（可选）
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-Linux")

include(CPack)
# ===================== 测试（保留） =====================
enable_testing()
add_test(NAME SimpleCreate COMMAND cpkg -c -f test.my cpkg)
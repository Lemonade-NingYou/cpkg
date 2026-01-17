# Makefile for cpkg project
# Copyright (c) 2025 lemonade_NingYou

# 编译器配置
CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c99
INCLUDES = -I./include
LDFLAGS = -larchive -lcrypto -lssl

# 目录结构
SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = .

# 源文件和目标文件
SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRCS))

# 目标可执行文件（放在根目录）
TARGET = cpkg

# 默认目标
all: $(TARGET)

# 链接可执行文件
$(TARGET): $(OBJS) | $(BIN_DIR)
	$(CC) $(OBJS) $(LDFLAGS) -o $@

# 编译源文件
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# 创建目录
$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

# 清理生成的文件
clean:
	rm -rf $(OBJ_DIR) $(TARGET)

# 安装到系统目录
install: $(TARGET)
	cp $(TARGET) /usr/local/bin/

# 卸载
uninstall:
	rm -f /usr/local/bin/$(TARGET)

# 重新编译
re: clean all

# 调试版本
debug: CFLAGS += -g -DDEBUG -O0
debug: clean all

# 发布版本
release: CFLAGS += -O3 -DNDEBUG
release: clean all

# 测试
test: $(TARGET)
	./$(TARGET) test/test.cpk

# 静态分析
check:
	scan-build make

# 格式检查
format:
	find . -name "*.c" -o -name "*.h" | xargs clang-format -i

# 显示帮助信息
help:
	@echo "=== CPKG Makefile 帮助 ==="
	@echo "  make all       - 编译程序 (默认)"
	@echo "  make clean     - 清理生成的文件"
	@echo "  make install   - 安装到系统目录"
	@echo "  make uninstall - 卸载程序"
	@echo "  make re        - 重新编译"
	@echo "  make debug     - 编译调试版本"
	@echo "  make release   - 编译发布版本"
	@echo "  make test      - 运行测试"
	@echo "  make check     - 运行静态分析"
	@echo "  make format    - 格式化代码"
	@echo "  make help      - 显示此帮助信息"

# 防止与同名文件冲突
.PHONY: all clean install uninstall re debug release test check format help
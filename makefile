# 项目配置
PROJECT_NAME = cpkg
VERSION = 0.0.0.2

# 编译器设置
CC = gcc
CFLAGS = -Wall -Wextra -Werror -O2 -g
LDFLAGS = -larchive -lcrypto -lssl -lm -lcurl

# 目录设置
SRC_DIR = src
OBJ_DIR = build/obj
BIN_DIR = build/bin
DIST_DIR = dist
INSTALL_PREFIX = /usr/local

# 源文件和目标文件
SOURCES = $(wildcard $(SRC_DIR)/*.c)
OBJECTS = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SOURCES))
EXECUTABLE = $(BIN_DIR)/$(PROJECT_NAME)

# 默认目标
all: $(EXECUTABLE)

# 链接可执行文件
$(EXECUTABLE): $(OBJECTS) | $(BIN_DIR)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)
	@echo "✅ 项目编译完成: $(EXECUTABLE)"

# 编译源文件
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# 创建必要的目录
$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(DIST_DIR):
	mkdir -p $(DIST_DIR)

# 清理构建文件
clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)
	@echo "🧹 已清理构建文件"

# 完全清理（包括发布文件）
distclean: clean
	rm -rf $(DIST_DIR) *.tar.gz *.zip *.deb
	@echo "🗑️  已清理所有生成文件"

# 安装到系统
install: $(EXECUTABLE)
	install -d $(INSTALL_PREFIX)/bin
	install -m 755 $(EXECUTABLE) $(INSTALL_PREFIX)/bin/$(PROJECT_NAME)
	@echo "📦 已安装到 $(INSTALL_PREFIX)/bin"

# 卸载
uninstall:
	rm -f $(INSTALL_PREFIX)/bin/$(PROJECT_NAME)
	@echo "🗑️  已从 $(INSTALL_PREFIX)/bin 卸载"

# 运行程序
run: $(EXECUTABLE)
	@echo "🚀 运行程序..."
	./$(EXECUTABLE)

# 调试构建
debug: CFLAGS = -Wall -Wextra -g -O0 -std=c11
debug: clean $(EXECUTABLE)
	@echo "🐛 调试版本编译完成"

# ===============================
# 打包目标
# ===============================

# 创建源码tar.gz包
dist-src: $(DIST_DIR)
	@echo "📦 正在创建源码压缩包..."
	tar --exclude='./build' --exclude='./dist' --exclude='./*.tar.gz' \
		--exclude='./*.zip' --exclude='./*.deb' --exclude='./.git*' \
		-czvf $(DIST_DIR)/$(PROJECT_NAME)-$(VERSION).tar.gz . --transform='s,^\./,$(PROJECT_NAME)-$(VERSION)/,'
	@echo "✅ 源码压缩包已创建: $(DIST_DIR)/$(PROJECT_NAME)-$(VERSION).tar.gz"

# 创建二进制tar.gz包
dist-bin: all $(DIST_DIR)
	@echo "📦 正在创建二进制压缩包..."
	mkdir -p $(DIST_DIR)/tmp/$(PROJECT_NAME)-$(VERSION)
	cp -r $(EXECUTABLE) README.md LICENSE $(DIST_DIR)/tmp/$(PROJECT_NAME)-$(VERSION)/
	cd $(DIST_DIR)/tmp && tar -czvf ../$(PROJECT_NAME)-$(VERSION)-linux-amd64.tar.gz $(PROJECT_NAME)-$(VERSION)
	rm -rf $(DIST_DIR)/tmp
	@echo "✅ 二进制压缩包已创建: $(DIST_DIR)/$(PROJECT_NAME)-$(VERSION)-linux-amd64.tar.gz"

# 创建ZIP包
dist-zip: $(DIST_DIR)
	@echo "📦 正在创建ZIP压缩包..."
	zip -r $(DIST_DIR)/$(PROJECT_NAME)-$(VERSION).zip . \
		-x 'build/*' 'dist/*' '*.tar.gz' '*.zip' '*.deb' '.git/*' '*~'
	@echo "✅ ZIP压缩包已创建: $(DIST_DIR)/$(PROJECT_NAME)-$(VERSION).zip"

# 创建DEB包（需要dpkg-dev和fakeroot）
# 创建DEB包（需要dpkg-dev和fakeroot）
dist-deb: all $(DIST_DIR)
	@echo "📦 正在创建DEB包..."
	@# 创建DEB包结构
	mkdir -p $(DIST_DIR)/deb/$(PROJECT_NAME)-$(VERSION)/DEBIAN
	mkdir -p $(DIST_DIR)/deb/$(PROJECT_NAME)-$(VERSION)$(INSTALL_PREFIX)/bin
	
	@# 复制可执行文件
	install -m 755 $(EXECUTABLE) $(DIST_DIR)/deb/$(PROJECT_NAME)-$(VERSION)$(INSTALL_PREFIX)/bin/
	
	@# 创建control文件
	@echo "Package: $(PROJECT_NAME)" > $(DIST_DIR)/deb/$(PROJECT_NAME)-$(VERSION)/DEBIAN/control
	@echo "Version: $(VERSION)" >> $(DIST_DIR)/deb/$(PROJECT_NAME)-$(VERSION)/DEBIAN/control
	@echo "Section: utils" >> $(DIST_DIR)/deb/$(PROJECT_NAME)-$(VERSION)/DEBIAN/control
	@echo "Priority: optional" >> $(DIST_DIR)/deb/$(PROJECT_NAME)-$(VERSION)/DEBIAN/control
	@echo "Architecture: amd64" >> $(DIST_DIR)/deb/$(PROJECT_NAME)-$(VERSION)/DEBIAN/control
	@echo "Maintainer: 你的姓名 <你的邮箱@example.com>" >> $(DIST_DIR)/deb/$(PROJECT_NAME)-$(VERSION)/DEBIAN/control
	@echo "Description: $(PROJECT_NAME) 应用程序" >> $(DIST_DIR)/deb/$(PROJECT_NAME)-$(VERSION)/DEBIAN/control
	@echo " 使用Makefile构建的C语言应用程序" >> $(DIST_DIR)/deb/$(PROJECT_NAME)-$(VERSION)/DEBIAN/control
	
	@# 检查是否安装了fakeroot
	@if command -v fakeroot >/dev/null 2>&1; then \
		echo "使用 fakeroot 构建 DEB 包..."; \
		fakeroot dpkg-deb --build $(DIST_DIR)/deb/$(PROJECT_NAME)-$(VERSION) $(DIST_DIR)/; \
	else \
		echo "警告: fakeroot 未安装，尝试使用 --root-owner-group 选项..."; \
		dpkg-deb --root-owner-group --build $(DIST_DIR)/deb/$(PROJECT_NAME)-$(VERSION) $(DIST_DIR)/; \
	fi
	
	@# 检查并重命名生成的文件
	@echo "检查生成的 DEB 文件..."
	@if [ -f "$(DIST_DIR)/$(PROJECT_NAME)-$(VERSION).deb" ]; then \
		echo "找到 $(DIST_DIR)/$(PROJECT_NAME)-$(VERSION).deb，重命名中..."; \
		mv "$(DIST_DIR)/$(PROJECT_NAME)-$(VERSION).deb" "$(DIST_DIR)/$(PROJECT_NAME)_$(VERSION)_amd64.deb"; \
	elif [ -f "$(DIST_DIR)/$(PROJECT_NAME)_$(VERSION)_amd64.deb" ]; then \
		echo "文件已正确命名: $(DIST_DIR)/$(PROJECT_NAME)_$(VERSION)_amd64.deb"; \
	else \
		echo "查找生成的 DEB 文件..."; \
		find $(DIST_DIR) -name "*.deb" -type f | head -5 | while read file; do \
			base=$$(basename "$$file"); \
			echo "找到: $$base"; \
			if echo "$$base" | grep -q "^$(PROJECT_NAME)_$(VERSION)_"; then \
				echo "文件已正确命名: $$file"; \
			else \
				echo "重命名 $$base..."; \
				mv "$$file" "$(DIST_DIR)/$(PROJECT_NAME)_$(VERSION)_amd64.deb"; \
			fi \
		done; \
	fi
	
	@# 清理临时目录
	@rm -rf $(DIST_DIR)/deb
	
	@# 验证最终文件
	@if [ -f "$(DIST_DIR)/$(PROJECT_NAME)_$(VERSION)_amd64.deb" ]; then \
		echo "✅ DEB包已创建: $(DIST_DIR)/$(PROJECT_NAME)_$(VERSION)_amd64.deb"; \
		ls -la "$(DIST_DIR)/$(PROJECT_NAME)_$(VERSION)_amd64.deb"; \
	else \
		echo "❌ 未能创建 DEB 包。检查以下可能的原因："; \
		echo "   1. 确保已安装 dpkg-deb (sudo apt-get install dpkg-dev)"; \
		echo "   2. 确保已安装 fakeroot (sudo apt-get install fakeroot)"; \
		echo "   3. 检查是否有足够的权限"; \
		false; \
	fi
	
# 创建所有发布包
dist-all: dist-src dist-bin dist-zip dist-deb
	@echo "🎉 所有发布包已创建完成，存放在 $(DIST_DIR)/ 目录"
	@echo "📁 生成的文件:"
	@ls -la $(DIST_DIR)/*.tar.gz $(DIST_DIR)/*.zip $(DIST_DIR)/*.deb 2>/dev/null || echo "未找到文件"

# 检查依赖
check-deps:
	@echo "🔍 正在检查依赖..."
	@command -v $(CC) >/dev/null 2>&1 || { echo "❌ 错误: 需要 $(CC) 但未安装。"; exit 1; }
	@command -v zip >/dev/null 2>&1 || { echo "⚠️  警告: zip 未安装，dist-zip 目标将失败。"; }
	@command -v dpkg-deb >/dev/null 2>&1 || { echo "⚠️  警告: dpkg-deb 未安装，dist-deb 目标将失败。"; }
	@echo "✅ 所有必需依赖已就绪"

# 显示项目信息
info:
	@echo "📋 项目信息:"
	@echo "   项目名称: $(PROJECT_NAME)"
	@echo "   版本号: $(VERSION)"
	@echo "   编译器: $(CC)"
	@echo "   源码目录: $(SRC_DIR)"
	@echo "   源文件: $(SOURCES)"
	@echo "   目标文件: $(OBJECTS)"
	@echo "   可执行文件: $(EXECUTABLE)"

# 显示帮助信息
help:
	@echo "📖 $(PROJECT_NAME) v$(VERSION) - Makefile 帮助"
	@echo ""
	@echo "使用方法: make [目标]"
	@echo ""
	@echo "基本目标:"
	@echo "  all           编译项目（默认）"
	@echo "  clean         清理构建文件"
	@echo "  distclean     清理所有生成文件"
	@echo "  install       安装到 $(INSTALL_PREFIX)"
	@echo "  uninstall     从 $(INSTALL_PREFIX) 卸载"
	@echo "  run           编译并运行程序"
	@echo "  debug         使用调试符号编译"
	@echo "  info          显示项目信息"
	@echo ""
	@echo "打包目标:"
	@echo "  dist-src      创建源码压缩包 (.tar.gz)"
	@echo "  dist-bin      创建二进制压缩包 (.tar.gz)"
	@echo "  dist-zip      创建ZIP压缩包 (.zip)"
	@echo "  dist-deb      创建Debian包 (.deb)"
	@echo "  dist-all      创建所有发布包"
	@echo ""
	@echo "工具目标:"
	@echo "  check-deps    检查构建依赖"
	@echo "  help          显示此帮助信息"

# 默认目标
.DEFAULT_GOAL := help

.PHONY: all clean distclean install uninstall run debug dist-src dist-bin dist-zip dist-deb dist-all check-deps help info
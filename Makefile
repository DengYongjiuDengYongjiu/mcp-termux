# MCP RE v7.0 Build
# 环境: Termux (Android ARM64) + g++/clang++

CXX ?= g++
CXXFLAGS = -std=c++17 -O2 -pthread
DEPLOY_DIR ?= /data/adb/mcp_re_v6

.PHONY: all mcp boot deploy clean

all: mcp boot

mcp: src/mcp_termux_v7.cpp src/httplib.h src/json.hpp
	$(CXX) $(CXXFLAGS) -o mcp_termux_v7 src/mcp_termux_v7.cpp

boot: src/mcp_boot.cpp src/httplib.h src/json.hpp
	$(CXX) $(CXXFLAGS) -o mcp_boot src/mcp_boot.cpp

deploy: mcp boot
	@echo "部署到 $(DEPLOY_DIR)..."
	cp mcp_termux_v7 $(DEPLOY_DIR)/mcp
	cp mcp_boot $(DEPLOY_DIR)/mcp_boot
	chmod 755 $(DEPLOY_DIR)/mcp $(DEPLOY_DIR)/mcp_boot
	@echo "部署完成。请手动重启 MCP 服务。"

clean:
	rm -f mcp_termux_v7 mcp_boot

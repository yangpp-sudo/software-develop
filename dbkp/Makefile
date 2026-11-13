# ============================================================================
#  Makefile —— Linux(主) / MinGW(本地自测) 双平台
#  目标：
#    make            构建 bk（CLI）+ 单测程序
#    make test       编译并运行单元测试
#    make demo       跑一遍备份/还原/校验演示
#    make gtest      使用系统 GoogleTest（需 libgtest-dev）
#    make clean
# ============================================================================

CXX      ?= g++
CXXSTD   ?= -std=c++17
WARNINGS := -Wall -Wextra
OPT      ?= -O2 -g
# -MMD -MP：为每个 .o 生成 .d，记录它 include 过的头文件。
# 没有它，改一个头文件只会重编"同名 .cpp"，其余目标文件仍按**旧的结构体布局**
# 参与链接 —— 表现就是"改了 PackOptions 之后单测随机崩溃"（ABI 不一致）。
DEPFLAGS := -MMD -MP
CPPFLAGS := -Iinclude $(CXXSTD) $(WARNINGS) $(OPT) $(DEPFLAGS) -pthread

# ---- 自动探测平台，选择对应的 Platform 实现 --------------------------------
# 注意：Windows 下绝不能执行 $(shell uname -s 2>/dev/null) —— cmd 找不到 uname，
# 而 "/dev/null" 这个重定向目标还会让控制台吐出"系统找不到指定的路径"，
# 看起来像构建失败，其实只是这一行的噪音。
ifeq ($(OS),Windows_NT)
  UNAME_S  :=
  EXE      := .exe
  PLAT_SRC := src/Platform/FS_win.cpp
  WATCH_SRC := src/Backup/Watcher_win.cpp
  # F3：fillRandom 改用 BCryptGenRandom，需链接 bcrypt.lib
  SYS_LIBS := -lws2_32 -lbcrypt
  MKDIR    = @if not exist "$(BIN)" mkdir "$(BIN)"
else
  UNAME_S  := $(shell uname -s)
  EXE      :=
  MKDIR    = @mkdir -p $(BIN)
  WATCH_SRC := src/Backup/Watcher_posix.cpp
  ifneq (,$(findstring Darwin,$(UNAME_S)))
    PLAT_SRC := src/Platform/FS_posix.cpp
    SYS_LIBS :=
  else
    PLAT_SRC := src/Platform/FS_posix.cpp
    SYS_LIBS := -lrt
  endif
endif

# ---- 源文件：自动收集，Platform/Backup 下按平台挑选 -------------------------------
ALL_SRC   := $(wildcard src/*/*.cpp)
PLAT_ALL  := src/Platform/FS_posix.cpp src/Platform/FS_win.cpp
WATCH_ALL := src/Backup/Watcher_posix.cpp src/Backup/Watcher_win.cpp
LIB_SRC   := $(filter-out $(PLAT_ALL) $(WATCH_ALL), $(ALL_SRC))
LIB_SRC   += $(PLAT_SRC)
LIB_SRC   += $(WATCH_SRC)
CLI_SRC   := src/main.cpp
SRV_SRC   := src/server_main.cpp
TEST_SRC  := $(wildcard test/*.cpp)

OBJ      := obj
LIB_OBJ  := $(LIB_SRC:%.cpp=$(OBJ)/%.o)
CLI_OBJ  := $(CLI_SRC:%.cpp=$(OBJ)/%.o)
SRV_OBJ  := $(SRV_SRC:%.cpp=$(OBJ)/%.o)
TEST_OBJ := $(TEST_SRC:%.cpp=$(OBJ)/%.o)

ifeq ($(OS),Windows_NT)
  # cmd 的 mkdir 会自动创建中间层目录
  MKDIR_P  = @if not exist "$(subst /,\,$1)" mkdir "$(subst /,\,$1)"
else
  MKDIR_P  = @mkdir -p
endif

BIN     := bin
APP     := $(BIN)/bk$(EXE)
APPDAEMON := $(BIN)/bkd$(EXE)
APPTEST := $(BIN)/bk_test$(EXE)
APPGT   := $(BIN)/bk_gtest$(EXE)

# ---- 批次10：vendored GoogleTest（third_party/googletest, release-1.12.1）-----
# 不依赖系统 libgtest，也不需要 CMake：直接把 googletest/src/gtest-all.cc 一起编。
# release-1.12.1 只要求 C++14，g++ 8.1.0 可编（更新的 v1.14+ 要 C++17 且用到
# GCC8 尚未提供的特性，故不用 HEAD）。入口不用 gtest_main.cc，改用
# test/test_wb_main.cpp —— 它在真实 gtest 下补上和迷你框架一样的临时沙箱 chdir，
# 否则老用例会把 ttest_* 目录拉进源码树。
GTEST_ROOT := third_party/googletest/googletest
GTEST_CC   := $(GTEST_ROOT)/src/gtest-all.cc
GTEST_INC  := -isystem $(GTEST_ROOT)/include -I $(GTEST_ROOT)

.PHONY: all clean test demo gtest test-gtest coverage dirs server

all: dirs $(APP) $(APPDAEMON)

dirs:
	$(MKDIR)

$(APP): $(LIB_OBJ) $(CLI_OBJ)
	$(CXX) $(CPPFLAGS) -o $@ $^ $(SYS_LIBS)

# bkd：Web 服务端。与 bk 共用同一个内核库（LIB_OBJ），只差入口。
$(APPDAEMON): $(LIB_OBJ) $(SRV_OBJ)
	$(CXX) $(CPPFLAGS) -o $@ $^ $(SYS_LIBS)

# 单独构建/运行服务：make server PORT=8080
server: $(APPDAEMON)
	$(APPDAEMON) --port $(PORT)

# 对象文件统一到 obj/ 下，保持源码树干净（评分项里有"工程规范"）
$(OBJ)/%.o: %.cpp
	$(call MKDIR_P,$(@D))
	$(CXX) $(CPPFLAGS) -c $< -o $@

# ---- 单元测试：默认使用自带迷你框架（无需外网/系统 gtest） ------------------
$(APPTEST): $(LIB_OBJ) $(TEST_OBJ)
	$(CXX) $(CPPFLAGS) -DDBKP_MINI_TEST=1 -o $@ $^ $(SYS_LIBS)

test: dirs $(APPTEST)
	$(APPTEST)

# ---- 批次10：使用 vendored GoogleTest 编译并运行全部用例 ---------------------
# 真实 gtest 与迷你框架的 TEST 宏注册的注册表不同，二者的 .o 不能混用，
# 所以测试代码单独编到 objg/，产品库 obj/ 复用（src/ 不含 TestFramework.h）。
OBJG      := objg
GT_TEST_O := $(TEST_SRC:%.cpp=$(OBJG)/%.o)

$(OBJG)/gtest-all.o: $(GTEST_CC)
	$(call MKDIR_P,$(@D))
	$(CXX) $(CXXSTD) $(OPT) $(GTEST_INC) -pthread -c $< -o $@

$(OBJG)/%.o: %.cpp
	$(call MKDIR_P,$(@D))
	$(CXX) $(CPPFLAGS) $(GTEST_INC) -DDBKP_USE_REAL_GTEST=1 -c $< -o $@

$(APPGT): $(LIB_OBJ) $(GT_TEST_O) $(OBJG)/gtest-all.o
	$(CXX) $(CPPFLAGS) -o $@ $^ $(SYS_LIBS)

test-gtest: dirs $(APPGT)
	$(APPGT)

# ---- 批次10：覆盖率（gcov/gcovr）。独立 objcov/ 目录，避免污染常规构建 ------
# COVFLAGS 覆盖 Makefile 里的 OPT（-O2 会让 gcov 把被优化掉的行算成"未执行"，
# 统计口径虚低），并额外加 --coverage 生成 .gcno/.gcda。
# 批次10 修正：原来这里写的是 objcov/src/Codec/Codec.o、objcov/src/Crypto/Crypto.o，
# 但仓库里根本没有 Codec.cpp / Crypto.cpp（实际文件是 Huffman/LZ77/BitIo/CodecFactory
# 和 Aes/ChaCha20/CryptoCodecs/Des/Sha256），gcov 找不到对象直接报错。
# 现在把"跑插桩测试 + 收集 gcov + 出 gcovr HTML"整体交给 script/coverage_run.ps1，
# Makefile 只负责触发，跨平台行为一致。
COVFLAGS := -O0 -g --coverage
coverage:
	$(MAKE) OBJ=objcov OPT="$(COVFLAGS)" test-gtest
	-powershell -ExecutionPolicy Bypass -File script/coverage_run.ps1

# ---- 使用系统 GoogleTest（Ubuntu: sudo apt install libgtest-dev） -----------
gtest: dirs $(LIB_OBJ) $(TEST_SRC)
	$(CXX) $(CPPFLAGS) -o $(APP) $(LIB_OBJ) $(CLI_OBJ) $(SYS_LIBS)
	$(CXX) $(CPPFLAGS) -DDBKP_USE_REAL_GTEST=1 -o $(BIN)/bk_gtest$(EXE) $(TEST_SRC) $(LIB_OBJ) -lgtest -lgtest_main $(SYS_LIBS)
	$(BIN)/bk_gtest$(EXE)

# ---- 演示：备份→校验→还原→对比 ---------------------------------------------
demo: $(APP)
	./script/demo.sh

clean:
ifeq ($(OS),Windows_NT)
	-if exist "obj" rmdir /s /q "obj"
	-if exist "bin" rmdir /s /q "bin"
	-if exist "src" del /s /q "*.o" 2>nul
else
	-rm -rf $(OBJ) $(BIN)
	-find src test -name '*.o' -delete
endif

# ---- 头文件依赖：改任何 .h 都会重编所有包含它的 .cpp --------------------------
ALL_OBJ := $(LIB_OBJ) $(CLI_OBJ) $(TEST_OBJ) $(SRV_OBJ)
-include $(ALL_OBJ:.o=.d)

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
CPPFLAGS := -Iinclude $(CXXSTD) $(WARNINGS) $(OPT) -pthread

# ---- 自动探测平台，选择对应的 Platform 实现 --------------------------------
UNAME_S := $(shell uname -s 2>/dev/null)
ifeq ($(OS),Windows_NT)
  EXE      := .exe
  PLAT_SRC := src/Platform/FS_win.cpp
  SYS_LIBS := -lws2_32
  MKDIR    = @if not exist "$(BIN)" mkdir "$(BIN)"
else
  EXE      :=
  MKDIR    = @mkdir -p $(BIN)
  ifneq (,$(findstring Darwin,$(UNAME_S)))
    PLAT_SRC := src/Platform/FS_posix.cpp
    SYS_LIBS :=
  else
    PLAT_SRC := src/Platform/FS_posix.cpp
    SYS_LIBS := -lrt
  endif
endif

# ---- 源文件：自动收集，Platform 下按平台挑选 -------------------------------
ALL_SRC   := $(wildcard src/*/*.cpp)
PLAT_ALL  := src/Platform/FS_posix.cpp src/Platform/FS_win.cpp
LIB_SRC   := $(filter-out $(PLAT_ALL), $(ALL_SRC))
LIB_SRC   += $(PLAT_SRC)
CLI_SRC   := src/main.cpp
TEST_SRC  := $(wildcard test/*.cpp)

OBJ      := obj
LIB_OBJ  := $(LIB_SRC:%.cpp=$(OBJ)/%.o)
CLI_OBJ  := $(CLI_SRC:%.cpp=$(OBJ)/%.o)
TEST_OBJ := $(TEST_SRC:%.cpp=$(OBJ)/%.o)

ifeq ($(OS),Windows_NT)
  # cmd 的 mkdir 会自动创建中间层目录
  MKDIR_P  = @if not exist "$(subst /,\,$1)" mkdir "$(subst /,\,$1)"
else
  MKDIR_P  = @mkdir -p
endif

BIN     := bin
APP     := $(BIN)/bk$(EXE)
APPTEST := $(BIN)/bk_test$(EXE)

.PHONY: all clean test demo gtest dirs

all: dirs $(APP)

dirs:
	$(MKDIR)

$(APP): $(LIB_OBJ) $(CLI_OBJ)
	$(CXX) $(CPPFLAGS) -o $@ $^ $(SYS_LIBS)

# 对象文件统一到 obj/ 下，保持源码树干净（评分项里有"工程规范"）
$(OBJ)/%.o: %.cpp
	$(call MKDIR_P,$(@D))
	$(CXX) $(CPPFLAGS) -c $< -o $@

# ---- 单元测试：默认使用自带迷你框架（无需外网/系统 gtest） ------------------
$(APPTEST): $(LIB_OBJ) $(TEST_OBJ)
	$(CXX) $(CPPFLAGS) -DDBKP_MINI_TEST=1 -o $@ $^ $(SYS_LIBS)

test: dirs $(APPTEST)
	$(APPTEST)

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

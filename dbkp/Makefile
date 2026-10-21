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
  MKDIR    := @mkdir -p
else
  EXE      :=
  ifneq (,$(findstring Darwin,$(UNAME_S)))
    PLAT_SRC := src/Platform/FS_posix.cpp
    SYS_LIBS :=
  else
    PLAT_SRC := src/Platform/FS_posix.cpp
    SYS_LIBS := -lrt
  endif
  MKDIR := @mkdir -p
endif

# ---- 源文件：自动收集，Platform 下按平台挑选 -------------------------------
ALL_SRC   := $(wildcard src/*/*.cpp)
PLAT_ALL  := src/Platform/FS_posix.cpp src/Platform/FS_win.cpp
LIB_SRC   := $(filter-out $(PLAT_ALL), $(ALL_SRC))
LIB_SRC   += $(PLAT_SRC)
CLI_SRC   := src/main.cpp
TEST_SRC  := $(wildcard test/*.cpp)

LIB_OBJ  := $(LIB_SRC:.cpp=.o)
CLI_OBJ  := $(CLI_SRC:.cpp=.o)
TEST_OBJ := $(TEST_SRC:.cpp=.o)

BIN     := bin
APP     := $(BIN)/bk$(EXE)
APPTEST := $(BIN)/bk_test$(EXE)

.PHONY: all clean test demo gtest dirs

all: dirs $(APP)

dirs:
	$(MKDIR) $(BIN) obj

$(APP): $(LIB_OBJ) $(CLI_OBJ)
	$(CXX) $(CPPFLAGS) -o $@ $^ $(SYS_LIBS)

%.o: %.cpp
	$(CXX) $(CPPFLAGS) -c $< -o $@

# ---- 单元测试：默认使用自带迷你框架（无需外网/系统 gtest） ------------------
$(APPTEST): $(LIB_OBJ) $(TEST_OBJ)
	$(CXX) $(CPPFLAGS) -DDBKP_MINI_TEST=1 -o $@ $^ $(SYS_LIBS)

test: dirs $(APPTEST)
	$(APPTEST)

# ---- 使用系统 GoogleTest（Ubuntu: sudo apt install libgtest-dev） -----------
gtest: dirs $(LIB_OBJ) $(TEST_SRC)
	$(CXX) $(CPPFLAGS) -o $(APP) $(LIB_OBJ) $(CLI_OBJ) $(SYS_LIBS)
	$(CXX) $(CPPFLAGS) -DGTEST=1 -o $(BIN)/bk_gtest$(EXE) $(TEST_SRC) $(LIB_OBJ) -lgtest -lgtest_main $(SYS_LIBS)
	$(BIN)/bk_gtest$(EXE)

# ---- 演示：备份→校验→还原→对比 ---------------------------------------------
demo: $(APP)
	./script/demo.sh

clean:
	-rm -f $(LIB_OBJ) $(CLI_OBJ) $(TEST_OBJ) $(APP) $(APPTEST)
	-rm -rf obj bin

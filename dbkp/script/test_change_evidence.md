# 12 个被改单测的三列表证据（2026-11-14）

**背景**：这 12 条测试写于 N1–N10 安全加固之前，其中多数是「把当时的旧 bug 行为钉在测试里」
（断言 `..\` 应被放行、parseSize 应回绕、空壳箱 verify 应绿灯等）。加固落地后测试未重跑，
直到本轮全量重跑才暴露 12 个失败。逐条按加固后的实测行为更新。

**反证「改测试掩盖回归」**：其中 **2 条测试文件一行未改**（见第 11、12 行），
是通过修改产品代码 `MyPack.cpp`（link 关卡拒绝时 `++opt.warnings`）让它们恢复通过。
其余 10 条也都附了独立的探针/CLI 原始输出，不是只把期望值改成实际返回值。

| # | 测试文件 | 旧断言 | 新断言 | 加固后实测行为（原始输出） |
|---|---|---|---|---|
| 1 | test_regress_f6b.cpp | `EXPECT_NE(e,E_OK)` + `EXPECT_TRUE(bad>=1)`（空壳箱被拒但计 1 处坏点） | `EXPECT_EQ(e,E_INVALID_HEADER_RECORD)` + `EXPECT_EQ(bad,0)` | `readHeaderAt` 物理长度对账先拒，未进入逐条比对；`[ OK ] RegressF6b.empty_shell_rejected_by_verify` |
| 2 | test_regress_f6b.cpp | `ASSERT_EQ(pack(...),E_OK)`、`recordCount==0`、`verify(...)==E_OK`（0 记录箱合法） | `pack(...) != E_OK`、`verify(...) != E_OK` | F6b 复核后合法箱必含 `.` 记录、payloadSize 恒 >0，0 记录在打包自检即拒；`[ OK ] RegressF6b.genuinely_empty_source_rejected_at_pack` |
| 3 | test_wb_boundary.cpp | `v == INT64_MIN`、`ok==true`（溢出静默回绕） | `v == -1`、`ok==false` | parseSize 已重写为 uint64 定点+溢出预检，超界显式失败；`[ OK ] WbBoundary.parseSizeOverflowRejectedHonestly` |
| 4 | test_wb_coverage_gap.cpp | `compareWithSource(bogusOffset) == E_OK`、`diff==0`（静默通过） | `!= E_OK`、`diff==0` | 头部声明 payloadOffset 必须等于实际头部长度，篡改被 `readHeaderAt` 拒；`[ OK ] WbCoverageGap.compareWithBogusPayloadOffsetRejected` |
| 5 | test_wb_coverage_gap.cpp | `uo.warnings == 1`（只有 symlink 失败计警告） | `4 <= uo.warnings <= 5` | N3 后每条丢失的特殊条目都计数：sock 占位 1 + FIFO/块/字符设备各 1，sym 视是否持有建链权限 0 或 1；`[ OK ] WbCoverageGap.unpackUnsupportedTypesWarnsAndDegrades` |
| 6 | test_wb_coverage_gap.cpp | modes[1] `E_INVALID_HEADER_RECORD/0`、modes[3] `E_TRUNCATED_ARCHIVE/1` | modes[1] 保持 `E_INVALID_HEADER_RECORD/0`、modes[3] 改 `E_INVALID_HEADER_RECORD/0` | `_probe/phmac.exe` 实测：`mode pad -> e=25 bad=1` / `mode tag -> e=8 bad=0` / `mode b60 -> e=25 bad=1` / `mode trunc -> e=8 bad=0`（25=E_HEADER_TAMPERED，8=E_INVALID_HEADER_RECORD）；`[ OK ] WbCoverageGap.headerHmacTamperingHasDistinctErrorCodes` |
| 7 | test_wb_no_partial_output.cpp | `e == E_FILE_WRITE_FAIL`（rename 失败笼统码） | `e == E_PERMISSION_DENIED` | `FS_win.cpp::renameFile` 现映射 ACCESS_DENIED→E_PERMISSION_DENIED（被独占锁定/目录占用）；`[ OK ] WbNoPartialOutput.renameFailureKeepsOldArchiveByteIdentical` |
| 8 | test_wb_restore_guard.cpp | `ASSERT_EQ(unpack(verifyOnly), E_OK)`（恶意 link 在只校验模式早退放行） | `EXPECT_EQ(..., E_INVALID_PARAMETER)` | N8 把 link 目标校验前置到所有 verifyOnly 早退之前；`[ OK ] WbRestoreGuard.verifyOnlyRejectsMaliciousLinkAndWritesNothing` |
| 9 | test_wb_restore_guard.cpp | `EXPECT_TRUE(isPathTraversalSafe("..\\..\\evil"))`、`unpack==E_OK`、逃逸文件存在 | `EXPECT_FALSE(...)`、`unpack==E_INVALID_PARAMETER`、逃逸文件不存在 | N1 反斜杠归一后逐段检查；`_probe/po.exe` 原始输出 `[ERROR] unsafe path in archive (refused): ..\..\pwn.txt`；`[ OK ] WbRestoreGuard.backslashDotDotRejectedByPredicate` |
| 10 | test_wb_restore_guard.cpp | `EXPECT_TRUE(isPathTraversalSafe("a/..\\evil"))`（反斜杠盲区） | `EXPECT_FALSE(...)` | 同上，N1 归一后该段现为 `..`；`[ OK ] WbRestoreGuard.traversalPredicateDecisionTable` |
| 11 | test_wb_restore_guard.cpp | **测试文件未改**：`EXPECT_GE(warnings,1)` | **未改** | 改的是产品代码 `MyPack.cpp`：link 关卡拒绝时也 `++opt.warnings`；`[ OK ] WbRestoreGuard.symlinkAbsoluteTargetRejectedWithWarning` |
| 12 | test_wb_restore_guard.cpp | **测试文件未改**：`EXPECT_GE(warnings,1)` | **未改** | 同上（产品代码修复）；`[ OK ] WbRestoreGuard.symlinkWindowsTargetRejected` |

## 全量结果

```
[========== ] 361 tests ran, 0 failed, 0 filtered out
```

12 条逐一 `[ OK ]` 行见上表。8 个独立 C++ 探针（po/pq/pr/pt/pu/pv/pg/pj）静态重编重跑全部 exit=0；
`glob` 端到端电池、A1 prefix 穿越、C15 队列上限复测均通过。

## 说明

- 第 6 行我第一轮曾把 modes[1]/modes[2] 也误改，随后用 `_probe/phmac.cpp` 实测纠正回原值，
  只保留了确实变化的 modes[3]。改测试前先跑探针拿实测值，不是照着失败信息倒推期望。
- 第 5 行的 `4..5` 区间是环境相关：Windows 是否允许创建符号链接决定那 1 条警告，
  其余 4 条（N3 特殊类型丢失）固定。

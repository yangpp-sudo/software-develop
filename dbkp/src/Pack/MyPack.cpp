/* ============================================================================
 *  MyPack.cpp  -- 归档写入/读取主体
 * ==========================================================================*/
#include "Pack/MyPack.h"

#include <algorithm>
#include <cstring>
#include <ctime>
#include <memory>

#include "Common/Serialize.h"
#include "Crypto/Algorithms.h"    /* F3：fillSalt 改走 fillRandom（系统 CSPRNG） */
#include "Crypto/Sha256.h"
#include "Platform/FS.h"
#include "Utils/CRC64.h"
#include "Utils/Logger.h"
#include "Utils/PathUtil.h"

namespace DBKP {

namespace {

uint64_t blocksFor(int64_t bytes) {
    return bytes <= 0 ? 0 : uint64_t((bytes + BLOCK_SIZE - 1) / BLOCK_SIZE);
}

std::string absOf(const std::string& root, const std::string& rel) {
    if (rel == "." || rel.empty()) return root;
    return Path::normalize(root + "/" + rel);
}

/* F3 修复：KDF salt 原为 time()+栈地址播种的 xorshift，与 fillRandom 同款弱随机。
 * 统一改走 fillRandom（Windows: BCryptGenRandom；POSIX: getrandom/urandom）。 */
void fillSalt(uint8_t salt[16]) {
    fillRandom(salt, 16);
}

/** 由遍历结果生成头记录（含元数据标志位） */
FileRecord makeRecord(const EnumeratedEntry& ent) {
    FileRecord rec;
    const Platform::FileInfo& fi = ent.info;
    rec.path = ent.relPath;
    rec.type = fi.type;
    rec.mode = fi.mode;
    rec.uid  = fi.uid;
    rec.gid  = fi.gid;
    rec.mtimeSec = fi.mtimeSec;  rec.mtimeNSec = fi.mtimeNSec;
    rec.atimeSec = fi.atimeSec;  rec.atimeNSec = fi.atimeNSec;
    rec.ctimeSec = fi.ctimeSec;
    rec.ino = fi.ino;
    rec.nlink = fi.nlink ? fi.nlink : 1;
    rec.dev = fi.dev;
    rec.majorNum = fi.majorNum;
    rec.minorNum = fi.minorNum;
    rec.size = fi.size;
    rec.flags = static_cast<uint8_t>(RF_META_MODE | RF_META_TIME | RF_CRC_VALID);
    if (Platform::supportsOwner()) rec.flags = static_cast<uint8_t>(rec.flags | RF_META_UID);
    if (rec.type == FT_SYMLINK) rec.link = fi.linkTarget;
    return rec;
}

} /* anonymous namespace */

IDataCodec* CMyPack::makeComp(AlgorithmId id, std::string& errText) const {
    if (id == ALG_NONE) return nullptr;
    IDataCodec* c = CompressionFactory::create(id);
    if (!c) errText = std::string("unknown compression algorithm: ") + algorithmName(id);
    return c;
}

IDataCodec* CMyPack::makeCrypto(CryptoId id, const std::string& password,
                                const uint8_t salt[16], int rounds,
                                std::string& errText) const {
    if (id == CRY_NONE || password.empty()) return nullptr;
    IDataCodec* c = CryptoFactory::create(id, password, salt, rounds);
    if (!c) errText = std::string("unknown crypto algorithm: ") + cryptoName(id);
    return c;
}

/* ------------------------------------------------------------ 打包 */
ErrCode CMyPack::pack(const std::string& sourceDir, const std::string& archivePath,
                      const PackOptions& opt) {
    m_errorText.clear();
    if (sourceDir.empty() || archivePath.empty()) return E_INVALID_PARAMETER;

    /* ---------------- F4：原子写前置检查 ----------------
       正式箱从头到尾不被就地改写：所有内容由 "<archive>.tmp" 承载，写完整、
       校验通过后才 rename 替换正式名。tmp 同时就是"进行中"标记（F6b）：
       启动时它还在，说明上次备份被打断/杀死，必须显式 --force 才继续。 */
    const std::string tmpPath = archivePath + ".tmp";

    if (Platform::exists(archivePath) == E_OK && !opt.force) {
        m_errorText = "archive already exists: " + archivePath + " (use --force to overwrite)";
        LOG_ERR(m_errorText);
        return E_ALREADY_EXISTS;
    }
    if (Platform::exists(tmpPath) == E_OK && !opt.force) {
        m_errorText = "previous backup incomplete (temp file present): " + tmpPath +
                      " (use --force to discard it and retry)";
        LOG_ERR(m_errorText);
        return E_INCOMPLETE;
    }

    std::unique_ptr<IDataCodec> comp(makeComp(opt.comp, m_errorText));
    if (!comp && opt.comp != ALG_NONE) { LOG_ERR(m_errorText); return E_INVALID_PARAMETER; }

    uint8_t salt[16];
    fillSalt(salt);
    const int kdfRounds = 4096;
    if (opt.crypto != CRY_NONE && opt.password.empty()) {
        LOG_ERR("crypto requested but no password given");
        return E_INVALID_PARAMETER;
    }
    std::unique_ptr<IDataCodec> crypto(
        makeCrypto(opt.crypto, opt.password, salt, kdfRounds, m_errorText));
    if (!crypto && opt.crypto != CRY_NONE) { LOG_ERR(m_errorText); return E_INVALID_PARAMETER; }

    /* 1. 先序枚举（含根目录自身 "."）。
       F9：归档目标（含 .tmp）若落在源目录内，必须从扫描中排除——否则下一轮
       备份会把上一轮的箱装进箱里，体积逐轮膨胀且永远备不完。 */
    CFileEnumerator enumerator;
    {
        std::set<std::string> excluded;
        std::string canon;
        if (DBKP_IS_ERR(Platform::canonicalPath(archivePath, canon))) canon = archivePath;
        excluded.insert(Path::normalize(canon));
        if (DBKP_IS_ERR(Platform::canonicalPath(tmpPath, canon))) canon = tmpPath;
        excluded.insert(Path::normalize(canon));
        enumerator.setExcludedAbsPaths(excluded);
    }
    std::vector<EnumeratedEntry> entries;
    ErrCode e = enumerator.enumerateFiles(sourceDir, opt.filter, entries);
    if (DBKP_IS_ERR(e)) return e;

    /* 进度上报：枚举完成后就能算出总字节，前端立刻得到可信的百分比 */
    uint64_t planBytes = 0;
    if (opt.progress) {
        for (size_t i = 0; i < entries.size(); ++i)
            if (entries[i].info.type == FT_REGULAR)
                planBytes += static_cast<uint64_t>(entries[i].info.size < 0 ? 0 : entries[i].info.size);
        opt.progress->onStart(static_cast<int64_t>(entries.size()), planBytes);
    }

    std::string absSource;
    if (DBKP_IS_ERR(Platform::canonicalPath(sourceDir, absSource)))
        absSource = Path::normalize(sourceDir);

    /* 2. 卷标占位，最后回填计数与 CRC —— 全部写进 tmp 文件。
       打开顺序刻意设计为"无 O_TRUNC 打开 → 加跨进程独占锁 → 显式截断"：
       两个进程同时备份同一目标时，后到者在锁上失败（E_BUSY），
       绝不会出现互相将对方刚写的数据截掉的情况（F4 验收①）。
       残留的旧 tmp 不需要先删：拿到锁后 truncate(0) 就把它洗干净了，
       而"先删后开"在 Windows 上会连带删掉别人正在写的句柄，是错误做法。 */
    CSimpleFile out;
    e = out.open(tmpPath, CSimpleFile::MODE_READ_WRITE_CREATE);
    if (DBKP_IS_ERR(e)) {
        m_errorText = "cannot create archive temp: " + tmpPath;
        LOG_ERR(m_errorText);
        return e;
    }
    e = Platform::tryLockFile(out.fd());
    if (DBKP_IS_ERR(e)) {
        out.close();
        m_errorText = "archive is locked by another backup process: " + archivePath;
        LOG_ERR(m_errorText);
        return e;
    }
    e = Platform::truncateFile(out.fd(), 0);
    if (DBKP_IS_ERR(e)) {
        Platform::unlockFile(out.fd());
        out.close();
        Platform::removeFile(tmpPath);
        m_errorText = "cannot reset archive temp: " + tmpPath;
        LOG_ERR(m_errorText);
        return e;
    }

    /* 安全垫：rename 提交之前任何提前 return（错误/取消）都清掉 tmp，
       绝不在正式名旁留下残骸（F4/F6b 验收"正式名下无残骸"）。
       Windows 上删除仍被句柄打开的文件会失败，所以先显式 close（幂等），
       锁也随句柄关闭自动释放。 */
    struct TmpGuard {
        const std::string& m_tmp;
        CSimpleFile* m_out;
        bool m_committed = false;
        ~TmpGuard() {
            if (m_committed) return;
            m_out->close();
            if (Platform::exists(m_tmp) == E_OK) Platform::removeFile(m_tmp);
        }
    };
    TmpGuard tmpGuard = { tmpPath, &out };

    ArchiveHeader hdr;
    hdr.compAlg   = static_cast<uint8_t>(comp ? opt.comp : ALG_NONE);
    hdr.cryptoAlg = static_cast<uint8_t>(crypto ? opt.crypto : CRY_NONE);
    hdr.checksum  = static_cast<uint8_t>(opt.checksum);
    hdr.createTime = static_cast<uint64_t>(std::time(nullptr));
    hdr.sourcePath = absSource;
    hdr.comment    = opt.comment;
    /* sha256 卷标多占一个 512B 扩展块放摘要，载荷起点随之后移 */
    hdr.payloadOffset = (opt.checksum == CHK_SHA256) ? ARCHIVE_HEADER_EXT : BLOCK_SIZE;
    hdr.kdfRounds = static_cast<uint16_t>(kdfRounds);
    std::memcpy(hdr.salt, salt, 16);

    std::vector<uint8_t> block;
    encodeArchiveHeader(hdr, block);
    e = out.writeN(block.data(), static_cast<int64_t>(block.size()));
    if (DBKP_IS_ERR(e)) {
        m_errorText = "write archive header failed";
        LOG_ERR(m_errorText);
        out.close();
        Platform::removeFile(tmpPath);
        return e;
    }

    /* 3. 逐条：数据块在前、头记录在后？ 统一为"头记录 + 数据块"，与讲义一致 */
    m_inodeMap.clear();
    uint64_t recordCount = 0, fileCount = 0, rawTotal = 0, storedTotal = 0;
    uint64_t doneBytes = 0;
    bool       canceled = false;
    for (size_t i = 0; i < entries.size(); ++i) {
        FileRecord rec = makeRecord(entries[i]);
        const Platform::FileInfo& fi = entries[i].info;
        ++fileCount;

        bool asHardLink = false;
        if (opt.hardlinkDedupe && fi.type == FT_REGULAR && fi.nlink > 1 && fi.ino != 0) {
            InodeKey key; key.dev = fi.dev; key.ino = fi.ino;
            std::map<InodeKey, std::string>::const_iterator it = m_inodeMap.find(key);
            if (it != m_inodeMap.end()) {
                rec.type = FT_HARDLINK;
                rec.link = it->second;
                rec.flags = static_cast<uint8_t>(rec.flags & ~RF_CRC_VALID);
                asHardLink = true;
            } else {
                m_inodeMap[key] = rec.path;
                rec.flags = static_cast<uint8_t>(rec.flags | RF_HARDLINK_SRC);
            }
        }

        if (asHardLink) {
            rec.size = 0; rec.storedSize = 0;
            rec.flags = static_cast<uint8_t>(rec.flags & ~RF_CRC_VALID);
            e = writeRecord(out, rec);
        } else if (fi.type == FT_REGULAR && fi.size > 0) {
            e = writeFileData(out, absOf(absSource, rec.path), rec, comp.get(), crypto.get(), opt);
        } else {
            /* 目录 / 空文件 / 符号链接 / 特殊文件：无数据块 */
            rec.storedSize = 0;
            if (fi.type != FT_REGULAR) rec.size = 0;
            if (fi.type == FT_DIR) rec.crc = 0;
            e = writeRecord(out, rec);
        }
        if (DBKP_IS_ERR(e)) {
            m_errorText = "failed packing: " + rec.path + " (" + errCodeToString(e) + ")";
            LOG_ERR(m_errorText);
            return e;
        }
        ++recordCount;
        rawTotal    += static_cast<uint64_t>(rec.size);
        storedTotal += static_cast<uint64_t>(rec.storedSize);
        if (opt.progress) {
            if (fi.type == FT_REGULAR && !asHardLink && fi.size > 0)
                doneBytes += static_cast<uint64_t>(fi.size);
            opt.progress->onProgress(static_cast<int64_t>(i + 1), doneBytes);
            if (opt.progress->canceled()) { canceled = true; break; }
        }
        if ((i + 1) % 1024 == 0) LOG_INFO("packed " + std::to_string(i + 1) + " entries");
    }

    /* 取消：close 释放锁，tmpGuard 删掉半成品——正式名下的旧箱纹丝不动，
       也绝不留一个"看起来成功"的归档（失败必须显式）。 */
    if (canceled) {
        out.close();
        m_errorText = "backup canceled by user";
        LOG_WARN(m_errorText);
        return E_CANCELED;
    }

    /* 4. 回填卷标：条目数、原始/编码字节数、整段载荷 CRC（sha256 模式还要算整卷摘要） */
    const int64_t endPos = out.tell();
    const int64_t hdrBytes = static_cast<int64_t>(hdr.payloadOffset);
    uint64_t payloadBytes = endPos > hdrBytes
                          ? static_cast<uint64_t>(endPos - hdrBytes) : 0;
    CRC64 payloadCrc;
    CSha256 payloadSha;
    const bool wantSha = hdr.checksum == CHK_SHA256;
    {
        std::vector<uint8_t> buf;
        buf.resize(64 * 1024);
        out.seekTo(hdrBytes);
        uint64_t done = 0;
        while (done < payloadBytes) {
            int64_t want = static_cast<int64_t>(
                std::min<uint64_t>(payloadBytes - done, static_cast<uint64_t>(buf.size())));
            ErrCode re = out.readN(buf.data(), want);
            if (DBKP_IS_ERR(re)) { LOG_WARN("payload checksum pass incomplete"); break; }
            payloadCrc.update(buf.data(), static_cast<size_t>(want));
            if (wantSha) payloadSha.update(buf.data(), static_cast<size_t>(want));
            done += static_cast<uint64_t>(want);
        }
    }
    hdr.payloadSize = payloadBytes;
    hdr.payloadCrc  = payloadCrc.value();
    if (wantSha) {
        hdr.payloadDigest.resize(CSha256::kDigestSize);
        payloadSha.finish(hdr.payloadDigest.data());
    }
    hdr.rawSize     = rawTotal;
    hdr.recordCount = recordCount;
    hdr.fileCount   = fileCount;
    encodeArchiveHeader(hdr, block);
    out.seekTo(0);
    e = out.writeN(block.data(), static_cast<int64_t>(block.size()));
    if (DBKP_IS_ERR(e)) {
        m_errorText = "rewrite archive header failed";
        LOG_ERR(m_errorText);
        out.close();
        Platform::removeFile(tmpPath);
        return e;
    }
    ErrCode fe = out.flush();
    ErrCode ce = out.close();
    /* 锁随 close 释放；此后 tmp 已完整落盘，正式名仍未被动过 */
    if (DBKP_IS_ERR(fe) || DBKP_IS_ERR(ce)) {
        m_errorText = "failed to finalize archive temp: " + tmpPath;
        LOG_ERR(m_errorText);
        Platform::removeFile(tmpPath);
        return DBKP_IS_ERR(fe) ? fe : ce;
    }

    /* 5. F4 提交前自校验：tmp 写完立刻按正式归档标准 verify 一遍，
       校验不过绝不 rename——保证正式名下永远只有"完整且自洽"的箱。 */
    {
        ArchiveHeader vh;
        ErrCode ve = readHeader(tmpPath, vh);
        if (DBKP_IS_ERR(ve)) {
            m_errorText = "archive temp header invalid before commit";
            LOG_ERR(m_errorText);
            Platform::removeFile(tmpPath);
            return ve;
        }
        ve = checkWholePayload(tmpPath, vh);
        if (DBKP_IS_ERR(ve)) {
            m_errorText = "archive temp failed self-verify before commit";
            LOG_ERR(m_errorText);
            Platform::removeFile(tmpPath);
            return ve;
        }
    }

    /* 6. 原子替换：MoveFileEx(REPLACE_EXISTING) / rename()。
       崩溃/kill 只可能发生在 rename 前（旧箱完好）或 rename 后（新箱完好），
       不存在"半新半旧"的中间态。 */
    e = Platform::renameFile(tmpPath, archivePath);
    if (DBKP_IS_ERR(e)) {
        m_errorText = "atomic rename failed: " + tmpPath + " -> " + archivePath;
        LOG_ERR(m_errorText);
        Platform::removeFile(tmpPath);
        return e;
    }
    tmpGuard.m_committed = true;   /* 提交成功，残骸清理责任解除 */

    LOG_INFO("archive written: " + std::to_string(fileCount) + " entries, " +
             std::to_string(rawTotal) + " -> " + std::to_string(storedTotal) +
             " bytes (payload " + std::to_string(payloadBytes) + ")");
    return E_OK;
}

/* ------------------------------------------------------------ 写一条记录 */
ErrCode CMyPack::writeRecord(CSimpleFile& out, const FileRecord& rec) {
    std::vector<uint8_t> bytes;
    ErrCode e = encodeRecord(rec, bytes);
    if (DBKP_IS_ERR(e)) return e;
    return out.writeN(bytes.data(), static_cast<int64_t>(bytes.size()));
}

/* ------------------------------------------------------------ 写一个文件的数据区 */
ErrCode CMyPack::writeFileData(CSimpleFile& out, const std::string& absPath, FileRecord& rec,
                               IDataCodec* comp, IDataCodec* crypto, const PackOptions& opt) {
    /* 1. 读原始数据 */
    std::vector<uint8_t> raw;
    ErrCode e = CSimpleFile::readWhole(absPath, raw);
    if (DBKP_IS_ERR(e)) { LOG_WARN("cannot read file content: " + absPath); return e; }
    rec.size = static_cast<int64_t>(raw.size());
    rec.crc  = CRC64::compute(raw.data(), raw.size());
    rec.flags = static_cast<uint8_t>(rec.flags | RF_CRC_VALID);

    const bool tooBig = static_cast<int64_t>(raw.size()) > opt.codecThreshold;
    std::vector<uint8_t> payload = raw;
    rec.compAlg = ALG_NONE;
    rec.cryptoAlg = CRY_NONE;

    /* 2. 先压缩 */
    if (comp && !tooBig) {
        std::vector<uint8_t> mid;
        ErrCode ce = comp->encode(payload, mid);
        if (DBKP_IS_ERR(ce)) {
            LOG_WARN("compress failed for " + rec.path + ", store as-is");
        } else if (mid.size() + BLOCK_SIZE >= payload.size()) {
            /* 压缩后反而更大（已压缩数据/随机数据）：退回不压缩，省 CPU 也省空间 */
            LOG_DEBUG("compression not profitable for " + rec.path);
        } else {
            payload.swap(mid);
            rec.compAlg = static_cast<uint8_t>(opt.comp);
        }
    }
    /* 3. 后加密 */
    if (crypto) {
        std::vector<uint8_t> enc;
        ErrCode ce = crypto->encode(payload, enc);
        if (DBKP_IS_ERR(ce)) { LOG_ERR("encrypt failed for " + rec.path); return ce; }
        payload.swap(enc);
        rec.cryptoAlg = static_cast<uint8_t>(opt.crypto);
    }

    /* 4. 写头记录（含 storedSize）再写 512B 对齐的数据块 */
    rec.storedSize = static_cast<int64_t>(payload.size());
    e = writeRecord(out, rec);
    if (DBKP_IS_ERR(e)) return e;

    const uint64_t blocks = blocksFor(rec.storedSize);
    std::vector<uint8_t> block;
    for (uint64_t b = 0; b < blocks; ++b) {
        const size_t off = static_cast<size_t>(b * BLOCK_SIZE);
        const size_t n = static_cast<size_t>(
            std::min<uint64_t>(BLOCK_SIZE, static_cast<uint64_t>(payload.size()) - off));
        block.assign(BLOCK_SIZE, 0);
        if (n) std::memcpy(block.data(), payload.data() + off, n);
        ErrCode we = out.writeN(block.data(), BLOCK_SIZE);
        if (DBKP_IS_ERR(we)) return we;
    }
    return E_OK;
}

/* ------------------------------------------------------------ 读数据区 */
ErrCode CMyPack::readDataBlocks(CSimpleFile& in, const FileRecord& rec,
                                std::vector<uint8_t>& rawOut,
                                IDataCodec* comp, IDataCodec* crypto,
                                const std::string& password, UnpackOptions& opt) {
    DBKP_UNUSED(password);
    const uint64_t blocks = blocksFor(rec.storedSize);
    std::vector<uint8_t> enc;
    if (blocks) {
        enc.resize(static_cast<size_t>(blocks * BLOCK_SIZE));
        ErrCode e = in.readN(enc.data(), static_cast<int64_t>(enc.size()));
        if (DBKP_IS_ERR(e)) { LOG_ERR("archive truncated at: " + rec.path); return E_TRUNCATED_ARCHIVE; }
        if (rec.storedSize < static_cast<int64_t>(enc.size()))
            enc.resize(static_cast<size_t>(rec.storedSize));
    }

    std::vector<uint8_t> work = enc;
    /* 1. 解密（与打包顺序相反：先解密，后解压） */
    if (rec.cryptoAlg != CRY_NONE) {
        if (!crypto) { LOG_ERR("archive is encrypted but no cipher available"); return E_CRYPTO_FAIL; }
        std::vector<uint8_t> plain;
        ErrCode e = crypto->decode(work, plain);
        if (DBKP_IS_ERR(e)) {
            LOG_ERR("decrypt failed for " + rec.path + " (" + errCodeToString(e) + ")");
            return e;
        }
        work.swap(plain);
    }
    /* 2. 解压 */
    if (rec.compAlg != ALG_NONE) {
        if (!comp) { LOG_ERR("archive is compressed but no codec available"); return E_COMPRESS_FAIL; }
        std::vector<uint8_t> plain;
        ErrCode e = comp->decode(work, plain);
        if (DBKP_IS_ERR(e)) {
            LOG_ERR("decompress failed for " + rec.path + " (" + errCodeToString(e) + ")");
            return e;
        }
        work.swap(plain);
    }
    /* 3. 校验原始数据 CRC64 */
    if (rec.flags & RF_CRC_VALID) {
        uint64_t got = CRC64::compute(work.data(), work.size());
        if (got != rec.crc) {
            LOG_ERR("checksum mismatch: " + rec.path + " (expect " +
                    CRC64::toString(rec.crc) + ", got " + CRC64::toString(got) + ")");
            ++opt.warnings;
            return E_CHECKSUM_MISMATCH;
        }
        /* 记录里的 size 字段也要和解出来的长度对得上：只过 CRC 不卡 size，
           篡改字段就只能靠整卷摘要拦（明文 sha256 归档的盲区之一） */
        if (rec.size != static_cast<int64_t>(work.size())) {
            LOG_ERR("size field mismatch: " + rec.path + " (header says " +
                    std::to_string(rec.size) + ", decoded " + std::to_string(work.size()) + ")");
            ++opt.warnings;
            return E_CHECKSUM_MISMATCH;
        }
    } else if (rec.storedSize == rec.size && rec.size != static_cast<int64_t>(work.size())) {
        LOG_ERR("size mismatch: " + rec.path);
        return E_CHECKSUM_MISMATCH;
    }
    rawOut.swap(work);
    return E_OK;
}

/* ------------------------------------------------------------ 恢复一个条目 */
ErrCode CMyPack::restoreEntry(const std::string& targetDir, const FileRecord& rec,
                              const std::vector<uint8_t>* data, UnpackOptions& opt,
                              std::vector<FileRecord>& pendingDirs) {
    if (rec.path != "." && !Path::isPathTraversalSafe(rec.path)) {
        LOG_ERR("unsafe path in archive (refused): " + rec.path);
        return E_INVALID_PARAMETER;
    }
    const std::string absPath = absOf(targetDir, rec.path);
    const std::string parent  = Path::parentDir(absPath);

    if (rec.type == FT_DIR) {
        if (!opt.verifyOnly) {
            ErrCode e = Platform::makeDirTree(absPath);
            if (DBKP_IS_ERR(e) && e != E_ALREADY_EXISTS) {
                LOG_WARN("cannot create directory: " + absPath);
                ++opt.warnings;
            }
            pendingDirs.push_back(rec);
        }
        return E_OK;
    }

    if (rec.type == FT_REGULAR) {
        if (opt.verifyOnly) return E_OK;
        if (!parent.empty()) Platform::makeDirTree(parent);
        CSimpleFile f;
        ErrCode e = f.open(absPath, CSimpleFile::MODE_WRITE_NEW);
        if (DBKP_IS_ERR(e)) {
            LOG_WARN("cannot create file: " + absPath + " (" + errCodeToString(e) + ")");
            ++opt.warnings;
            return e;
        }
        if (data && !data->empty()) {
            e = f.writeN(data->data(), static_cast<int64_t>(data->size()));
            if (DBKP_IS_ERR(e)) { LOG_ERR("write failed: " + absPath); return e; }
        }
        ErrCode fe = f.flush();
        ErrCode ce = f.close();
        if (DBKP_IS_ERR(fe) || DBKP_IS_ERR(ce)) return E_FILE_WRITE_FAIL;
        applyMetadata(absPath, rec, opt, true);
        return E_OK;
    }

    if (rec.type == FT_SYMLINK) {
        if (opt.verifyOnly) return E_OK;
        /* F1 修法第 4 点（F21）：归档里的 link 目标同样是不可信输入。
           绝对路径（"C:/x"、"/x"、"\\server\x"）或含 ".." 的相对值一旦照建，
           还原出的链接就能把后续读写引到目标目录之外。path 字段早就有
           isPathTraversalSafe 把关，link 字段以前是"任意值照建"。 */
        if (!Path::isPathTraversalSafe(rec.link)) {
            LOG_ERR("unsafe link target in archive (refused): " + rec.path +
                    " -> " + rec.link);
            ++opt.warnings;
            return E_INVALID_PARAMETER;
        }
        if (!parent.empty()) Platform::makeDirTree(parent);
        if (!Platform::supportsSymlink()) {
            LOG_WARN("symbolic links unsupported here, skip: " + rec.path);
            ++opt.warnings;
            return E_OK;
        }
        ErrCode e = Platform::makeSymlink(rec.link, absPath);
        if (DBKP_IS_ERR(e)) {
            LOG_WARN("cannot create symlink " + rec.path + " -> " + rec.link +
                     " (" + errCodeToString(e) + ")");
            ++opt.warnings;
        } else {
            /* 讲义缺陷修复：符号链接元数据不能作用到目标文件上 */
            applyMetadata(absPath, rec, opt, false);
        }
        return E_OK;
    }

    if (rec.type == FT_HARDLINK) {
        if (opt.verifyOnly) return E_OK;
        if (!parent.empty()) Platform::makeDirTree(parent);
        ErrCode e = Platform::makeHardLink(absOf(targetDir, rec.link), absPath);
        if (DBKP_IS_ERR(e)) {
            LOG_WARN("cannot recreate hard link " + rec.path + " -> " + rec.link +
                     " (" + errCodeToString(e) + ")");
            ++opt.warnings;
        }
        return E_OK;
    }

    /* 特殊文件：FIFO / 块设备 / 字符设备 / 套接字 */
    if (opt.verifyOnly) return E_OK;
    if (!parent.empty()) Platform::makeDirTree(parent);
    if (rec.type == FT_FIFO) {
        ErrCode e = Platform::makeFifo(absPath, rec.mode);
        if (e == E_UNSUPPORTED_FEATURE) LOG_WARN("FIFO unsupported, skip: " + rec.path);
        else if (DBKP_IS_ERR(e)) LOG_WARN("cannot create FIFO: " + rec.path);
        else applyMetadata(absPath, rec, opt, true);
    } else if (rec.type == FT_BLOCK || rec.type == FT_CHAR) {
        ErrCode e = Platform::makeDeviceNode(absPath, rec.type, rec.majorNum, rec.minorNum, rec.mode);
        if (e == E_PERMISSION_DENIED) LOG_WARN("need root for device node: " + rec.path);
        else if (e == E_UNSUPPORTED_FEATURE) LOG_WARN("device node unsupported: " + rec.path);
        else if (DBKP_IS_ERR(e)) LOG_WARN("cannot create device node: " + rec.path);
        else applyMetadata(absPath, rec, opt, true);
    } else if (rec.type == FT_SOCKET) {
        LOG_WARN("unix socket cannot be restored faithfully: " + rec.path);
        Platform::makeSocketPlaceholder(absPath);
    }
    return E_OK;
}

/* ------------------------------------------------------------ 元数据恢复 */
ErrCode CMyPack::applyMetadata(const std::string& absPath, const FileRecord& rec,
                               UnpackOptions& opt, bool followSymlink) {
    if (!opt.restoreMeta) return E_OK;
    if (rec.flags & RF_META_TIME) {
        ErrCode e = Platform::setTimes(absPath, rec.mtimeSec, rec.mtimeNSec,
                                       rec.atimeSec, rec.atimeNSec, followSymlink);
        if (DBKP_IS_ERR(e)) LOG_DEBUG("restore times failed: " + absPath);
    }
    if (rec.flags & RF_META_MODE) {
        ErrCode e = Platform::setMode(absPath, rec.mode);
        if (DBKP_IS_ERR(e)) LOG_DEBUG("restore mode failed: " + absPath);
    }
    if (rec.flags & RF_META_UID) {
        ErrCode e = Platform::setOwner(absPath, rec.uid, rec.gid);
        if (DBKP_IS_ERR(e) && e != E_UNSUPPORTED_FEATURE)
            LOG_DEBUG("restore owner failed: " + absPath);
    }
    return E_OK;
}

/* ------------------------------------------------------------ 读取卷标 */
ErrCode CMyPack::readHeaderAt(CSimpleFile& in, ArchiveHeader& hdr) {
    std::vector<uint8_t> block;
    block.resize(BLOCK_SIZE);
    if (DBKP_IS_ERR(in.seekTo(0))) return E_TRUNCATED_ARCHIVE;
    ErrCode e = in.readN(block.data(), BLOCK_SIZE);
    if (DBKP_IS_ERR(e)) return E_TRUNCATED_ARCHIVE;
    /* checksum=sha256 的归档卷标后面跟一个摘要扩展块，一并读进来。
       必须先确认第一块魔数正常再决定读扩展块：否则遇到非归档文件时，
       第 6 字节的 headerSize 会读成随机大值（例如 'zz' = 31354），于是
       去读第二块并在 EOF 处失败，把“这不是归档”误报成 E_TRUNCATED_ARCHIVE。 */
    std::vector<uint8_t> ext;
    if (readLE32(block.data()) == ARCHIVE_MAGIC &&
        readLE16(block.data() + 6) >= ARCHIVE_HEADER_EXT) {
        ext.resize(BLOCK_SIZE);
        if (DBKP_IS_ERR(in.readN(ext.data(), BLOCK_SIZE))) return E_TRUNCATED_ARCHIVE;
    }
    return decodeArchiveHeader(block.data(), hdr, ext.empty() ? nullptr : ext.data());
}

ErrCode CMyPack::readHeader(const std::string& archivePath, ArchiveHeader& hdr) {
    CSimpleFile in;
    ErrCode e = in.open(archivePath, CSimpleFile::MODE_READ);
    if (DBKP_IS_ERR(e)) return e;
    return readHeaderAt(in, hdr);
}

/* -------------------------------------------------------- 整卷校验辅助 */
ErrCode CMyPack::checkWholePayload(const std::string& archivePath, const ArchiveHeader& hdr) {
    /* F6b：payloadSize==0 但记录区声称有条目——这是"空壳箱"（半成品/人造残骸），
       以前直接返回 E_OK 让 verify 绿灯通过，现在必须拒绝。
       判据取 recordCount 与 fileCount 任一非零：正常备份哪怕源目录为空，
       也至少有根目录 "." 一条记录，两者同时为 0 的箱只可能是空卷标。 */
    if (hdr.payloadSize == 0 && (hdr.recordCount != 0 || hdr.fileCount != 0)) {
        LOG_ERR("archive declares " + std::to_string(hdr.recordCount) +
                " record(s) but carries an empty payload (incomplete archive)");
        return E_TRUNCATED_ARCHIVE;
    }
    if (hdr.checksum == CHK_NONE || hdr.payloadSize == 0) return E_OK;
    CSimpleFile in;
    ErrCode e = in.open(archivePath, CSimpleFile::MODE_READ);
    if (DBKP_IS_ERR(e)) return e;
    if (DBKP_IS_ERR(in.seekTo(static_cast<int64_t>(hdr.payloadOffset)))) return E_TRUNCATED_ARCHIVE;
    CRC64 crc;
    CSha256 sha;
    const bool useSha = hdr.checksum == CHK_SHA256;
    if (useSha && hdr.payloadDigest.size() != CSha256::kDigestSize) {
        /* 旧版 sha256 归档只存了个标志字节，摘要从未落盘：检不出任何记录区篡改。
           这里明说而不是静默跳过，避免用户把“选了 sha256”当成已经有保护。 */
        LOG_ERR("archive declares sha256 but carries no digest (written by an older "
                "version); re-create it to get whole-volume protection");
        return E_INVALID_HEADER_RECORD;
    }
    std::vector<uint8_t> buf;
    buf.resize(64 * 1024);
    uint64_t done = 0;
    while (done < hdr.payloadSize) {
        const int64_t want = static_cast<int64_t>(std::min<uint64_t>(
            hdr.payloadSize - done, static_cast<uint64_t>(buf.size())));
        ErrCode re = in.readN(buf.data(), want);
        if (DBKP_IS_ERR(re)) {
            LOG_ERR("archive truncated during checksum pass");
            return E_TRUNCATED_ARCHIVE;
        }
        crc.update(buf.data(), static_cast<size_t>(want));
        if (useSha) sha.update(buf.data(), static_cast<size_t>(want));
        done += static_cast<uint64_t>(want);
    }
    if (useSha) {
        uint8_t digest[CSha256::kDigestSize];
        sha.finish(digest);
        if (std::memcmp(digest, hdr.payloadDigest.data(), CSha256::kDigestSize) != 0) {
            LOG_ERR("payload sha256 mismatch: expect " + CSha256::toHex(hdr.payloadDigest.data()) +
                    ", got " + CSha256::toHex(digest));
            return E_CHECKSUM_MISMATCH;
        }
        LOG_DEBUG("payload sha256 verified: " + CSha256::toHex(digest));
    } else {
        if (crc.value() != hdr.payloadCrc) {
            LOG_ERR("payload checksum mismatch: expect " + CRC64::toString(hdr.payloadCrc) +
                    ", got " + CRC64::toString(crc.value()));
            return E_CHECKSUM_MISMATCH;
        }
        LOG_DEBUG("payload crc64 verified: " + CRC64::toString(crc.value()));
    }
    return E_OK;
}

/* ------------------------------------------------------------ 解包 */
ErrCode CMyPack::unpack(const std::string& archivePath, const std::string& targetDir,
                        UnpackOptions& opt) {
    m_errorText.clear();
    opt.warnings = 0;
    if (archivePath.empty() || targetDir.empty()) return E_INVALID_PARAMETER;

    CSimpleFile in;
    ErrCode e = in.open(archivePath, CSimpleFile::MODE_READ);
    if (DBKP_IS_ERR(e)) { m_errorText = "cannot open archive: " + archivePath; return e; }

    ArchiveHeader hdr;
    e = readHeaderAt(in, hdr);
    if (DBKP_IS_ERR(e)) { m_errorText = "not a dbkp archive"; return e; }
    if (hdr.version != ARCHIVE_VERSION) {
        LOG_ERR("unsupported archive version " + std::to_string(hdr.version));
        return E_INVALID_HEADER_RECORD;
    }
    if (hdr.compAlg >= ALG_COUNT || hdr.cryptoAlg >= CRY_COUNT) {
        LOG_ERR("corrupted archive header");
        return E_INVALID_HEADER_RECORD;
    }

    std::string errText;
    std::unique_ptr<IDataCodec> comp(makeComp(static_cast<AlgorithmId>(hdr.compAlg), errText));
    std::unique_ptr<IDataCodec> crypto;
    if (hdr.cryptoAlg != CRY_NONE) {
        if (opt.password.empty()) {
            m_errorText = "archive is encrypted, --password is required";
            LOG_ERR(m_errorText);
            return E_WRONG_PASSWORD;
        }
        crypto.reset(makeCrypto(static_cast<CryptoId>(hdr.cryptoAlg), opt.password,
                                hdr.salt, hdr.kdfRounds ? hdr.kdfRounds : 4096, errText));
        if (!crypto) { LOG_ERR(errText); return E_INVALID_PARAMETER; }
    }

    /* 落盘前先过整卷校验（crc64/sha256）：以前只有 verify 命令会查，
       restore 对“记录区被改”完全无感（文件名/时间篡改能静默还原成功）。 */
    if (!opt.verifyOnly && !opt.skipPayloadVerify) {
        ErrCode ce = checkWholePayload(archivePath, hdr);
        if (DBKP_IS_ERR(ce)) {
            m_errorText = "archive failed whole-volume integrity check, restore refused";
            LOG_ERR(m_errorText + " (" + errCodeToString(ce) + ")");
            return ce;
        }
    }

    /* 目标目录：不存在则创建；存在且非空需要 --force（对应错误码 2） */
    if (!opt.verifyOnly) {
        if (DBKP_IS_ERR(Platform::exists(targetDir))) {
            e = Platform::makeDirTree(targetDir);
            if (DBKP_IS_ERR(e)) { m_errorText = "cannot create target: " + targetDir; return e; }
        } else if (!Platform::isDirectory(targetDir)) {
            LOG_ERR("target is not a directory: " + targetDir);
            return E_INVALID_PARAMETER;
        } else if (!opt.overwrite) {
            ErrCode emptyErr = Platform::assertDirEmpty(targetDir);
            if (DBKP_IS_ERR(emptyErr)) {
                m_errorText = "target directory is not empty: " + targetDir;
                LOG_ERR(m_errorText + " (use --force to overwrite)");
                return E_DESTINATION_NOT_EMPTY;
            }
        }
    }

    int64_t cur = static_cast<int64_t>(hdr.payloadOffset);
    if (hdr.payloadOffset != BLOCK_SIZE) {
        e = in.seekTo(static_cast<int64_t>(hdr.payloadOffset));
        if (DBKP_IS_ERR(e)) return E_TRUNCATED_ARCHIVE;
        cur = static_cast<int64_t>(hdr.payloadOffset);
    }
    /* readHeaderAt 已把文件游标移到卷标之后；载荷紧跟卷标，无需再定位 */
    std::vector<uint8_t> block;
    block.resize(BLOCK_SIZE);
    const int64_t payloadEnd = hdr.payloadSize > 0
        ? static_cast<int64_t>(hdr.payloadOffset + hdr.payloadSize) : -1;

    CRecordReader reader;
    std::vector<FileRecord> pendingDirs;
    int64_t  entries = 0;
    uint64_t rdone   = 0;
    bool       rcancel = false;
    if (opt.progress)
        opt.progress->onStart(static_cast<int64_t>(hdr.fileCount),
                              static_cast<uint64_t>(hdr.rawSize > 0 ? hdr.rawSize : 0));
    for (;;) {
        if (payloadEnd >= 0 && cur >= payloadEnd) break;
        e = in.readN(block.data(), BLOCK_SIZE);
        if (DBKP_IS_ERR(e)) break;                    /* 正常到达文件尾 */
        cur += BLOCK_SIZE;
        ErrCode pe = reader.pushBlock(block.data());
        if (DBKP_IS_ERR(pe)) {
            m_errorText = "invalid record at offset " + std::to_string(cur - BLOCK_SIZE);
            LOG_ERR(m_errorText + " (" + errCodeToString(pe) + ")");
            return pe;
        }
        if (!reader.hasRecord()) continue;             /* 扩展记录尚未闭合 */
        FileRecord rec = reader.take();

        std::vector<uint8_t> data;
        if (rec.type == FT_REGULAR && rec.storedSize > 0) {
            e = readDataBlocks(in, rec, data, comp.get(), crypto.get(), opt.password, opt);
            cur += static_cast<int64_t>(blocksFor(rec.storedSize) * BLOCK_SIZE);
            if (DBKP_IS_ERR(e)) {
                if (e == E_CHECKSUM_MISMATCH) LOG_ERR("restore aborted at corrupted file: " + rec.path);
                return e;
            }
        }
        ErrCode re = restoreEntry(targetDir, rec,
                                  rec.type == FT_REGULAR ? &data : nullptr, opt, pendingDirs);
        if (DBKP_IS_ERR(re)) { m_errorText = "restore failed: " + rec.path; return re; }
        ++entries;
        if (opt.progress) {
            if (rec.type == FT_REGULAR && rec.size > 0)
                rdone += static_cast<uint64_t>(rec.size);
            opt.progress->onProgress(entries, rdone);
            if (opt.progress->canceled()) { rcancel = true; break; }
        }
        if ((entries % 1024) == 0) LOG_INFO("restored " + std::to_string(entries) + " entries");
    }

    /* 取消：不再回填目录元数据，明确返回失败，前端据此显示"已取消" */
    if (rcancel) {
        m_errorText = "restore canceled by user";
        LOG_WARN(m_errorText);
        return E_CANCELED;
    }

    /* 目录 mtime 最后、逆序恢复（修复讲义已知缺陷：父目录时间被子项顶新） */
    for (size_t i = pendingDirs.size(); i-- > 0;) {
        applyMetadata(absOf(targetDir, pendingDirs[i].path), pendingDirs[i], opt, true);
    }

    if (payloadEnd >= 0 && cur != payloadEnd) {
        LOG_WARN("archive length mismatch: read " + std::to_string(cur) +
                 ", header says " + std::to_string(payloadEnd));
        ++opt.warnings;
    }
    LOG_INFO(std::string(opt.verifyOnly ? "verified " : "restored ") +
             std::to_string(entries) + " entries into " + targetDir);
    return E_OK;
}

/* ------------------------------------------------------------ 仅列出记录 */
ErrCode CMyPack::list(const std::string& archivePath, std::vector<FileRecord>& recs) {
    recs.clear();
    CSimpleFile in;
    ErrCode e = in.open(archivePath, CSimpleFile::MODE_READ);
    if (DBKP_IS_ERR(e)) return e;
    ArchiveHeader hdr;
    e = readHeaderAt(in, hdr);
    if (DBKP_IS_ERR(e)) return e;
    if (hdr.payloadOffset != BLOCK_SIZE && DBKP_IS_ERR(in.seekTo(static_cast<int64_t>(hdr.payloadOffset))))
        return E_TRUNCATED_ARCHIVE;

    CRecordReader reader;
    std::vector<uint8_t> block;
    block.resize(BLOCK_SIZE);
    for (;;) {
        e = in.readN(block.data(), BLOCK_SIZE);
        if (DBKP_IS_ERR(e)) break;
        ErrCode pe = reader.pushBlock(block.data());
        if (DBKP_IS_ERR(pe)) return pe;
        if (!reader.hasRecord()) continue;
        FileRecord rec = reader.take();
        recs.push_back(rec);
        if (rec.type == FT_REGULAR && rec.storedSize > 0) {
            ErrCode se = in.seekFile(static_cast<int64_t>(blocksFor(rec.storedSize) * BLOCK_SIZE),
                                     SEEK_CUR);
            if (DBKP_IS_ERR(se)) return E_TRUNCATED_ARCHIVE;
        }
    }
    return E_OK;
}

/* ------------------------------------------------------------ 统计 */
ErrCode CMyPack::stat(const std::string& archivePath, ArchiveHeader& hdr, ArchiveStat& st) {
    ErrCode e = readHeader(archivePath, hdr);
    if (DBKP_IS_ERR(e)) return e;
    std::vector<FileRecord> recs;
    e = list(archivePath, recs);
    if (DBKP_IS_ERR(e)) return e;
    st = ArchiveStat();
    for (size_t i = 0; i < recs.size(); ++i) {
        const FileRecord& r = recs[i];
        switch (r.type) {
        case FT_REGULAR:   ++st.fileCount; break;
        case FT_DIR:       ++st.dirCount; break;
        case FT_SYMLINK:
        case FT_HARDLINK:  ++st.linkCount; break;
        default:           ++st.specialCount; break;
        }
        st.rawBytes   += r.size;
        st.storedBytes += r.storedSize;
    }
    return E_OK;
}

/* ------------------------------------------------------------ 校验 */
ErrCode CMyPack::verify(const std::string& archivePath, const std::string& password, int& badCount) {
    badCount = 0;
    /* F6b：正式箱旁边若还留着 .tmp，说明上一次备份没有走到 rename 提交
       （被打断/杀死/崩溃）。tmp 即天然进行中标记，这里只报告不删除，
       删除责任在 pack --force，避免两套清理机制互相误删。 */
    if (Platform::exists(archivePath + ".tmp") == E_OK) {
        LOG_ERR("temp file present next to archive, previous backup did not finish: " +
                archivePath + ".tmp");
        ++badCount;
        return E_INCOMPLETE;
    }
    ArchiveHeader hdr;
    ErrCode e = readHeader(archivePath, hdr);
    if (DBKP_IS_ERR(e)) return e;

    /* 1) 整段载荷校验（crc64 或 sha256）：任何单字节损坏（含记录区）都会在这里暴露 */
    ErrCode pe = checkWholePayload(archivePath, hdr);
    if (DBKP_IS_ERR(pe)) { ++badCount; return pe; }

    /* 2) 逐条解码并校验每个文件的 CRC64（不落盘） */
    UnpackOptions opt;
    opt.verifyOnly = true;
    opt.restoreMeta = false;
    opt.password = password;
    return unpack(archivePath, ".", opt);
}

/* ---------------------------------------------- 归档 vs 原始目录 差异对比 */
ErrCode CMyPack::compareWithSource(const std::string& archivePath, const std::string& sourceDir,
                                   const std::string& password, int& diffCount) {
    diffCount = 0;
    ArchiveHeader hdr;
    ErrCode e = readHeader(archivePath, hdr);
    if (DBKP_IS_ERR(e)) return e;

    std::string errText;
    std::unique_ptr<IDataCodec> comp(makeComp(static_cast<AlgorithmId>(hdr.compAlg), errText));
    std::unique_ptr<IDataCodec> crypto(
        makeCrypto(static_cast<CryptoId>(hdr.cryptoAlg), password, hdr.salt,
                   hdr.kdfRounds ? hdr.kdfRounds : 4096, errText));
    if (hdr.cryptoAlg != CRY_NONE && !crypto) { LOG_ERR(errText); return E_INVALID_PARAMETER; }

    std::vector<FileRecord> recs;
    e = list(archivePath, recs);
    if (DBKP_IS_ERR(e)) return e;

    /* 逐个回源比对：类型、长度、CRC（数据需要重新读一遍归档，故用完整遍历） */
    CSimpleFile in;
    e = in.open(archivePath, CSimpleFile::MODE_READ);
    if (DBKP_IS_ERR(e)) return e;
    std::vector<uint8_t> block;
    block.resize(BLOCK_SIZE);
    in.seekTo(static_cast<int64_t>(hdr.payloadOffset));

    CRecordReader reader;
    UnpackOptions dummy;
    for (;;) {
        e = in.readN(block.data(), BLOCK_SIZE);
        if (DBKP_IS_ERR(e)) break;
        ErrCode pe = reader.pushBlock(block.data());
        if (DBKP_IS_ERR(pe)) return pe;
        if (!reader.hasRecord()) continue;
        FileRecord rec = reader.take();

        std::vector<uint8_t> data;
        if (rec.type == FT_REGULAR && rec.storedSize > 0) {
            ErrCode de = readDataBlocks(in, rec, data, comp.get(), crypto.get(), password, dummy);
            if (DBKP_IS_ERR(de)) { ++diffCount; continue; }
        }
        const std::string absPath = absOf(sourceDir, rec.path);
        Platform::FileInfo fi;
        ErrCode ge = Platform::getInfo(absPath, fi, rec.type != FT_SYMLINK);
        if (DBKP_IS_ERR(ge)) {
            LOG_WARN("compare: missing in source: " + rec.path);
            ++diffCount;
            continue;
        }
        if (fi.type != rec.type && !(rec.type == FT_HARDLINK)) {
            LOG_WARN("compare: type differs: " + rec.path);
            ++diffCount;
        }
        if (rec.type == FT_REGULAR) {
            if (static_cast<int64_t>(data.size()) != fi.size) {
                LOG_WARN("compare: size differs: " + rec.path);
                ++diffCount;
            } else if (CRC64::compute(data.data(), data.size()) != rec.crc) {
                LOG_WARN("compare: content differs: " + rec.path);
                ++diffCount;
            }
        } else if (rec.type == FT_SYMLINK && fi.linkTarget != rec.link) {
            LOG_WARN("compare: symlink target differs: " + rec.path);
            ++diffCount;
        }
    }
    LOG_INFO("compare finished with " + std::to_string(diffCount) + " difference(s)");
    return E_OK;
}

} /* namespace DBKP */







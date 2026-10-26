/* ============================================================================
 *  MyPack.cpp  -- 归档写入/读取主体
 * ==========================================================================*/
#include "Pack/MyPack.h"

#include <algorithm>
#include <cstring>
#include <ctime>
#include <memory>

#include "Common/Serialize.h"
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

void fillSalt(uint8_t salt[16]) {
    uint64_t seed = static_cast<uint64_t>(std::time(nullptr)) ^
                    (static_cast<uint64_t>(reinterpret_cast<uintptr_t>(&seed)) << 17) ^
                    0x9E3779B97F4A7C15ull;
    for (int i = 0; i < 16; ++i) {
        seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
        salt[i] = static_cast<uint8_t>(seed & 0xFF);
    }
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

    /* 1. 先序枚举（含根目录自身 "."） */
    CFileEnumerator enumerator;
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

    /* 2. 卷标占位，最后回填计数与 CRC */
    CSimpleFile out;
    e = out.open(archivePath, CSimpleFile::MODE_READ_WRITE);
    if (DBKP_IS_ERR(e)) {
        m_errorText = "cannot create archive: " + archivePath;
        LOG_ERR(m_errorText);
        return e;
    }

    ArchiveHeader hdr;
    hdr.compAlg   = static_cast<uint8_t>(comp ? opt.comp : ALG_NONE);
    hdr.cryptoAlg = static_cast<uint8_t>(crypto ? opt.crypto : CRY_NONE);
    hdr.checksum  = static_cast<uint8_t>(opt.checksum);
    hdr.createTime = static_cast<uint64_t>(std::time(nullptr));
    hdr.sourcePath = absSource;
    hdr.comment    = opt.comment;
    hdr.payloadOffset = BLOCK_SIZE;
    hdr.kdfRounds = static_cast<uint16_t>(kdfRounds);
    std::memcpy(hdr.salt, salt, 16);

    std::vector<uint8_t> block;
    encodeArchiveHeader(hdr, block);
    e = out.writeN(block.data(), static_cast<int64_t>(block.size()));
    if (DBKP_IS_ERR(e)) { m_errorText = "write archive header failed"; return e; }

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

    /* 取消：删掉半成品，绝不留一个"看起来成功"的归档（失败必须显式） */
    if (canceled) {
        out.close();
        Platform::removeFile(archivePath);
        m_errorText = "backup canceled by user";
        LOG_WARN(m_errorText);
        return E_CANCELED;
    }

    /* 4. 回填卷标：条目数、原始/编码字节数、整段载荷 CRC */
    const int64_t endPos = out.tell();
    uint64_t payloadBytes = endPos > static_cast<int64_t>(BLOCK_SIZE)
                          ? static_cast<uint64_t>(endPos - BLOCK_SIZE) : 0;
    CRC64 payloadCrc;
    {
        std::vector<uint8_t> buf;
        buf.resize(64 * 1024);
        out.seekTo(static_cast<int64_t>(BLOCK_SIZE));
        uint64_t done = 0;
        while (done < payloadBytes) {
            int64_t want = static_cast<int64_t>(
                std::min<uint64_t>(payloadBytes - done, static_cast<uint64_t>(buf.size())));
            ErrCode re = out.readN(buf.data(), want);
            if (DBKP_IS_ERR(re)) { LOG_WARN("payload checksum pass incomplete"); break; }
            payloadCrc.update(buf.data(), static_cast<size_t>(want));
            done += static_cast<uint64_t>(want);
        }
    }
    hdr.payloadSize = payloadBytes;
    hdr.payloadCrc  = payloadCrc.value();
    hdr.rawSize     = rawTotal;
    hdr.recordCount = recordCount;
    hdr.fileCount   = fileCount;
    encodeArchiveHeader(hdr, block);
    out.seekTo(0);
    e = out.writeN(block.data(), static_cast<int64_t>(block.size()));
    if (DBKP_IS_ERR(e)) { m_errorText = "rewrite archive header failed"; return e; }
    ErrCode fe = out.flush();
    ErrCode ce = out.close();
    LOG_INFO("archive written: " + std::to_string(fileCount) + " entries, " +
             std::to_string(rawTotal) + " -> " + std::to_string(storedTotal) +
             " bytes (payload " + std::to_string(payloadBytes) + ")");
    return DBKP_IS_ERR(fe) ? fe : ce;
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
ErrCode CMyPack::readHeader(const std::string& archivePath, ArchiveHeader& hdr) {
    CSimpleFile in;
    ErrCode e = in.open(archivePath, CSimpleFile::MODE_READ);
    if (DBKP_IS_ERR(e)) return e;
    std::vector<uint8_t> block;
    block.resize(BLOCK_SIZE);
    e = in.readN(block.data(), BLOCK_SIZE);
    if (DBKP_IS_ERR(e)) return E_TRUNCATED_ARCHIVE;
    return decodeArchiveHeader(block.data(), hdr);
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

    std::vector<uint8_t> block;
    block.resize(BLOCK_SIZE);
    e = in.readN(block.data(), BLOCK_SIZE);
    if (DBKP_IS_ERR(e)) return E_TRUNCATED_ARCHIVE;
    ArchiveHeader hdr;
    e = decodeArchiveHeader(block.data(), hdr);
    if (DBKP_IS_ERR(e)) { m_errorText = "not a dbkp archive"; return e; }
    if (hdr.version != ARCHIVE_VERSION) {
        LOG_ERR("unsupported archive version " + std::to_string(hdr.version));
        return E_INVALID_HEADER_RECORD;
    }
    if (hdr.compAlg >= ALG_COUNT || hdr.cryptoAlg > CRY_XOR_TEST) {
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
        e = in.seekTo(cur);
        if (DBKP_IS_ERR(e)) return E_TRUNCATED_ARCHIVE;
    }
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
    std::vector<uint8_t> block;
    block.resize(BLOCK_SIZE);
    e = in.readN(block.data(), BLOCK_SIZE);
    if (DBKP_IS_ERR(e)) return E_TRUNCATED_ARCHIVE;
    ArchiveHeader hdr;
    e = decodeArchiveHeader(block.data(), hdr);
    if (DBKP_IS_ERR(e)) return e;

    CRecordReader reader;
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
    ArchiveHeader hdr;
    ErrCode e = readHeader(archivePath, hdr);
    if (DBKP_IS_ERR(e)) return e;

    /* 1) 整段载荷 CRC：任何单字节损坏（含头记录区）都会在这里暴露 */
    if (hdr.checksum == CHK_CRC64 && hdr.payloadSize > 0) {
        CSimpleFile in;
        e = in.open(archivePath, CSimpleFile::MODE_READ);
        if (DBKP_IS_ERR(e)) return e;
        if (DBKP_IS_ERR(in.seekTo(static_cast<int64_t>(hdr.payloadOffset)))) return E_TRUNCATED_ARCHIVE;
        CRC64 crc;
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
            done += static_cast<uint64_t>(want);
        }
        if (crc.value() != hdr.payloadCrc) {
            LOG_ERR("payload checksum mismatch: expect " + CRC64::toString(hdr.payloadCrc) +
                    ", got " + CRC64::toString(crc.value()));
            ++badCount;
            return E_CHECKSUM_MISMATCH;
        }
        LOG_DEBUG("payload crc64 verified: " + CRC64::toString(crc.value()));
    }

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







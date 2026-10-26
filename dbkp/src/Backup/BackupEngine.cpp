/* ============================================================================
 *  BackupEngine.cpp  -- 逐文件复制备份 / 还原 / 校验（课程"基本要求"形态）
 * ==========================================================================*/
#include "Backup/BackupEngine.h"

#include <algorithm>
#include <cstring>
#include <map>

#include "Common/Serialize.h"
#include "Platform/FS.h"
#include "Utils/CRC64.h"
#include "Utils/Logger.h"
#include "Utils/PathUtil.h"

namespace DBKP {

namespace {

const int64_t kCopyChunk = 512 * 1024;

std::string absOf(const std::string& root, const std::string& rel) {
    if (rel == "." || rel.empty()) return root;
    return Path::normalize(root + "/" + rel);
}

FileRecord recordFrom(const EnumeratedEntry& ent) {
    FileRecord rec;
    const Platform::FileInfo& fi = ent.info;
    rec.path = ent.relPath;
    rec.type = fi.type;
    rec.link = fi.linkTarget;
    rec.mode = fi.mode;
    rec.uid = fi.uid;
    rec.gid = fi.gid;
    rec.mtimeSec = fi.mtimeSec; rec.mtimeNSec = fi.mtimeNSec;
    rec.atimeSec = fi.atimeSec; rec.atimeNSec = fi.atimeNSec;
    rec.ctimeSec = fi.ctimeSec;
    rec.ino = fi.ino; rec.nlink = fi.nlink; rec.dev = fi.dev;
    rec.majorNum = fi.majorNum; rec.minorNum = fi.minorNum;
    rec.size = fi.size;
    rec.flags = static_cast<uint8_t>(RF_META_MODE | RF_META_TIME | RF_CRC_VALID);
    return rec;
}

/** 流式复制一个普通文件（分块，不整体载入内存），返回其 CRC64 */
ErrCode streamCopy(const std::string& src, const std::string& dst, uint64_t& crcOut) {
    CSimpleFile in;
    ErrCode e = in.open(src, CSimpleFile::MODE_READ);
    if (DBKP_IS_ERR(e)) return e;
    CSimpleFile out;
    e = out.open(dst, CSimpleFile::MODE_WRITE_NEW);
    if (DBKP_IS_ERR(e)) { in.close(); return e; }

    std::vector<uint8_t> buf;
    buf.resize(static_cast<size_t>(kCopyChunk));
    CRC64 crc;
    for (;;) {
        int64_t n = Platform::readNative(in.fd(), buf.data(), kCopyChunk);
        if (n < 0) {
            if (errno == EINTR) continue;
            out.close(); in.close();
            return E_FILE_READ_FAIL;
        }
        if (n == 0) break;
        e = out.writeN(buf.data(), n);
        if (DBKP_IS_ERR(e)) { out.close(); in.close(); return e; }
        crc.update(buf.data(), static_cast<size_t>(n));
    }
    ErrCode fe = out.flush();
    ErrCode ce = out.close();
    in.close();
    crcOut = crc.value();
    if (DBKP_IS_ERR(fe)) return fe;
    return ce;
}

} /* anonymous namespace */

BackupMode CBackupEngine::resolveMode(const std::string& destination, BackupMode requested) {
    if (requested != MODE_AUTO) return requested;
    const std::string d = Path::toArchive(destination);
    const std::string suffix = DEFAULT_ARCHIVE_SUFFIX;
    if (d.size() >= suffix.size() &&
        d.compare(d.size() - suffix.size(), suffix.size(), suffix) == 0) {
        return MODE_ARCHIVE;
    }
    return MODE_COPY;
}

ErrCode CBackupEngine::run(BackupOptions& opt) {
    m_error.clear();
    if (opt.source.empty() || opt.destination.empty()) {
        m_error = "source and destination are required";
        return E_INVALID_PARAMETER;
    }
    const BackupMode mode = resolveMode(opt.destination, opt.mode);
    LOG_INFO("backup mode = " + std::string(backupModeName(mode)));

    if (mode == MODE_ARCHIVE) {
        PackOptions p = opt.pack;
        p.password = opt.password;
        p.progress = opt.progress;
        if (p.filter.isEmpty() && !opt.filter.isEmpty()) p.filter = opt.filter;
        CMyPack packer;
        ErrCode e = packer.pack(opt.source, opt.destination, p);
        if (DBKP_IS_ERR(e)) { m_error = packer.lastErrorText(); return e; }
        if (opt.verifyAfter) {
            int bad = 0;
            ErrCode ve = packer.verify(opt.destination, opt.password, bad);
            if (DBKP_IS_ERR(ve)) { m_error = "post-backup verification failed"; return ve; }
            LOG_INFO("post-backup verify: archive is consistent");
        }
        return E_OK;
    }

    FilterOptions f = opt.pack.filter.isEmpty() ? opt.filter : opt.pack.filter;
    ErrCode e = copyBackup(opt.source, opt.destination, f, opt.preserveMeta, opt.warnings,
                           opt.progress);
    if (DBKP_IS_ERR(e)) return e;
    if (opt.verifyAfter) {
        int diff = 0;
        ErrCode ve = verifyCopy(opt.source, opt.destination, f, diff);
        if (DBKP_IS_ERR(ve)) return ve;
        if (diff != 0) { m_error = "post-copy verification found differences"; return E_CHECKSUM_MISMATCH; }
        LOG_INFO("post-backup verify: all copies match source CRC");
    }
    return E_OK;
}

/* ------------------------------------------------------------ 复制备份 */
ErrCode CBackupEngine::copyBackup(const std::string& source, const std::string& dest,
                                  const FilterOptions& filter, bool preserveMeta, int& warnings,
                                  IProgressSink* progress) {
    m_error.clear();
    warnings = 0;
    CFileEnumerator enumerator;
    std::vector<EnumeratedEntry> entries;
    ErrCode e = enumerator.enumerateFiles(source, filter, entries);
    if (DBKP_IS_ERR(e)) { m_error = "enumerate failed"; return e; }

    uint64_t planBytes = 0;
    for (size_t i = 0; i < entries.size(); ++i)
        if (entries[i].info.type == FT_REGULAR && entries[i].info.size > 0)
            planBytes += static_cast<uint64_t>(entries[i].info.size);
    if (progress) progress->onStart(static_cast<int64_t>(entries.size()), planBytes);

    if (DBKP_IS_ERR(Platform::exists(dest))) {
        e = Platform::makeDirTree(dest);
        if (DBKP_IS_ERR(e)) { m_error = "cannot create destination: " + dest; return e; }
    } else if (!Platform::isDirectory(dest)) {
        m_error = "destination is not a directory: " + dest;
        return E_INVALID_PARAMETER;
    }

    std::map<std::pair<uint32_t, uint64_t>, std::string> inodeMap;
    std::vector<FileRecord> pendingDirs;
    int64_t copied = 0, dirsMade = 0, links = 0, special = 0;

    uint64_t cdone = 0;
    for (size_t i = 0; i < entries.size(); ++i) {
        if (progress) {
            if (i > 0 && entries[i - 1].info.type == FT_REGULAR && entries[i - 1].info.size > 0)
                cdone += static_cast<uint64_t>(entries[i - 1].info.size);
            progress->onProgress(static_cast<int64_t>(i), cdone);
            if (progress->canceled()) {
                m_error = "copy backup canceled (partial copies kept)";
                LOG_WARN(m_error);
                return E_CANCELED;
            }
        }
        const EnumeratedEntry& ent = entries[i];
        FileRecord rec = recordFrom(ent);
        const std::string srcAbs = absOf(source, rec.path);
        const std::string dstAbs = absOf(dest, rec.path);
        const std::string parent = Path::parentDir(dstAbs);

        if (rec.type == FT_DIR) {
            e = Platform::makeDirTree(dstAbs);
            if (DBKP_IS_ERR(e) && e != E_ALREADY_EXISTS) {
                LOG_WARN("cannot create directory: " + dstAbs);
                ++warnings;
                continue;
            }
            pendingDirs.push_back(rec);
            ++dirsMade;
            continue;
        }

        if (rec.type == FT_REGULAR) {
            bool madeLink = false;
            if (rec.nlink > 1 && rec.ino != 0 && Platform::supportsHardlink()) {
                const std::pair<uint32_t, uint64_t> key(rec.dev, rec.ino);
                std::map<std::pair<uint32_t, uint64_t>, std::string>::const_iterator it =
                    inodeMap.find(key);
                if (it != inodeMap.end()) {
                    ErrCode le = Platform::makeHardLink(absOf(dest, it->second), dstAbs);
                    if (DBKP_IS_ERR(le)) {
                        LOG_WARN("hard link failed, copy instead: " + rec.path);
                        ++warnings;
                    } else {
                        madeLink = true;
                        ++links;
                    }
                }
                if (!madeLink) inodeMap[key] = rec.path;
            }
            if (!madeLink) {
                e = copyOneFile(srcAbs, dstAbs, rec, preserveMeta, warnings);
                if (DBKP_IS_ERR(e)) {
                    m_error = "copy failed: " + rec.path + " (" + errCodeToString(e) + ")";
                    LOG_ERR(m_error);
                    if (e == E_PERMISSION_DENIED) continue;
                    return e;
                }
                ++copied;
            } else if (preserveMeta) {
                Platform::setTimes(dstAbs, rec.mtimeSec, rec.mtimeNSec,
                                   rec.atimeSec, rec.atimeNSec, true);
            }
            continue;
        }

        if (rec.type == FT_SYMLINK) {
            if (!Platform::supportsSymlink()) { ++special; continue; }
            if (!parent.empty()) Platform::makeDirTree(parent);
            e = Platform::makeSymlink(rec.link, dstAbs);
            if (DBKP_IS_ERR(e)) {
                LOG_WARN(std::string("symlink not recreated (") + errCodeToString(e) +
                         "): " + rec.path);
                ++warnings;
            } else {
                ++links;
                if (preserveMeta) {
                    Platform::setTimes(dstAbs, rec.mtimeSec, rec.mtimeNSec,
                                       rec.atimeSec, rec.atimeNSec, false);
                }
            }
            continue;
        }

        if (!parent.empty()) Platform::makeDirTree(parent);
        if (rec.type == FT_FIFO) {
            e = Platform::makeFifo(dstAbs, rec.mode);
        } else if (rec.type == FT_BLOCK || rec.type == FT_CHAR) {
            e = Platform::makeDeviceNode(dstAbs, rec.type, rec.majorNum, rec.minorNum, rec.mode);
        } else if (rec.type == FT_SOCKET) {
            e = Platform::makeSocketPlaceholder(dstAbs);
            LOG_WARN("socket recorded as placeholder: " + rec.path);
        } else {
            e = E_UNSUPPORTED_FEATURE;
        }
        if (DBKP_IS_ERR(e)) {
            LOG_WARN(std::string("special file skipped (") + errCodeToString(e) +
                     "): " + rec.path);
            ++warnings;
        } else {
            ++special;
        }
    }

    /* 目录时间/权限最后逆序恢复（修复讲义已知缺陷） */
    if (preserveMeta) {
        for (size_t i = pendingDirs.size(); i-- > 0;) {
            const FileRecord& rec = pendingDirs[i];
            const std::string dstAbs = absOf(dest, rec.path);
            Platform::setTimes(dstAbs, rec.mtimeSec, rec.mtimeNSec,
                               rec.atimeSec, rec.atimeNSec, true);
            Platform::setMode(dstAbs, rec.mode);
            if (Platform::supportsOwner()) Platform::setOwner(dstAbs, rec.uid, rec.gid);
        }
    }

    LOG_INFO("copy backup done: " + std::to_string(copied) + " files, " +
             std::to_string(dirsMade) + " dirs, " + std::to_string(links) + " links, " +
             std::to_string(special) + " special -> " + dest);
    return E_OK;
}

/* ------------------------------------------------------------ 单个文件 */
ErrCode CBackupEngine::copyOneFile(const std::string& srcAbs, const std::string& dstAbs,
                                   const FileRecord& rec, bool preserveMeta, int& warnings) {
    const std::string parent = Path::parentDir(dstAbs);
    if (!parent.empty()) Platform::makeDirTree(parent);
    uint64_t crc = 0;
    ErrCode e = streamCopy(srcAbs, dstAbs, crc);
    if (DBKP_IS_ERR(e)) { ++warnings; return e; }
    if (preserveMeta) {
        Platform::setTimes(dstAbs, rec.mtimeSec, rec.mtimeNSec,
                           rec.atimeSec, rec.atimeNSec, true);
        Platform::setMode(dstAbs, rec.mode);
        if (Platform::supportsOwner()) Platform::setOwner(dstAbs, rec.uid, rec.gid);
    }
    return E_OK;
}

/* ------------------------------------------------------------ 从复制目录还原 */
ErrCode CBackupEngine::copyRestore(const std::string& backupDir, const std::string& dest,
                                   bool preserveMeta, int& warnings, IProgressSink* progress) {
    FilterOptions all;                       /* 备份目录本身已是筛选后的结果 */
    all.includeDirs = true;
    return copyBackup(backupDir, dest, all, preserveMeta, warnings, progress);
}

/* ------------------------------------------------------------ 复制结果校验 */
namespace {

ErrCode fileCrc(const std::string& path, uint64_t& crcOut) {
    CSimpleFile f;
    ErrCode e = f.open(path, CSimpleFile::MODE_READ);
    if (DBKP_IS_ERR(e)) return e;
    std::vector<uint8_t> buf;
    buf.resize(static_cast<size_t>(kCopyChunk));
    CRC64 crc;
    for (;;) {
        int64_t n = Platform::readNative(f.fd(), buf.data(), kCopyChunk);
        if (n < 0) { f.close(); return E_FILE_READ_FAIL; }
        if (n == 0) break;
        crc.update(buf.data(), static_cast<size_t>(n));
    }
    f.close();
    crcOut = crc.value();
    return E_OK;
}

} /* anonymous namespace */

ErrCode CBackupEngine::verifyCopy(const std::string& source, const std::string& dest,
                                  const FilterOptions& filter, int& diffCount) {
    diffCount = 0;
    CFileEnumerator enumerator;
    std::vector<EnumeratedEntry> entries;
    ErrCode e = enumerator.enumerateFiles(source, filter, entries);
    if (DBKP_IS_ERR(e)) { m_error = "enumerate source failed"; return e; }

    std::vector<EnumeratedEntry> mirrored;
    FilterOptions all;
    e = enumerator.enumerateFiles(dest, all, mirrored);
    if (DBKP_IS_ERR(e)) { m_error = "enumerate destination failed"; return e; }

    std::map<std::string, const EnumeratedEntry*> srcMap, dstMap;
    for (size_t i = 0; i < entries.size(); ++i) srcMap[entries[i].relPath] = &entries[i];
    for (size_t i = 0; i < mirrored.size(); ++i) dstMap[mirrored[i].relPath] = &mirrored[i];

    for (auto it = srcMap.begin(); it != srcMap.end(); ++it) {
        const EnumeratedEntry& s = *it->second;
        std::map<std::string, const EnumeratedEntry*>::const_iterator d = dstMap.find(s.relPath);
        if (d == dstMap.end()) {
            /* 目录可能被过滤掉了（例如只复制文件），只在类型应当存在时报错 */
            if (s.info.type == FT_REGULAR && s.info.size > 0) {
                LOG_WARN("verify: missing in backup: " + s.relPath);
                ++diffCount;
            }
            continue;
        }
        const EnumeratedEntry& t = *d->second;
        if (s.info.type != t.info.type) {
            LOG_WARN("verify: type differs: " + s.relPath);
            ++diffCount;
            continue;
        }
        if (s.info.type == FT_REGULAR) {
            if (s.info.size != t.info.size) {
                LOG_WARN("verify: size differs: " + s.relPath);
                ++diffCount;
                continue;
            }
            uint64_t a = 0, b = 0;
            ErrCode e1 = fileCrc(absOf(source, s.relPath), a);
            ErrCode e2 = fileCrc(absOf(dest, t.relPath), b);
            if (DBKP_IS_ERR(e1) || DBKP_IS_ERR(e2) || a != b) {
                LOG_WARN("verify: content differs: " + s.relPath);
                ++diffCount;
            }
        } else if (s.info.type == FT_SYMLINK && s.info.linkTarget != t.info.linkTarget) {
            LOG_WARN("verify: symlink target differs: " + s.relPath);
            ++diffCount;
        }
    }
    for (auto it = dstMap.begin(); it != dstMap.end(); ++it) {
        if (srcMap.find(it->first) == srcMap.end()) {
            LOG_WARN("verify: unexpected extra entry: " + it->first);
            ++diffCount;
        }
    }
    LOG_INFO("verify copy: " + std::to_string(diffCount) + " difference(s)");
    return E_OK;
}

ErrCode CBackupEngine::verifyArchive(const std::string& archive, const std::string& password,
                                     ArchiveStat& stat, uint64_t& crc) {
    CMyPack packer;
    ArchiveHeader hdr;
    ErrCode e = packer.stat(archive, hdr, stat);
    if (DBKP_IS_ERR(e)) { m_error = packer.lastErrorText(); return e; }
    crc = hdr.payloadCrc;
    int bad = 0;
    e = packer.verify(archive, password, bad);
    if (DBKP_IS_ERR(e)) m_error = packer.lastErrorText();
    return e;
}

} /* namespace DBKP */



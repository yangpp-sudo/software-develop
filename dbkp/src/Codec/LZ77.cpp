/* ============================================================================
 *  LZ77.cpp  -- 滑动窗口 LZ77（4096B 窗口 / 3..18 字节匹配），从零实现
 *
 *  令牌编码：每 8 个令牌前置 1 个控制字节（bit=1 表示匹配项）
 *    字面量 : 1 字节
 *    匹配项 : 2 字节 = off_low | (off_high<<4)|(len-3) —— 12bit 偏移 + 4bit 长度
 *  压缩无收益时（flags bit0 = 1）整段原样存储，保证解码端行为一致。
 * ==========================================================================*/
#include "Codec/Codecs.h"

#include <cstring>

namespace DBKP {

ErrCode CLZ77::encode(const std::vector<uint8_t>& in, std::vector<uint8_t>& out) {
    const size_t n = in.size();
    std::vector<uint8_t> body;
    body.reserve(n + n / 8 + 16);

    std::vector<size_t> head(1u << kWindowBits, n);      /* 3 字节哈希 -> 最近位置 */
    struct H {
        static size_t of(uint8_t a, uint8_t b, uint8_t c) {
            unsigned h = (unsigned(a) * 0x9E3779B1u) ^ (unsigned(b) * 0x85EBCA77u) ^ unsigned(c);
            return (h >> 8) & ((1u << 12) - 1u);
        }
    };

    uint8_t ctrl = 0;
    std::vector<uint8_t> pend;                 /* 当前控制字节的尾数 */
    int items = 0;
    auto flushGroup = [&]() {
        if (items == 0) return;
        body.push_back(ctrl);
        body.insert(body.end(), pend.begin(), pend.end());
        ctrl = 0; pend.clear(); items = 0;
    };
    auto emitLiteral = [&](uint8_t b) {
        ctrl = static_cast<uint8_t>(ctrl & ~(1u << items));
        pend.push_back(b);
        if (++items == kNumLitPerCtrl) flushGroup();
    };
    auto emitMatch = [&](size_t len, size_t off) {
        ctrl = static_cast<uint8_t>(ctrl | (1u << items));
        pend.push_back(static_cast<uint8_t>(off & 0xFF));
        pend.push_back(static_cast<uint8_t>(((off >> 8) & 0x0F) | ((len - kMinMatch) << 4)));
        if (++items == kNumLitPerCtrl) flushGroup();
    };

    size_t i = 0;
    while (i < n) {
        size_t bestLen = 0, bestOff = 0;
        if (i + 2 < n) {
            const size_t cand = head[H::of(in[i], in[i + 1], in[i + 2])];
            if (cand < i && (i - cand) < static_cast<size_t>(kWindowSize)) {
                size_t len = 0;
                /* cand+len 允许越过 i：解码端逐字节复制，语义一致 */
                while (len < static_cast<size_t>(kMaxMatch) && i + len < n &&
                       in[cand + len] == in[i + len]) ++len;
                if (len >= static_cast<size_t>(kMinMatch)) { bestLen = len; bestOff = i - cand; }
            }
        }
        if (bestLen >= static_cast<size_t>(kMinMatch)) {
            emitMatch(bestLen, bestOff);
            for (size_t k = 0; k < bestLen; ++k) {
                if (i + k + 2 < n) head[H::of(in[i + k], in[i + k + 1], in[i + k + 2])] = i + k;
            }
            i += bestLen;
        } else {
            emitLiteral(in[i]);
            if (i + 2 < n) head[H::of(in[i], in[i + 1], in[i + 2])] = i;
            ++i;
        }
    }
    flushGroup();

    out.clear();
    const uint8_t flags = body.size() >= n ? 1 : 0;
    Codec::putHeader(out, static_cast<uint16_t>(CODEC_MAGIC_LZ & 0xFFFFu), 1, flags,
                     static_cast<uint64_t>(n));
    if (flags) out.insert(out.end(), in.begin(), in.end());
    else       out.insert(out.end(), body.begin(), body.end());
    return E_OK;
}

ErrCode CLZ77::decode(const std::vector<uint8_t>& in, std::vector<uint8_t>& out) {
    uint8_t ver = 0, flags = 0;
    uint64_t rawLen = 0;
    size_t start = 0;
    if (!Codec::readHeader(in, static_cast<uint16_t>(CODEC_MAGIC_LZ & 0xFFFFu),
                           ver, flags, rawLen, start)) return E_COMPRESS_FAIL;
    if (ver != 1) return E_COMPRESS_FAIL;
    if (rawLen > (1ull << 40)) return E_COMPRESS_FAIL;         /* 防御异常头 */

    if (flags & 1) {                                           /* 存储模式 */
        if (in.size() - start < rawLen) return E_TRUNCATED_ARCHIVE;
        out.assign(in.begin() + start, in.begin() + start + static_cast<size_t>(rawLen));
        return out.size() == rawLen ? E_OK : E_COMPRESS_FAIL;
    }

    out.clear();
    out.reserve(static_cast<size_t>(rawLen));
    size_t p = start;
    while (out.size() < static_cast<size_t>(rawLen)) {
        if (p >= in.size()) return E_TRUNCATED_ARCHIVE;
        const uint8_t ctrl = in[p++];
        for (int bit = 0; bit < kNumLitPerCtrl && out.size() < static_cast<size_t>(rawLen); ++bit) {
            if (ctrl & (1u << bit)) {
                if (p + 2 > in.size()) return E_TRUNCATED_ARCHIVE;
                const size_t off = size_t(in[p]) | (size_t(in[p + 1] & 0x0F) << 8);
                const size_t len = size_t(in[p + 1] >> 4) + kMinMatch;
                p += 2;
                if (off == 0 || off > out.size()) return E_COMPRESS_FAIL;
                for (size_t k = 0; k < len && out.size() < static_cast<size_t>(rawLen); ++k) {
                    out.push_back(out[out.size() - off]);
                }
            } else {
                if (p >= in.size()) return E_TRUNCATED_ARCHIVE;
                out.push_back(in[p++]);
            }
        }
    }
    return out.size() == static_cast<size_t>(rawLen) ? E_OK : E_COMPRESS_FAIL;
}

/* ------------------------------------------------------------------ RLE */
ErrCode CRle::encode(const std::vector<uint8_t>& in, std::vector<uint8_t>& out) {
    out.clear();
    Codec::putHeader(out, static_cast<uint16_t>(CODEC_MAGIC_RLE & 0xFFFFu), 1, 0,
                     static_cast<uint64_t>(in.size()));
    /* 令牌：0x00 + 字面量；0x01 + [len][byte]，len 1..255 */
    size_t i = 0;
    while (i < in.size()) {
        size_t run = 1;
        while (run < 255 && i + run < in.size() && in[i + run] == in[i]) ++run;
        if (run >= 3) {
            out.push_back(0x01);
            out.push_back(static_cast<uint8_t>(run));
            out.push_back(in[i]);
            i += run;
        } else {
            out.push_back(0x00);
            out.push_back(in[i]);
            ++i;
        }
    }
    return E_OK;
}

ErrCode CRle::decode(const std::vector<uint8_t>& in, std::vector<uint8_t>& out) {
    uint8_t ver = 0, flags = 0;
    uint64_t rawLen = 0;
    size_t start = 0;
    if (!Codec::readHeader(in, static_cast<uint16_t>(CODEC_MAGIC_RLE & 0xFFFFu),
                           ver, flags, rawLen, start)) return E_COMPRESS_FAIL;
    if (ver != 1 || flags != 0) return E_COMPRESS_FAIL;
    if (rawLen > (1ull << 40)) return E_COMPRESS_FAIL;
    out.clear();
    out.reserve(static_cast<size_t>(rawLen));
    size_t p = start;
    while (out.size() < static_cast<size_t>(rawLen)) {
        if (p + 1 >= in.size()) return E_TRUNCATED_ARCHIVE;
        const uint8_t tag = in[p++];
        if (tag == 0x00) {
            out.push_back(in[p++]);
        } else if (tag == 0x01) {
            if (p + 1 >= in.size()) return E_TRUNCATED_ARCHIVE;
            const size_t len = in[p++];
            const uint8_t b = in[p++];
            for (size_t k = 0; k < len && out.size() < static_cast<size_t>(rawLen); ++k) out.push_back(b);
        } else {
            return E_COMPRESS_FAIL;
        }
    }
    return out.size() == static_cast<size_t>(rawLen) ? E_OK : E_COMPRESS_FAIL;
}

/* ------------------------------------------------------------ LZ77+Huffman */
ErrCode CComboCodec::encode(const std::vector<uint8_t>& in, std::vector<uint8_t>& out) {
    std::vector<uint8_t> mid;
    ErrCode e = m_inner->encode(in, mid);
    if (DBKP_IS_ERR(e)) return e;
    return m_outer->encode(mid, out);
}

ErrCode CComboCodec::decode(const std::vector<uint8_t>& in, std::vector<uint8_t>& out) {
    std::vector<uint8_t> mid;
    ErrCode e = m_outer->decode(in, mid);
    if (DBKP_IS_ERR(e)) return e;
    return m_inner->decode(mid, out);
}

} /* namespace DBKP */


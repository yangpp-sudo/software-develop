/* ============================================================================
 *  Huffman.cpp  -- 规范（canonical）Huffman，从零实现
 *
 *  与讲义第 7 讲一致的两点设计：
 *    1. 码长表随流下发（256 字节），解码端据此重建规范码，无需重建树；
 *    2. 单符号/空输入特判，避免退化的 Kraft 和。
 *  额外加固：树深超过 kMaxCodeLen 时自动退化为"定长 8bit 存储"，
 *            保证任何输入都能解码（讲义实现未处理该边界）。
 * ==========================================================================*/
#include "Codec/Codecs.h"

#include <algorithm>
#include <cstring>
#include <functional>
#include <queue>

namespace DBKP {

namespace {

struct Node {
    uint64_t weight;
    int left, right;
    int symbol;         /* 叶子 >= 0 */
};

} /* anonymous namespace */

void CHuffman::buildCodeLengths(const uint32_t freq[256], uint8_t len[256]) {
    std::memset(len, 0, 256);
    std::vector<Node> nodes;
    nodes.reserve(512);
    int used = 0, only = -1;
    for (int s = 0; s < 256; ++s) {
        if (freq[s]) { nodes.push_back(Node{freq[s], -1, -1, s}); ++used; only = s; }
    }
    if (used == 0) return;                            /* 空输入 */
    if (used == 1) {                                  /* 单符号：两个长度为 1 的码 */
        len[only] = 1;
        len[(only + 1) & 0xFF] = 1;
        return;
    }

    typedef std::pair<uint64_t, int> Item;            /* (weight, nodeIndex) */
    std::priority_queue<Item, std::vector<Item>, std::greater<Item> > pq;
    for (size_t i = 0; i < nodes.size(); ++i) pq.push(Item(nodes[i].weight, int(i)));
    while (pq.size() > 1) {
        Item a = pq.top(); pq.pop();
        Item b = pq.top(); pq.pop();
        Node parent;
        parent.weight = a.first + b.first;
        parent.left = a.second; parent.right = b.second; parent.symbol = -1;
        nodes.push_back(parent);
        pq.push(Item(parent.weight, static_cast<int>(nodes.size()) - 1));
    }

    /* 迭代求深度，避免超深树递归爆栈 */
    struct Frame { int idx; int depth; };
    std::vector<Frame> stack;
    stack.push_back(Frame{static_cast<int>(nodes.size()) - 1, 0});
    int maxDepth = 0;
    bool overflow = false;
    while (!stack.empty()) {
        Frame f = stack.back(); stack.pop_back();
        const Node& n = nodes[f.idx];
        if (n.symbol >= 0) {
            len[n.symbol] = static_cast<uint8_t>(f.depth == 0 ? 1 : f.depth);
            if (f.depth > maxDepth) maxDepth = f.depth;
            continue;
        }
        if (f.depth + 1 > kMaxCodeLen) overflow = true;
        if (n.left  >= 0) stack.push_back(Frame{n.left,  f.depth + 1});
        if (n.right >= 0) stack.push_back(Frame{n.right, f.depth + 1});
    }
    if (overflow || maxDepth > kMaxCodeLen) {         /* 退化：定长 8bit 存储 */
        std::memset(len, 0, 256);
        for (int s = 0; s < 256; ++s) len[s] = 8;
    }
}

void CHuffman::buildCanonicalCodes(const uint8_t len[256], uint32_t code[256]) {
    uint32_t count[kMaxCodeLen + 2];
    std::memset(count, 0, sizeof(count));
    for (int s = 0; s < 256; ++s) if (len[s] && len[s] <= kMaxCodeLen) ++count[len[s]];
    uint32_t next[kMaxCodeLen + 2];
    next[1] = 0;
    for (int l = 2; l <= kMaxCodeLen; ++l) next[l] = (next[l - 1] + count[l - 1]) << 1;
    std::memset(code, 0, sizeof(uint32_t) * 256);
    uint32_t cur[kMaxCodeLen + 2];
    std::memcpy(cur, next, sizeof(cur));
    for (int s = 0; s < 256; ++s)
        if (len[s] && len[s] <= kMaxCodeLen) code[s] = cur[len[s]]++;
}

ErrCode CHuffman::encode(const std::vector<uint8_t>& in, std::vector<uint8_t>& out) {
    uint32_t freq[256];
    std::memset(freq, 0, sizeof(freq));
    for (size_t i = 0; i < in.size(); ++i) ++freq[in[i]];

    uint8_t len[256];
    buildCodeLengths(freq, len);
    uint32_t code[256];
    buildCanonicalCodes(len, code);

    out.clear();
    Codec::putHeader(out, static_cast<uint16_t>(CODEC_MAGIC_HUFF & 0xFFFFu), 1, 0,
                     static_cast<uint64_t>(in.size()));
    out.insert(out.end(), len, len + 256);
    if (in.empty()) return E_OK;

    Codec::BitWriter w(out);
    for (size_t i = 0; i < in.size(); ++i) {
        const uint8_t l = len[in[i]];
        if (l == 0) return E_COMPRESS_FAIL;         /* 频表与数据不一致 */
        w.writeMsb(code[in[i]], l);
    }
    w.flush();
    return E_OK;
}

ErrCode CHuffman::decode(const std::vector<uint8_t>& in, std::vector<uint8_t>& out) {
    uint8_t ver = 0, flags = 0;
    uint64_t rawLen = 0;
    std::size_t start = 0;
    if (!Codec::readHeader(in, static_cast<uint16_t>(CODEC_MAGIC_HUFF & 0xFFFFu),
                           ver, flags, rawLen, start)) return E_COMPRESS_FAIL;
    if (ver != 1) return E_COMPRESS_FAIL;
    if (in.size() < start + 256) return E_TRUNCATED_ARCHIVE;
    if (rawLen == 0) { out.clear(); return E_OK; }

    const uint8_t* len = in.data() + start;
    uint32_t count[kMaxCodeLen + 2];
    std::memset(count, 0, sizeof(count));
    uint64_t kraft = 0;
    for (int s = 0; s < 256; ++s) {
        if (len[s] > kMaxCodeLen) return E_COMPRESS_FAIL;
        if (len[s]) { ++count[len[s]]; kraft += uint64_t(1) << (kMaxCodeLen - len[s]); }
    }
    /* 完备前缀码：Kraft 和必须恰为 2^kMaxCodeLen */
    if (kraft != (uint64_t(1) << kMaxCodeLen)) return E_COMPRESS_FAIL;

    uint32_t offset[kMaxCodeLen + 2];
    offset[1] = 0;
    for (int l = 1; l <= kMaxCodeLen; ++l) offset[l + 1] = offset[l] + count[l];
    std::vector<int> sorted(256, 0);
    {
        uint32_t fill[kMaxCodeLen + 2];
        std::memcpy(fill, offset, sizeof(fill));
        for (int s = 0; s < 256; ++s) if (len[s]) sorted[fill[len[s]]++] = s;
    }

    out.assign(static_cast<size_t>(rawLen), 0);
    Codec::BitReader r(in.data() + start + 256, in.size() - start - 256);
    for (size_t i = 0; i < out.size(); ++i) {
        uint32_t c = 0, first = 0;
        int index = 0;
        bool found = false;
        for (int l = 1; l <= kMaxCodeLen; ++l) {
            uint32_t bit = 0;
            if (!r.read(bit, 1)) return E_COMPRESS_FAIL;
            c |= bit;                       /* 先读的位在高位：见末尾 c <<= 1 */
            if (c < first + count[l]) {
                out[i] = static_cast<uint8_t>(sorted[index + int(c - first)]);
                found = true;
                break;
            }
            index += int(count[l]);
            first = (first + count[l]) << 1;
            c <<= 1;
        }
        if (!found) return E_COMPRESS_FAIL;
    }
    return E_OK;
}

} /* namespace DBKP */


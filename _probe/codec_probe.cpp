#include <cstdio>
#include <cstring>
#include <random>
#include <vector>
#include "Codec/Codecs.h"
using namespace DBKP;

static int fails = 0;

static void Run(const char* name, const std::vector<uint8_t>& d, IDataCodec* c) {
    std::vector<uint8_t> e, o;
    ErrCode a = c->encode(d, e);
    ErrCode b = c->decode(e, o);
    bool same = (a == E_OK && b == E_OK && o == d);
    printf("%-22s enc=%3d dec=%3d in=%6zu out=%6zu %s\n", name, a, b, d.size(), e.size(),
           same ? "OK" : "FAIL");
    if (!same) {
        ++fails;
        for (size_t i = 0; i < std::min(o.size(), d.size()); ++i) {
            if (o[i] != d[i]) { printf("   first diff at %zu: got %d want %d\n", i, o[i], d[i]); break; }
        }
        if (o.size() != d.size()) printf("   size mismatch: got %zu want %zu\n", o.size(), d.size());
    }
}

static std::vector<uint8_t> rep(uint8_t b, size_t n) { return std::vector<uint8_t>(n, b); }

int main() {
    CLZ77 lz; CHuffman hu; CRle rl; CComboCodec combo;
    std::vector<uint8_t> empty;
    Run("empty", empty, &lz);
    Run("one", std::vector<uint8_t>{0x41}, &lz);
    Run("two", std::vector<uint8_t>{0x41, 0x42}, &lz);
    Run("aaa x300", rep('a', 300), &lz);
    std::string s; for (int i = 0; i < 500; ++i) s += "hello dbkp ";
    Run("hello dbkp x500", std::vector<uint8_t>(s.begin(), s.end()), &lz);
    std::vector<uint8_t> log; for (int i = 0; i < 300; ++i) { log.push_back('l'); log.push_back('o'); log.push_back('g'); log.push_back(' '); }
    Run("log pattern", log, &lz);
    std::vector<uint8_t> seq; for (int i = 0; i < 1000; ++i) seq.push_back(uint8_t(i));
    Run("0..255 cycle", seq, &lz);
    std::mt19937 g(42);
    std::vector<uint8_t> rnd; for (int i = 0; i < 40000; ++i) rnd.push_back(uint8_t(g() & 0xFF));
    Run("random 40000", rnd, &lz);
    std::vector<uint8_t> mixed = rep('a', 20); 
    mixed.insert(mixed.end(), rnd.begin(), rnd.begin() + 3000);
    mixed.insert(mixed.end(), 500, 'z');
    Run("mixed", mixed, &lz);
    std::vector<uint8_t> big; big.reserve(300000);
    for (int i = 0; i < 300000; ++i) big.push_back(uint8_t((i / 7) % 251));
    Run("ramp 300000", big, &lz);
    printf("--- huffman/lzhuff/rle sanity ---\n");
    Run("hello (huffman)", std::vector<uint8_t>(s.begin(), s.end()), &hu);
    Run("hello (lzhuff)", std::vector<uint8_t>(s.begin(), s.end()), &combo);
    Run("hello (rle)", std::vector<uint8_t>(s.begin(), s.end()), &rl);
    printf("FAILS=%d\n", fails);
    return fails ? 1 : 0;
}

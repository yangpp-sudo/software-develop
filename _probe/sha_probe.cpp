#include <cstdio>
#include <cstring>
#include "Crypto/Sha256.h"
using namespace DBKP;

static void show(const char* label, const char* s, size_t n) {
    uint8_t d[32];
    CSha256::hash(s, n, d);
    printf("%-10s %s\n", label, CSha256::toHex(d).c_str());
}

int main() {
    /* 标准测试向量 */
    show("empty", "", 0);
    printf("expect   e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n");
    show("abc", "abc", 3);
    printf("expect   ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\n");
    char m56[56]; memset(m56, 'a', 56);
    show("56xa", m56, 56);
    printf("expect   6640ea7222b8b2b0f49e132a75a6e5de6c504067692e156f7f3f9e507b2f68bc\n");
    char m64[64]; memset(m64, 'a', 64);
    show("64xa", m64, 64);
    printf("expect   ffe0c351b22c034ed029c59921a5d936a90cc6c1aca609b39a522e7224fe7ed1\n");
    return 0;
}

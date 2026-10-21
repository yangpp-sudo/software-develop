/* ============================================================================
 *  CRC64.cpp  -- CRC-64/ECMA-182（MSB-first，poly=0x42F0E1EBA9EA3693，init=0）
 * ==========================================================================*/
#include "Utils/CRC64.h"

#include <cstring>
#include <ctime>

namespace DBKP {

static const uint64_t kPoly64 = 0x42F0E1EBA9EA3693ull;
static uint64_t s_table[256];
static bool     s_ready = false;

void CRC64::initTable() {
    for (unsigned i = 0; i < 256; ++i) {
        uint64_t crc = uint64_t(i) << 56;
        for (int k = 0; k < 8; ++k) {
            crc = (crc & 0x8000000000000000ull) ? ((crc << 1) ^ kPoly64) : (crc << 1);
        }
        s_table[i] = crc;
    }
    s_ready = true;
}

uint64_t CRC64::compute(const void* data, std::size_t len, uint64_t init) {
    if (!s_ready) initTable();
    const uint8_t* p = static_cast<const uint8_t*>(data);
    uint64_t crc = init;
    for (std::size_t i = 0; i < len; ++i) {
        crc = (crc << 8) ^ s_table[uint8_t((crc >> 56) ^ p[i])];
    }
    return crc;
}

void CRC64::update(const void* data, std::size_t len) {
    m_crc = compute(data, len, m_crc);
}

std::string CRC64::toString(uint64_t crc) {
    static const char* kHex = "0123456789abcdef";
    char out[17];
    for (int i = 0; i < 16; ++i) {
        unsigned nibble = unsigned((crc >> ((15 - i) * 4)) & 0xF);
        out[i] = kHex[nibble];
    }
    out[16] = '\0';
    return std::string(out);
}

} /* namespace DBKP */

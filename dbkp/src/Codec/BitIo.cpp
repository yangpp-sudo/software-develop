/* ============================================================================
 *  BitIo.cpp  -- 码流头 + 位读写器
 * ==========================================================================*/
#include "Codec/Codecs.h"

#include <cstring>

namespace DBKP {
namespace Codec {

void putHeader(std::vector<uint8_t>& out, uint16_t magic, uint8_t ver, uint8_t flags,
               uint64_t rawLen) {
    out.push_back(static_cast<uint8_t>(magic & 0xFF));
    out.push_back(static_cast<uint8_t>((magic >> 8) & 0xFF));
    out.push_back(ver);
    out.push_back(flags);
    for (int i = 0; i < 8; ++i) out.push_back(static_cast<uint8_t>((rawLen >> (8 * i)) & 0xFF));
}

bool readHeader(const std::vector<uint8_t>& in, uint16_t expectMagic,
                uint8_t& ver, uint8_t& flags, uint64_t& rawLen, std::size_t& payloadStart) {
    if (in.size() < 12) return false;
    const uint16_t magic = uint16_t(in[0]) | (uint16_t(in[1]) << 8);
    if (magic != expectMagic) return false;
    ver = in[2];
    flags = in[3];
    rawLen = 0;
    for (int i = 0; i < 8; ++i) rawLen |= uint64_t(in[4 + i]) << (8 * i);
    payloadStart = 12;
    return true;
}

void BitWriter::write(uint32_t value, int nbits) {
    for (int i = 0; i < nbits; ++i) {
        m_acc |= ((value >> i) & 1u) << m_bits;
        ++m_bits;
        if (m_bits == 8) { m_out.push_back(static_cast<uint8_t>(m_acc)); m_acc = 0; m_bits = 0; }
    }
}

void BitWriter::writeMsb(uint32_t value, int nbits) {
    for (int i = nbits - 1; i >= 0; --i) {
        m_acc |= ((value >> i) & 1u) << m_bits;
        ++m_bits;
        if (m_bits == 8) { m_out.push_back(static_cast<uint8_t>(m_acc)); m_acc = 0; m_bits = 0; }
    }
}

void BitWriter::flush() {
    if (m_bits) { m_out.push_back(static_cast<uint8_t>(m_acc)); m_acc = 0; m_bits = 0; }
}

bool BitReader::read(uint32_t& value, int nbits) {
    value = 0;
    for (int i = 0; i < nbits; ++i) {
        if (m_bits == 0) {
            if (m_pos >= m_size) return false;
            m_acc = m_data[m_pos++];
            m_bits = 8;
        }
        value |= (m_acc & 1u) << i;
        m_acc >>= 1;
        --m_bits;
    }
    return true;
}

bool BitReader::readMsb(uint32_t& value, int nbits) {
    value = 0;
    for (int i = nbits - 1; i >= 0; --i) {
        if (m_bits == 0) {
            if (m_pos >= m_size) return false;
            m_acc = m_data[m_pos++];
            m_bits = 8;
        }
        value |= (m_acc & 1u) << i;
        m_acc >>= 1;
        --m_bits;
    }
    return true;
}

} /* namespace Codec */
} /* namespace DBKP */

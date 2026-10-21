/* ============================================================================
 *  CRC64.h  -- CRC-64/XZ（反射式，多项式 0x42F8E23B884FC003）查表实现
 *
 *  用途：① 每条文件记录的数据校验；② 归档卷标对整段载荷的校验。
 *  自己实现而非调用 zlib，符合"扩展功能不得使用第三方库直接实现"的要求。
 * ==========================================================================*/
#ifndef DBKP_UTILS_CRC64_H
#define DBKP_UTILS_CRC64_H

#include <cstdint>
#include <cstddef>
#include <string>

namespace DBKP {

class CRC64 {
public:
    CRC64() { reset(); }

    static void initTable();
    static uint64_t compute(const void* data, std::size_t len, uint64_t init = 0);

    void reset() { m_crc = 0; }
    void update(const void* data, std::size_t len);
    uint64_t value() const { return m_crc; }

    /** 64 位哈希的短文本表示（打印用） */
    static std::string toString(uint64_t crc);

private:
    uint64_t m_crc;
};

} /* namespace DBKP */

#endif /* DBKP_UTILS_CRC64_H */

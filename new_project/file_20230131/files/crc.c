#include "crc.h"
#include "stdio.h"

#define CRC_START_32    0xFFFFFFFFL
#define CRC_POLY_32     0xEDB88320L

static uint32_t crc_tab32[256];
static int crc_tab32_init = 0;

static void init_crc32_tab(void)
{
    uint32_t i;
    uint32_t j;
    uint32_t crc;
    for (i = 0; i < 256; i++)
    {
        crc = i;
        for (j = 0; j < 8; j++)
        {
            if (crc & 0x00000001L) crc = (crc >> 1) ^ CRC_POLY_32;
            else                     crc =   crc >> 1;
        }
        crc_tab32[i] = crc;
    }
    crc_tab32_init = 1;
}

CHECK_TYPE crc_32(const unsigned char *input_str, size_t num_bytes)
{
    uint32_t crc;
    uint32_t tmp;
    uint32_t long_c;
    const unsigned char *ptr;
    size_t a;

    if (!crc_tab32_init)
    {
        init_crc32_tab();
    }

    crc = CRC_START_32;
    ptr = input_str;

    if (ptr != NULL)
    {
        for (a = 0; a < num_bytes; a++)
        {
            long_c = 0x000000FFL & (uint32_t) * ptr;
            tmp    = crc ^ long_c;
            crc    = (crc >> 8) ^ crc_tab32[tmp & 0xff];
            ptr++;
        }
    }
    crc ^= 0xffffffffL;
    return (CHECK_TYPE)(crc & 0xffffffffL);
}

uint32_t check_sum_func(const unsigned char *input_str, size_t num_bytes)
{
    uint32_t check_rst = 0, i = 0;
    for (i = 0; i < num_bytes; i++)
    {
        check_rst += input_str[i];
    }
    return check_rst;
}

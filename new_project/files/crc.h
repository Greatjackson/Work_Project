#ifndef _CRC_H_
#define _CRC_H_
#include "stddef.h"
#include <stdlib.h>
typedef unsigned int uint32_t;
typedef uint32_t CHECK_TYPE;
extern CHECK_TYPE crc_32(const unsigned char *input_str, size_t num_bytes);
extern uint32_t check_sum_func(const unsigned char *input_str, size_t num_bytes);
#endif